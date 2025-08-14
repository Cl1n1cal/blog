---
layout: post
title:  "Safe Linking (tcache, fastbins)"
date:   2025-08-13 06:50:19 +0200
hidden: true
---
### Description
To make it harder for an attacker to overwrite the next ptr in a free tcache or fastbin chunk, newer libc versions feature a security measure called "Safe Linking" (version 2.32 and onwards). This means that the next ptr in the free chunk is not stored in plaintext, but rather it is mangled.

### Some information about the tcache
Consider the following scenario: Imagine we have 2 chunks allocated with malloc(0x40): Chunk0 and chunk1. First chunk1 is freed and then chunk0. Now in the tcache 0x50 bin you will have the following layout: chunk0 -> chunk1. <br>
This means that chunk0 is the 'head' of the 0x50 tcache bin (0x50 because 0x40+0x10 for metadata such as size field). The head is the first chunk to be allocated if a malloc(0x40) occurs, since the tcache uses last-in-first-out (like a stack).<br>
But in order to keep track of the next elements in the same bin, the tcache uses a ptr to the user data of the next chunk. If this ptr is overwritten by an attacker, they can control where the next allocation will be, giving them a lot of control.<br>
To try and mitigate this, safe linking has been employed, so that an attacker cannot 'just' overwrite the next ptr with a plain text value. They need a heap leak first, since safe linking uses the heap addresses to mangle the next ptr before storing it.

### Safe Linking
To put it plainly, safe linking works by doing the following:
```
chunk0->fd = (chunk0 >> 12) ^ chunk1
```
Take the address of chunk0 and right shift 12 bits, then xor with chunk1 and store result at the address of chunk0.<br>

To get back the original ptr, do the following:
```
read_fd = (chunk0 >> 12) ^ chunk1
```
<br>
Below is a picture that illustrates safe linking:
<img src="/assets/images/others/safe_linking.png" style="width:100%; height:100%;" />

chunk0 is at addr: 0x5555555592a0<br>
chunk1 is at addr: 0x5555555592f0<br>

So to do safe linking here:<br>
chunk0->fd = (0x5555555592a0 >> 12) ^ 0x5555555592f0 <br>

chunk0->fd is the first value you see at address 0x5555555592a0: 0x000055500000c7a9