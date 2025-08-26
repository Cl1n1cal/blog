---
layout: post
title:  "Libc leak with tcache enabled"
date:   2025-08-14 06:50:19 +0200
author: cl1nical
hidden: true
---
### Description
When we have a UAF to read from a freed chunk how can we use this to get a libc leak?<br>
The tcache only stores its next ptrs and a key value, so we cannot leak libc through there. But if we could allocate and free more than what tcache can hold (7 chunks per bin) and then free another chunk that does not fit into fastbins, we might get it into unsortedbin. Unsortedbin contains libc ptrs to main arena.

### How to leak libc through unsortedbin
We are going to allocate and free 7 chunks to fill the tcache, 1 chunk to go into unsortedbin and a guard chunk to prevent top chunk consolidation. The chunks for tcache and unsortedbin are malloc(0x90) to prevent them from going into fastbin (larger than 64 bytes) and the guard chunk is only malloc(0x20) because its size does not matter. The POC program allows you to do arbitrary allocations of almost arbitrary size.<br>


<img src="/assets/images/others/unsortedbin.png" style="width:100%; height:100%;" />
At address 0x555555559700 and 0x555555559708 you see that they contain the libc addresses of the unsortedbin. They are the fd and bk ptrs to the main arena.<br>

At address 0x5555555597a0 you see the guard chunk user data. This guard chunk prevents top chunk consolidation and forces the previous chunk into the unsortedbin - just what we want.<br>

Next up, the address from the unsortedbin chunk is leaked using the UAF bug in the POC binary. This Leak is at a fixed offset from libc base and this enables us to calculate libc base - finalizing our libc leak. The libc calculation is shown below:<br>
<img src="/assets/images/others/libc_calc.png" style="width:100%; height:100%;" />

The picture below shows you the end result in the termina:<br>
<img src="/assets/images/others/libcleak.png" style="width:100%; height:100%;" />