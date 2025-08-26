---
layout: post
title:  "Windows Heap POC binary"
date:   2025-08-26 06:50:19 +0200
author: cl1nical
hidden: true
---
### Description
The following binary will be used as a proof of concept to demonstrate various scenarios in the Windows heap. I will be using a modern Windows 11 version. <br>
The following zip archive contains 3 files: Source code, executable and .pdb.<br> 
You can download the zip archive by clicking [here](/binaries/Windows_Heap_POC.zip). <br>
The archive can be unzipped by running the following command:
```
unzip Windows_Heap_POC.zip
```

### Walkthrough
<img src="/assets/images/windows/heap_poc/windows_heap_poc1.png" style="width:100%; height:100%;" />  
<br>
As you can see from the picture above, this is a simple console application that allows you to do different things on the heap. The program is written in such a way, that every time it is finished giving output such as printing the menu or some data, it will output a "> " which should make your exploit development easier.<br>
Also, the program has these bugs that will be relevant for you:
- You can do more than 16 allocations, since the program does not check if an allocation has already been made given a certain index e.g. index 4 can be used multiple times
- The program has a UAF bug allowing both writing to a free chunk using the "Edit" option but also printing from a free chunk using the "Print" option.
- The "Print" option is using puts which means that it will terminate on a null byte or a newline character. This has some implications in terms of how a leak can be achieved. <br>

Play around with the program and look at the source code to understand the program.

