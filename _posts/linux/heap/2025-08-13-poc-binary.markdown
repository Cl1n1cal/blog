---
layout: post
title:  "POC Binary"
date:   2025-08-13 06:50:19 +0200
hidden: true
---
### Description
The following binary will be used as a proof of concept to demonstrate various scenarios in the linux heap. I will be using libc version 2.39 on a Ubuntu 24 LTS machine.<br>
The following zip archive contains 4 files: Source code, elf binary, libc and linker.<br> 
You can download the zip archive by clicking [here](/binaries/poc-binary.tar.gz). <br>
The archive can be unzipped by running the following command:
```
tar -xvzf poc-binary.tar.gz
```

### Walkthrough
Using the file command you should see the following output:
```
file program
```
```
program: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5ebf57c66be7230d65662438a74d55d2d49494fb, for GNU/Linux 3.2.0, not stripped
```

You'll notice that is a dynamically linked binary, meaning that it loads the necessary libraries at runtime. So unless you are also using Ubuntu 24 LTS with libc version 2.39 it would be a very good idea to make sure that the binary uses the provided libraries. Pwninit is a binary that can patch a binary to use the specified libc and linker. The pwninit binary can be downloaded from Github [here](https://github.com/io12/pwninit/releases). <br>
The following command can then be used to make the binary run with the proper libc and linker. You will have to use the output binary called **program_patched**:
```
/path/to/pwninit --libc libc.so.6 --ld ld-linux-x86-64.so.2 --bin program
```
Now the program is ready to run:<br>
<img src="/assets/images/poc-walkthrough/poc0.png" style="width:70%; height:70%;" />  

As you can see from the picture above, this is a simple console application that allows you to do different things on the heap. The program is written in such a way, that every time it is finished giving output such as printing the menu or some data, it will output a "> " which should make your exploit development easier.<br>
Also, the program has these bugs that will be relevant for you:
- You can do more than 16 allocations, since the program does not check if an allocation has already been made given a certain index e.g. index 4 can be used multiple times
- The program has a UAF bug allowing both writing to a free chunk using the "Edit" option but also printing from a free chunk using the "Print" option.
- The "Print" option is using puts which means that it will terminate on a null byte or a newline character. This has some implications in terms of how a leak can be achieved. <br>

Play around with the program and look at the source code to understand the program.
