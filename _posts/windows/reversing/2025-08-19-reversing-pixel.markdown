---
layout: post
title:  "Crackme.ones - Pixel writeup"
date:   2025-08-19 06:50:19 +0200
author: cl1nical
hidden: true
---
### Description
For some time I have wanted to get better at reverse engineering. After recently solving some shellcoding and buffer overflow binaries on Windows I thought the time was finally right to get started. <br>
The binary in this blog post was fetched from [crackmes.one]("https://crackmes.one"). The challenge is called **pixel** (challenge file called: **lazy.exe**) and was written by **Boozy**. The difficulty rating is 2.0 and the quality rating is 4.0.

### Tools
To solve this crackme I used the following tools:
- IDA Free (static analysis)
- x64dbg (dynamic analysis)

### Writeup
First off, open the program in Ida. Then go to the **main** function. In there you will see the following:<br>
<img src="/assets/images/windows/reversing/pixel/ida1.png" style="width:100%; height:100%;" />
<br>
The above image describes how the program is using [FindFirstFileA]("https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilea") to find an image file with the exteion '.jpeg'.
But there are also 3 '?' before the '.jpeg' file extension. These question mark characters are wildcards, according to the Windows docs. To sum up, the program is looking for a '.jpeg' file in the current folder, which has a name of the characters
before the file extension.<br>

After seeing this, we create a file called: "AAA.jpeg" (which was actually a cat image I downloaded but I don't know if that makes a difference :-) ).<br>
Also, I discovered that the program would try and use [fopen]("https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/fopen-wfopen") to open a file. This prompted me to inspect the binary with the dynamic debugger to get a better understanding before proceeding with the static analysis.<br>
The picture below is a screenshot from Ida that displays how the program is using fopen:<br>
<img src="/assets/images/windows/reversing/pixel/ida2.png" style="width:100%; height:100%;" />
<br>

After setting a breakpoint on **fopen** it was possible to inspect the registers before and after the function call.<br>
Before:<br>
<img src="/assets/images/windows/reversing/pixel/x64dbg1.png" style="width:100%; height:100%;" />

After:<br>
<img src="/assets/images/windows/reversing/pixel/x64dbg2.png" style="width:100%; height:100%;" />
<br>
In the 2nd picture above, you can see that the **fopen** call returns null, indicating an error. After stepping a little further, I discovered that the program did not terminate after this.<br>
In the x64dbg view I noticed that there was some comparison loop going on, by noticing that the registers kept changing between different char values. Also, the assembly showed that there was comparison operations going on.<br>
The picture below shows the loop in x64dbg:<br>
<img src="/assets/images/windows/reversing/pixel/x64dbg3.png" style="width:100%; height:100%;" />
<br>
The picture below shows the loop in Ida:<br>
<img src="/assets/images/windows/reversing/pixel/ida3.png" style="width:100%; height:100%;" />
<br>
And looking a little further down in the Ida graph viewer, I noticed that there was a comparison with '~' - hmmm, this seemed interesting.<br>
<img src="/assets/images/windows/reversing/pixel/ida4.png" style="width:100%; height:100%;" />
<br>
Moving back to the pseudocode in Ida, it was possible to see the final check where the binary would either print "umm....try again" or the winning message: "dayummm". I went back into x64dbg and stepped further in the code. I also put a breakpoint
on the final comparison to see what was going on: <br>
<img src="/assets/images/windows/reversing/pixel/x64dbg4.png" style="width:100%; height:100%;" />
<br>
The binary was checking if our image was named '~~~.jpeg'!<br>
After realizing this I renamed the picture and ran the program again in x64dbg just to confirm - it was correct!<br>
Below you can see the terminal output of the program after renaming the picture to '~~~.jpeg'.<br>
<img src="/assets/images/windows/reversing/pixel/result.png" style="width:100%; height:100%;" />




