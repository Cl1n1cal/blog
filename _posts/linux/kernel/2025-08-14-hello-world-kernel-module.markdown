---
layout: post
title:  "Hello World Kernel Module"
date:   2025-08-14 06:50:19 +0200
author: cl1nical
hidden: true
---
### Description
This is a very simple kernel module that uses printk to write "Hello world!".

### Resources
See this [link]("https://www.youtube.com/watch?v=RuocwHw0MzE") by Johannes 4GNU_Linux

### Module
```C
#include <linux/module.h>
#include <linux/init.h>

int hello_start(void)
{
    printk(KERN_INFO "Hello world!\n");
    return 0;
}

void hello_end(void)
{
    printk(KERN_INFO "Hello module unloaded\n");
}

module_init(hello_start);
module_exit(hello_end);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cl1nical");
MODULE_DESCRIPTION("Hello World Kernel Module");
MODULE_VERSION("0.1");
```

### Makefile
```make
obj-m += main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

### Result
Compile using the following command in the dir:
```
make
```
Insert the module into the kernel **Disclaimer: Use a VM**
```
sudo insmod main.ko
```
Use the following command to display the output:
```
sudo dmesg
```
<img src="/assets/images/kernel/hello_world_insmod.png" style="width:100%; height:100%;" />