---
layout: post
title:  "Buffer Overflow Kernel Module"
date:   2025-09-18 06:50:19 +0200
author: cl1nical
hidden: true
---
### Description
This post shows the code of a vulnerable kernel module that allows the attacker to read as many bytes as they want and write as many bytes as they want to the kernel module.<br>
[Click here](https://github.com/Cl1n1cal/Kernel-Module-Archives/tree/main) for a link to the Github repo. <br>

```c
#include "main.h"

#define SUCCESS 0
#define DEVICE_NAME "hackme"
#define BUF_LEN 100

static int Major;

/**
 * Ensure atomicity and prevent race conditions
 */
enum { 
    CDEV_NOT_USED, 
    CDEV_EXCLUSIVE_OPEN, 
}; 

/* Is device open? Used to prevent multiple access to device */ 
static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED);

static struct class *cls; 

static struct file_operations fops = {
    .read = hackme_read,
    .write = hackme_write,
    .open = hackme_open,
    .release = hackme_release
};

/**
 * Called when the module is loaded
 */
static int hackme_init(void)
{
    Major = register_chrdev(0, DEVICE_NAME, &fops);

    if (Major < 0) {
        pr_alert("Registrering char device failed\n");
        return Major;
    }

    pr_info("Device assigned major number: %d\n", Major);

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0) 
        cls = class_create(DEVICE_NAME); 
    #else 
        cls = class_create(THIS_MODULE, DEVICE_NAME); 
    #endif 
        device_create(cls, NULL, MKDEV(Major, 0), NULL, DEVICE_NAME); 
 
    pr_info("Device created on /dev/%s\n", DEVICE_NAME); 
 

    return SUCCESS;
}

/**
 * Called when the module is unloaded
 */
static void hackme_exit(void)
{
    device_destroy(cls, MKDEV(Major, 0));
    class_destroy(cls);

    /**
     * Unregister the device
     */
    unregister_chrdev(Major, DEVICE_NAME);
    pr_info("Unregistered kernel module\n");
}

/* Methods */

/**
 * Called when a process tries to open the device file
 */
static int hackme_open(struct inode *inode, struct file *file)
{
    if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN)) {
        return -EBUSY;
    }

    pr_info("Device opened\n");

    return 0;
}

/**
 * Called when a process releases the device
 */
static int hackme_release(struct inode *inode, struct file *file)
{
    atomic_set(&already_open, CDEV_NOT_USED); 
    return 0;
}

/**
 * Called when a process reads from the device
 */
static ssize_t hackme_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    size_t bytes_read = 0;
    char vuln_buf[BUF_LEN];

    bytes_read = raw_copy_to_user(buffer, vuln_buf, length);

    return bytes_read;
}

/**
 * Called when a process writes to the device
 */
static ssize_t hackme_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset)
{
    size_t bytes_written = 0;
    char vuln_buf[BUF_LEN];

    bytes_written = raw_copy_from_user(vuln_buf, buffer, length);

    return bytes_written;
}

module_init(hackme_init);
module_exit(hackme_exit);

MODULE_LICENSE("GPL");
```