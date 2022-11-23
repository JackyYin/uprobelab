#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h> // ioctl, chrdev
#include <linux/file.h> // fget, fput
#include <linux/ioctl.h> // ioctl
#include <linux/uaccess.h> // copy_from_user
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h> // kzalloc

#define IOC_MAGIC 'x'
#define IOCTL_ATTACH_UPROBE _IOW(IOC_MAGIC, 0, void *)

struct uprobe_attach_info {
    int fd;
    long long offset;
};

static int major;
static struct class *myclass;
static struct device *mydevice;
static struct cdev mycdev;
static dev_t dev = 0;

static void print_reg(struct pt_regs *regs, int r)
{
    int rc;
    int arg;
    if (regs->regs[r]) {
        if ((rc = copy_from_user(&arg, (const void __user *)regs->regs[r], sizeof(int)))) {
            pr_info("failed to get argument %d...%d\n", r, rc);
        } else {
            pr_info("arg[%d]: %d\n", r, arg);
        }
    }
}

static int uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs)
{
    int rc;
    int i = 0;
    pr_info("enter uprobe_handler...\n");


    for (; i < 31; i++) {
        pr_info("regs[%d] = %p\n", i, regs->regs[i]);
    }
    pr_info("sp: %p\n", regs->sp);

    /* pr_info("wo: %p\n", (regs->regs[0] & 0xFFFFFFFF)); */
    /* pr_info("w1: %p\n", (regs->regs[1] & 0xFFFFFFFF)); */
    /* pr_info("w2: %p\n", (regs->regs[2] & 0xFFFFFFFF)); */
    /* char stack[256]; */
    /* if (regs->sp) { */
    /*     if ((rc = copy_from_user(stack, (const void __user *)regs->sp, 64))) { */
    /*         pr_info("failed to get stack ...%d\n", rc); */
    /*     } else { */
    /*         int *sp = (int *)(stack + 28); */
    /*         pr_info("sp[0]: %d\n", sp[0]); */
    /*     } */
    /* } */

    print_reg(regs, 0);
    print_reg(regs, 1);
    print_reg(regs, 2);
    /* print_reg(regs, 12); */
    return 0;
}

static int uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long func, struct pt_regs *regs)
{
    int rc;
    pr_info("uprobe_ret_handler...\n");
    pr_info("retval: %d\n", regs->regs[0]);
    /* char stack[256]; */
    /* if (regs->sp) { */
    /*     if ((rc = copy_from_user(stack, (const void __user *)regs->sp, 64))) { */
    /*         pr_info("failed to get stack ...%d\n", rc); */
    /*     } else { */
    /*         long *sp = (long *)(stack + 40); */
    /*         pr_info("sp[0]: %ld\n", sp[0]); */
    /*         sp = (long *)(stack + 32); */
    /*         pr_info("sp[1]: %ld\n", sp[1]); */
    /*         sp = (long *)(stack + 24); */
    /*         pr_info("sp[2]: %ld\n", sp[2]); */
    /*     } */
    /* } */

    return 0;
}

static struct uprobe_consumer uc = {
    .handler = uprobe_handler,
    .ret_handler = uprobe_ret_handler
};

long ioctl_handler(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int retval = 0;
    struct file *file = NULL;
    struct inode *f_inode = NULL;

    pr_info("recevied ioctl... %lu\n", cmd);

    switch (cmd) {
    case IOCTL_ATTACH_UPROBE:
        struct uprobe_attach_info *attach_info;

        pr_info("handle IOCTL_ATTACH_UPROBE...\n");
        attach_info = kzalloc(sizeof(struct uprobe_attach_info), GFP_KERNEL);
        if (!attach_info) {
            pr_info("failed to alloc...\n");
            retval = -ENOMEM;
            goto out;
        }

        if ((copy_from_user(attach_info, (const void __user *)arg, sizeof(struct uprobe_attach_info)))) {
            pr_info("failed to copy_from_user...\n");
            retval = -EIO;
            goto out;
        }

        if (!attach_info->fd || !attach_info->offset) {
            pr_info("no fd or offset provided...\n");
            retval = -EIO;
            goto out;
        }

        file = fget_raw(attach_info->fd);
        if (!file) {
            retval = -EBADF;
        }

        f_inode = igrab(file->f_inode);
        retval = uprobe_register(f_inode, attach_info->offset, &uc);
        pr_info("uprobe_registed...\n");
        fput(file);
        break;
    default:
        retval = -ENOENT;
    }

out:
    return retval;
}

int open_handler(struct inode *inode, struct file *filp)
{
    pr_info("device file opened...\n");
    return 0;
}


struct file_operations fops = {
    .open = open_handler,
    .unlocked_ioctl = ioctl_handler
};

static int __init uprobe_init(void)
{
    pr_info("uprobe module init...\n");

    /* major = register_chrdev(0, "myuprobe", &fops); */
    /* if (major < 0) { */
    /*     pr_alert("Failed to register char device: %d\n", major); */
    /*     return major; */
    /* } */

    if (alloc_chrdev_region(&dev, 0, 1, "myuprobe") < 0) {
        pr_alert("Failed to register char device...\n");
        return -1;
    }

    cdev_init(&mycdev, &fops);

    cdev_add(&mycdev, dev, 1);

    myclass = class_create(THIS_MODULE, "myuprobeclass");
    if (!myclass) {
        pr_alert("Failed to create class...\n");
        return -1;
    }

    mydevice = device_create(myclass, NULL, dev, NULL, "myuprobe");
    if (!mydevice) {
        pr_alert("Failed to create device...\n");
        return -1;
    }

    return 0;
}

static void __exit uprobe_exit(void)
{
    /* unregister_chrdev(0, "myuprobe"); */
    device_destroy(myclass, dev);
    class_destroy(myclass);
    cdev_del(&mycdev);
    unregister_chrdev_region(dev, 1);
    pr_info("uprobe module exit!!!\n");
}

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("simple lab for uprobe");
MODULE_AUTHOR("Jacky Yin");

module_init(uprobe_init);
module_exit(uprobe_exit);

