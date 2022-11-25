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
#include <linux/list.h> // linked list API
#include <linux/spinlock.h>

#define IOC_MAGIC 'x'
#define IOCTL_ATTACH_UPROBE _IOW(IOC_MAGIC, 0, void *)

struct uprobe_attach_info {
    int fd;
    long long offset;
};

struct uprobe_list_node {
    struct uprobe_attach_info attach_info;
    struct list_head list;
};

static struct class *myclass;
static struct device *mydevice;
static struct cdev mycdev;
static dev_t dev = 0;

static LIST_HEAD(uprobe_list);
DEFINE_SPINLOCK(uprobe_list_spinlock);

static int uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs)
{
    pr_info("enter uprobe_handler...\n");

#if defined(CONFIG_ARM64)
    int i = 0;
    for (; i < 31; i++) {
        pr_info("regs[%d] = %lu\n", i, regs->regs[i]);
    }
    pr_info("sp: %p\n", regs->sp);
#elif defined(CONFIG_X86_64)
    pr_info("regs[rdi] = %lu\n", regs->di);
    pr_info("regs[rsi] = %lu\n", regs->si);
    pr_info("regs[rdx] = %lu\n", regs->dx);
    pr_info("regs[rcx] = %lu\n", regs->cx);
    pr_info("regs[rax] = %lu\n", regs->ax);
#endif
    return 0;
}

static int uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long func, struct pt_regs *regs)
{
    pr_info("enter uprobe_ret_handler...\n");

#if defined(CONFIG_ARM64)
    int i = 0;
    for (; i < 31; i++) {
        pr_info("regs[%d] = %lu\n", i, regs->regs[i]);
    }
    pr_info("sp: %lu\n", regs->sp);
#elif defined(CONFIG_X86_64)
    pr_info("register set came from user mode : %d\n", user_mode(regs) ? 1 : 0);
    pr_info("regs[rdi] = %lu\n", regs->di);
    pr_info("regs[rsi] = %lu\n", regs->si);
    pr_info("regs[rdx] = %lu\n", regs->dx);
    pr_info("regs[rcx] = %lu\n", regs->cx);
    pr_info("regs[rax] = %lu\n", regs->ax);
#endif

#if defined(CONFIG_ARM64)
    pr_info("retval: %lu\n", regs->regs[0]);
#elif defined(CONFIG_X86_64)
    pr_info("retval: %lu\n", regs->ax);
#endif
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

    pr_info("recevied ioctl... %u\n", cmd);

    switch (cmd) {
    case IOCTL_ATTACH_UPROBE:
        struct uprobe_list_node *list_node;

        pr_info("handle IOCTL_ATTACH_UPROBE...\n");
        list_node = kzalloc(sizeof(struct uprobe_list_node), GFP_KERNEL);
        if (!list_node) {
            pr_info("failed to alloc...\n");
            retval = -ENOMEM;
            goto out;
        }
        INIT_LIST_HEAD(&list_node->list);

        if ((copy_from_user(&list_node->attach_info, (const void __user *)arg, sizeof(struct uprobe_attach_info)))) {
            pr_info("failed to copy_from_user...\n");
            retval = -EIO;
            kfree(list_node);
            goto out;
        }

        if (!list_node->attach_info.fd || !list_node->attach_info.offset) {
            pr_info("no fd or offset provided...\n");
            retval = -EIO;
            kfree(list_node);
            goto out;
        }

        file = fget_raw(list_node->attach_info.fd);
        if (!file) {
            retval = -EBADF;
            kfree(list_node);
            goto out;
        }
        f_inode = igrab(file->f_inode);

        retval = uprobe_register(f_inode, list_node->attach_info.offset, &uc);
        if (retval) {
            pr_info("uprobe_register failed with: %d\n", retval);
            fput(file);
            kfree(list_node);
            goto out;
        }

        spin_lock(&uprobe_list_spinlock);
        list_add_tail(&list_node->list, &uprobe_list);
        spin_unlock(&uprobe_list_spinlock);

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

    INIT_LIST_HEAD(&uprobe_list);
    return 0;
}

static void __exit uprobe_exit(void)
{
    struct uprobe_list_node *cur = NULL, *tmp;

    spin_lock(&uprobe_list_spinlock);
    list_for_each_entry_safe(cur, tmp, &uprobe_list, list) {
        kfree(cur);
    }
    spin_unlock(&uprobe_list_spinlock);


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

