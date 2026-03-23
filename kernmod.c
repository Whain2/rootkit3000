#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>

#include "ftrace.h"
#include "common.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivan Briukhov");
MODULE_DESCRIPTION("test kernel module");

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    long ret;

    ret = orig_getdents64(regs);

    pr_info("kernmod: getdents64 called by pid %d, returned %ld bytes\n",
            current->pid, ret);

    return ret;
}

static asmlinkage long hook_getdents(const struct pt_regs *regs)
{
    long ret;

    ret = orig_getdents(regs);

    pr_info("kernmod: getdents called by pid %d, returned %ld bytes\n",
            current->pid, ret);

    return ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents",   hook_getdents,   &orig_getdents),
};

static long kernmod_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    char buf[MAX_HIDDEN_NAME] = {0};

    switch (cmd) {
    case IOCTL_HIDE_FILE:
        if (copy_from_user(buf, (char __user *)arg, MAX_HIDDEN_NAME))
            return -EFAULT;
        buf[MAX_HIDDEN_NAME - 1] = '\0';
        pr_info("kernmod: HIDE_FILE requested with file name: %s\n", buf);
        return 0;

    case IOCTL_UNHIDE_FILE:
        if (copy_from_user(buf, (char __user *)arg, MAX_HIDDEN_NAME))
            return -EFAULT;
        buf[MAX_HIDDEN_NAME - 1] = '\0';
        pr_info("kernmod: UNHIDE_FILE requested with file name: %s\n", buf);
        return 0;

    default:
        return -EINVAL;
    }
}

static const struct file_operations kernmod_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = kernmod_ioctl,
};

static struct miscdevice kernmod_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "kernmod",
    .fops = &kernmod_fops,
    .mode = 0660,
};

static int __init kernmod_init(void)
{
    int err;

    err = misc_register(&kernmod_dev);
    if (err) {
        pr_err("kernmod: misc_register failed: %d\n", err);
        return err;
    }

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        pr_err("kernmod: fh_install_hooks failed: %d\n", err);
        misc_deregister(&kernmod_dev);
        return err;
    }

    pr_info("kernmod: module loaded\n");
    return 0;
}

static void __exit kernmod_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    misc_deregister(&kernmod_dev);

    pr_info("kernmod: module unloaded\n");
}

module_init(kernmod_init);
module_exit(kernmod_exit);