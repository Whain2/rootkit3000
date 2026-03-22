#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>

#include "ftrace.h"

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

static int __init kernmod_init(void)
{
    int err;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        pr_err("kernmod: fh_install_hooks failed: %d\n", err);
        return err;
    }

    pr_info("kernmod: module loaded\n");
    return 0;
}

static void __exit kernmod_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

    pr_info("kernmod: module unloaded\n");
}

module_init(kernmod_init);
module_exit(kernmod_exit);