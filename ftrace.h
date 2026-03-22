#ifndef FTRACE_H
#define FTRACE_H

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
// new kernels
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>

static unsigned long lookup_name(const char *name) // get func addr by name
{
    struct kprobe kp = {
        .symbol_name = name
    };
    unsigned long retval;

    if (register_kprobe(&kp) < 0)
        return 0;

    retval = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return retval;
}
#else
// old kernels
static unsigned long lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}
#endif

struct ftrace_hook {
    const char *name; // name of the intercepted function
    void *function; // replacement funс
    void *original; // original func

    unsigned long address; // addr replacement funс
    struct ftrace_ops ops;
};

#define HOOK(_name, _hook, _orig)   \
{                                   \
    .name = (_name),                \
    .function = (_hook),            \
    .original = (_orig),            \
}

static int resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = lookup_name(hook->name);

    if (!hook->address) {
        pr_err("kernmod: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long *)hook->original) = hook->address;
    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip,
    unsigned long parent_ip,
    struct ftrace_ops *ops,
    struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    // recursion protect
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}

static int fh_install_hook(struct ftrace_hook *hook)
{
    int err;
    // find addr
    err = resolve_hook_address(hook);
    if (err)
        return err;

    // ops setup
    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION
                    | FTRACE_OPS_FL_IPMODIFY;

    // filter
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_err("kernmod: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }
    // activation
    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_err("kernmod: register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0); // filter clear
        return err;
    }

    return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err)
        pr_err("kernmod: unregister_ftrace_function() failed: %d\n", err);

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
        pr_err("kernmod: ftrace_set_filter_ip(remove) failed: %d\n", err);
}

static int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err)
            goto error;
    }
    return 0;

error:
    while (i != 0) {
        fh_remove_hook(&hooks[--i]);
    }
    return err;
}

static void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);
}

#endif