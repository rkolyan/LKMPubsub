#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/module.h>

static void notrace ftrace_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
    printk(KERN_INFO "Function called: %ps\n", (void *)ip);
}

static struct ftrace_ops ops = {
    .func = ftrace_callback,
    .flags = FTRACE_OPS_FL_SAVE_REGS,
};

static int __init ftrace_init(void)
{
    int ret;
    ret = register_ftrace_function(&ops);
    if (ret) {
        pr_err("Failed to register ftrace callback\n");
        return ret;
    }
    return 0;
}

static void __exit ftrace_exit(void)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ваше имя");
