#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init hello_init(void)
{
    printk(KERN_INFO "Module start\n");
    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_INFO "Module finish\n");
}

module_init(hello_init);   // entery point
module_exit(hello_exit);   // exit point

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("Ivan Briukhov");
MODULE_DESCRIPTION("test kernel module");