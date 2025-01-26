#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "syscalls.h"
#include "node.h"

MODULE_AUTHOR("Golovnev Nikolay");
MODULE_DESCRIPTION("PubSub");
MODULE_LICENSE("GPL");

static int __init pubsub_init(void) {
    /*
    struct device *dev = NULL;
    my_major = MAJOR(0);
    result = register_chrdev(my_major, DEVICE_NAME, &fops);
    if (result < 0) {
        pr_err("ssssssShit!");
        return result;
    }
    cls = class_create(DEVICE_NAME);
    if (IS_ERR(cls)) {
        pr_err("class fuckup!");
        return -EINVAL;
    }
    dev = device_create(cls, NULL, MKDEV(my_major, my_minor), NULL, DEVICE_NAME);
    if (!dev) {
        pr_err("DDDDDDdevice fucjk up!");
        return -EINVAL;
    }
    */
    //1)Инициализация node
    int err = init_nodes();
    //2)Перехват функций
    err = hook_functions();
    return err;
}

static void __exit pubsub_exit(void)
{
    //1)Удаление функций из таблицы системных вызовов
    int err = unhook_functions();
    err = unhook_functions();
    //2)Очистка нодов и всего такого
    err = deinit_nodes();
}

module_init(pubsub_init);
module_exit(pubsub_exit);
