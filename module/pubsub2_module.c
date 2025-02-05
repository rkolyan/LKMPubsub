//
// Created by rkolyan on 02.02.2025.
//

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "node.h"

MODULE_AUTHOR("Golovnev Nikolay");
MODULE_DESCRIPTION("PubSub File version");
MODULE_LICENSE("GPL");


static int __init pubsub_init(void) {
    //1)Инициализация node
    int err = init_nodes();
    printk("AAAerr = %d", err);
    return err;
}

static void __exit pubsub_exit(void)
{
    //2)Очистка нодов и всего такого
    deinit_nodes();
}

module_init(pubsub_init);
module_exit(pubsub_exit);
