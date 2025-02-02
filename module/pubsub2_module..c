//
// Created by rkolyan on 02.02.2025.
//

MODULE_AUTHOR("Golovnev Nikolay");
MODULE_DESCRIPTION("PubSub File version");
MODULE_LICENSE("GPL");

static int __init pubsub_init(void) {
    //1)Инициализация node
    int err = init_nodes();
    return err;
}

static void __exit pubsub_exit(void)
{
    //2)Очистка нодов и всего такого
    err = deinit_nodes();
}

module_init(pubsub_init);
module_exit(pubsub_exit);
