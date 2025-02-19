#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>

MODULE_AUTHOR("Golovnev Nikolay");
MODULE_DESCRIPTION("PubSubExpeirmietn");
MODULE_LICENSE("GPL");

static int __init pubsub_init(void) {
	char output[20] = {'0', '9', '1', '2', '3', '4', '5', '6', '7', '8', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
	trace_printk("output = %p, &output[3] = %p, output + 3 = %p, (char *)output + 3 = %p\n", output, &output[3], output + 3, (char *)output + 3);
	return 0;
}

static void __exit pubsub_exit(void)
{
}

module_init(pubsub_init);
module_exit(pubsub_exit);
