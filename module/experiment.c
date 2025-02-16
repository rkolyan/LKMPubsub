#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>

MODULE_AUTHOR("Golovnev Nikolay");
MODULE_DESCRIPTION("PubSubExpeirmietn");
MODULE_LICENSE("GPL");

static int __init pubsub_init(void) {
	char output[20] = {'0', '9', '1', '2', '3', '4', '5', '6', '7', '8', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
	char input[20] = {'\0'};
	void *addr = memcpy(input, output, 20);
	trace_printk("output = \"%20s\"\tinput = \"%20s\"\t addr = %p, input = %p\n", output, input, addr, input);
	return 0;
}

static void __exit pubsub_exit(void)
{
}

module_init(pubsub_init);
module_exit(pubsub_exit);
