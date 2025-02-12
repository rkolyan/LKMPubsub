#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>
#include <linux/hashtable.h>

MODULE_AUTHOR("Golovnev Nikolay");
MODULE_DESCRIPTION("PubSub");
MODULE_LICENSE("GPL");

struct some_struct {
	int num;
	struct hlist_node hlist;
};

static int __init pubsub_init(void) {
	DEFINE_HASHTABLE(some, 3);
	struct some_struct *ps = vmalloc(sizeof(struct some_struct));
	ps->num = 3;
	hash_add_rcu(some, &(ps->hlist), ps->num);
	synchronize_rcu();
	return 0;
}

static void __exit pubsub_exit(void)
{
}

module_init(pubsub_init);
module_exit(pubsub_exit);
