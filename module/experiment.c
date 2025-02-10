#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>

MODULE_AUTHOR("Golovnev Nikolay");
MODULE_DESCRIPTION("PubSub");
MODULE_LICENSE("GPL");

static int __init pubsub_init(void) {
	struct mm_struct *mm = NULL;
	unsigned long number1 = 100, number2 = 200;
	unsigned long __user *user_buf = NULL;

	mm = mm_alloc();
	if (!mm) {
		trace_printk("mm not allocated!\n");
		return 0;
	}

	user_buf = (unsigned long __user *)vmalloc_user(PAGE_SIZE);

	use_mm(mm);

	unsigned long read1 = copy_to_user(user_buf, &number1, sizeof(unsigned long));
	unsigned long read2 = copy_from_user(&number2, user_buf, sizeof(unsigned long));

	unuse_mm(mm);
	trace_printk("hello: *user_buf == %lu, number1 = %lu, number2 = %lu, read1 = %lu, read2 = %lu\n", *user_buf, number1, number2, read1, read2);

	vfree(user_buf);
	mmput(mm);
	return 0;
}

static void __exit pubsub_exit(void)
{
}

module_init(pubsub_init);
module_exit(pubsub_exit);
