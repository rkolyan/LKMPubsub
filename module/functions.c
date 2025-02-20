//
// Created by rkolyan on 02.02.2025.
//

#include "node.h"
#include "functions.h"

#ifndef PS_TEST
long ps_node_create(size_t buf_size, size_t block_size, unsigned long __user *result) {
#else
long ps_node_create(size_t buf_size, size_t block_size, unsigned long *result) {
#endif
	struct ps_node *node = NULL;
	trace_printk("BEGIN buf_size = %lu, block_size = %lu, result = %p\n", buf_size, block_size, result);
	int err = create_node_struct(buf_size, block_size, &node);
	trace_printk("after create_node_struct node = %p, node_id = %lu,  err = %d\n", node, node->id, err);
	if (err) {
		trace_puts("Нельзя добавить node!\n");
		return err;
	}
	add_node(node);
	err = get_node_id(node, result);
       	if (err) {
		trace_printk("get_node return EAGAIN(\n");
		remove_node(node);
		mark_node_unused(node);
		delete_node_struct_if_unused(node);
		return err;
	}
	trace_puts("END\n");
	return 0;
}

long ps_node_delete(unsigned long node_id) {
	struct ps_node *node = NULL;
	long err = 0;
	err = acquire_node(node_id, &node);
	trace_printk("after acquire_node err = %ld, node = %p\n", err, node);
	if (err) {
		return err;
	}
	remove_node(node);
	trace_puts("after remove_node\n");
	release_node(node);
	mark_node_unused(node);
	delete_node_struct_if_unused(node);
	return err;
}

long ps_node_subscribe(unsigned long node_id) {
	unsigned long sub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_subscriber *sub = NULL;

	trace_printk("BEGIN node_id = %lu\n", node_id);
	err = create_subscriber_struct(sub_id, &sub);
	trace_printk("after create_subscriber_struct sub  = %p, err = %d\n", sub, err);
	if (err)
		return err;

	err = acquire_node(node_id, &node);
	trace_printk("after acquire_node node = %p, node_id = %ld\n", node, node_id);

	if (err) {
		trace_puts("node not found\n");
		return err;
	}

	err = find_subscriber_in_node(node, sub_id, &sub);
	trace_printk("after find_subscriber_in_node sub  = %p, pos = %p, err = %d\n", sub, sub ? sub->pos : NULL, err);
	if (err == -ENOENT) {
		err = add_subscriber_in_node(node, sub);
		trace_printk("after adding to collections err = %d, sub = %p, sub->pos = %p\n", err, sub, sub->pos);
	}
       	if (err) {
		delete_subscriber_struct(sub);
		trace_puts("after delete structures\n");
	}

	release_node(node);
	delete_node_struct_if_unused(node);
	trace_puts("END\n");
	return err;
}

long ps_node_unsubscribe(unsigned long node_id) {
	unsigned long sub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_subscriber *sub = NULL;
	trace_puts("BEGIN\n");

	err = acquire_node(node_id, &node);

	trace_printk("after acquire_node node  = %p, err = %d\n", node, err);
	if (err) {
		return err;
	}

	err = find_subscriber_in_node(node, sub_id, &sub);
	trace_printk("after find_subscriber_in_node sub  = %p, pos = %p, err = %d\n", sub, sub ? sub->pos : NULL, err);
	if (!err) {
		remove_subscriber_in_node(node, sub);
		trace_puts("after remove collections\n");
		delete_subscriber_struct(sub);
		trace_puts("after delete structures\n");
	}
	release_node(node);
	delete_node_struct_if_unused(node);
	trace_puts("END\n");
	return err;
}

long ps_node_publish(unsigned long node_id) {
	unsigned long pub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_publisher *pub = NULL, *tmp_pub = NULL;
	trace_puts("BEGIN\n");
	err = create_publisher_struct(pub_id, &pub);
	trace_printk("after create_publisher_struct pub = %p, err = %d\n", pub, err);
	if (err || !pub) {
		return err;
	}

	err = acquire_node(node_id, &node);
	trace_printk("after find_node node = %p, err = %d\n", node, err);

	if (err) {
		delete_publisher_struct(pub);
		return err;
	}

	err = find_publisher_in_node(node, pub_id, &tmp_pub);
	trace_printk("after find_publisher_in_node pub = %p, err = %d\n", tmp_pub, err);
	if (err == -ENOENT) {
		err = add_publisher_in_node(node, pub);
		trace_printk("after add_publisher_in_node node = %p, pub = %p, err = %d\n", node, pub, err);
	} else {
		err = -EEXIST;
		delete_publisher_struct(pub);
		trace_puts("after delete_publisher_struct\n");
	}

	release_node(node);
	delete_node_struct_if_unused(node);
	trace_puts("END\n");
	return err;
}

long ps_node_unpublish(unsigned long node_id) {
	unsigned long pub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_publisher *pub = NULL;
	trace_puts("BEGIN\n");

	err = acquire_node(node_id, &node);
	trace_printk("after acquire_node node = %p, err = %d\n", node, err);

	if (err) {
		return err;
	}

	err = find_publisher_in_node(node, pub_id, &pub);
	trace_printk("after find_publisher_in_node pub = %p, err = %d\n", pub, err);
	if (!err) {
		remove_publisher_in_node(node, pub);
		delete_publisher_struct(pub);
		trace_puts("after remove and delete_publisher_struct\n");
	}

	release_node(node);
	delete_node_struct_if_unused(node);
	trace_puts("END\n");
	return err;
}

#ifndef PS_TEST
long ps_node_send(unsigned long node_id, void __user *info) {
#else
long ps_node_send(unsigned long node_id, void *info) {
#endif
	unsigned long pub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_publisher *pub = NULL;

	trace_puts("BEGIN\n");

	err = acquire_node(node_id, &node);
	trace_printk("after acquire_node node = %p, err = %d\n", node, err);

	if (err) {
		return err;
	}

	err = find_publisher_in_node(node, pub_id, &pub);
	trace_printk("after find_publisher_in_node pub = %p, err = %d\n", pub, err);
	if (!err) {
		err = send_message_to_node(node, pub, info);
		trace_printk("after send_message_to_node pub = %p, info = %p, err = %d\n", pub, info, err);
	}

	release_node(node);
	delete_node_struct_if_unused(node);
	trace_puts("END\n");
	return err;
}

#ifndef PS_TEST
long ps_node_receive(unsigned long node_id, void __user *info) {
#else
long ps_node_receive(unsigned long node_id, void *info) {
#endif
	unsigned long sub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_subscriber *sub = NULL;

	trace_puts("BEGIN\n");

	err = acquire_node(node_id, &node);
	trace_printk("after acquire_node node = %p, err = %d\n", node, err);

	if (err) {
		return err;
	}

	err = find_subscriber_in_node(node, sub_id, &sub);
	trace_printk("after find_subscriber_in_node sub  = %p, pos = %p, err = %d\n", sub, sub ? sub->pos : NULL, err);
	if (!err) {
		err = receive_message_from_node(node, sub, info);
		trace_printk("after receive_message_from_node sub = %p, pos = %p, info = %p, err = %d\n", sub, sub->pos, info, err);
	}

	release_node(node);
	delete_node_struct_if_unused(node);
	trace_puts("END\n");
	return err;
}
