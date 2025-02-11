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
		trace_puts("Нельзя добавить топик!\n");
		return err;
	}
	ps_nodes_write_lock();
	trace_puts("after ps_nodes_write_lock\n");
	add_node(node);
	if (get_node_id(node, result)) {
		trace_printk("get_node return EAGAIN(\n");
	}
	trace_puts("after get_node_id\n");
	ps_nodes_write_unlock();
	trace_puts("after ps_nodes_write_unlock\nEND\n");
	return 0;
}

long ps_node_delete(unsigned long node_id) {
	struct ps_node *node = NULL;
	long err = 0;
	ps_nodes_write_lock();
	trace_printk("begin node_id = %lu\n", node_id);
	err = find_node(node_id, &node);
	trace_printk("after find_node err = %ld, node = %p\n", err, node);
	if (!err) {
		remove_node(node);
		trace_puts("after remove_node\n");
	}
	trace_puts("before ps_nodes_write_unlock\n");
	ps_nodes_write_unlock();
	trace_puts("after ps_nodes_write_unlock\n");
	if (!err) {
		ps_current_write_wait(node);
		trace_puts("after ps_current_write_wait\n");
		//TODO: Доделать delete_node
		trace_puts("before delete_node_struct\n");
		err = delete_node_struct(node);
		trace_puts("after delete_node_struct\n");
	}
	return err;
}

long ps_node_subscribe(unsigned long node_id) {
	unsigned long sub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_subscriber *sub = NULL;
	struct ps_position *pos = NULL;

	trace_printk("BEGIN node_id = %lu\n", node_id);
	err = create_subscriber_struct(sub_id, &sub);
	trace_printk("after create_subscriber_struct sub  = %p, err = %d\n", sub, err);
	if (err)
		return err;
	err = create_position_struct(&pos);
	trace_printk("after create_position_struct pos  = %p, err = %d\n", pos, err);
	if (err) {
		delete_position_struct(pos);
	trace_printk("after ps_nodes_read_lock\n");
		return -ENOMEM;
	}

	ps_nodes_read_lock();
	trace_printk("after ps_nodes_read_lock\n");

	err = find_node(node_id, &node);
	trace_printk("after find_node node = %p, node_id = %ld\n", node, node_id);
	if (!err) {
		ps_current_read_lock(node);
	trace_puts("after ps_current_read_lock\n");
	}

	ps_nodes_read_unlock();
	trace_puts("after ps_nodes_read_unlock\n");

	if (!err) {
		err = find_subscriber_in_node(node, sub_id, &sub);
	trace_printk("after find_subscriber_in_node sub  = %p, err = %d\n", sub, err);
		if (err == -ENOENT) {
			add_position_in_node(node, pos);
			add_subscriber_in_node(node, sub);
	trace_puts("after adding to collections\n");
		}
		ps_current_read_unlock(node);
	trace_puts("after ps_current_read_unlock\n");
	}
	if (err) {
		delete_position_struct(pos);
		delete_subscriber_struct(sub);
	trace_puts("after delete structures\n");
	}
	trace_puts("END\n");
	return err;
}

long ps_node_unsubscribe(unsigned long node_id) {
	unsigned long sub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_subscriber *sub = NULL;
	struct ps_position *pos = NULL;
	trace_puts("BEGIN\n");
	ps_nodes_read_lock();
	trace_printk("after ps_nodes_read_lock\n");

	err = find_node(node_id, &node);
	trace_printk("after find_node node  = %p, err = %d\n", node, err);
	if (!err) {
		ps_current_read_lock(node);
	trace_puts("after ps_current_read_lock\n");
	}

	ps_nodes_read_unlock();
	trace_puts("after ps_nodes_read_unlock\n");

	if (!err) {
		err = find_subscriber_in_node(node, sub_id, &sub);
	trace_printk("after find_subscriber_in_node sub = %p, err = %d\n", sub, err);
		if (!err) {
			remove_subscriber_in_node(node, sub);
			remove_position_in_node(node);
		trace_puts("after remove collections\n");
		}
		ps_current_read_unlock(node);
	trace_puts("after ps_current_read_unlock\n");
		if (!err) {
			delete_position_struct(pos);
			delete_subscriber_struct(sub);
	trace_puts("after delete structures\n");
		}
	}
	trace_puts("END\n");
	return err;
}

long ps_node_publish(unsigned long node_id) {
	unsigned long pub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_publisher *pub = NULL;
	trace_puts("BEGIN\n");
	err = create_publisher_struct(pub_id, &pub);
	trace_printk("after create_publisher_struct pub = %p, err = %d\n", pub, err);
	if (err) {
		return err;
	}

	ps_nodes_read_lock();
	trace_puts("after ps_nodes_read_lock\n");

	err = find_node(node_id, &node);
	trace_printk("after find_node node = %p, err = %d\n", node, err);
	if (!err) {
		ps_current_read_lock(node);
		trace_puts("after ps_current_read_lock\n");
	}
	ps_nodes_read_unlock();
	trace_puts("after ps_nodes_read_unlock\n");

	if (!err) {
		err = find_publisher_in_node(node, pub_id, &pub);
		trace_printk("after find_publisher_in_node pub = %p, err = %d\n", pub, err);
		if (err == -ENOENT) {
			err = add_publisher_in_node(node, pub);
		}
		ps_current_read_unlock(node);
	trace_puts("after ps_current_read_unlock\n");
	}
	if (err) {
		delete_publisher_struct(pub);
	trace_puts("after delete_publisher_struct\n");
	}
	trace_puts("END\n");
	return err;
}

long ps_node_unpublish(unsigned long node_id) {
	unsigned long pub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_publisher *pub = NULL;
	trace_puts("BEGIN\n");

	ps_nodes_read_lock();
	trace_puts("after ps_nodes_read_lock\n");

	err = find_node(node_id, &node);
	trace_printk("after find_node node = %p, err = %d\n", node, err);
	if (!err) {
		ps_current_read_lock(node);
		trace_puts("after ps_current_read_lock\n");
	}
	ps_nodes_read_unlock();
	trace_puts("after ps_nodes_read_unlock\n");

	if (!err) {
		err = find_publisher_in_node(node, pub_id, &pub);
		trace_printk("after find_publisher_in_node pub = %p, err = %d\n", pub, err);
		if (!err) {
			remove_publisher_in_node(node, pub);
		}
		ps_current_read_unlock(node);
		trace_puts("after ps_current_read_unlock\n");
	}

	if (!err) {
		delete_publisher_struct(pub);
		trace_puts("after delete_publisher_struct\n");
	}
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
	ps_nodes_read_lock();
	trace_puts("after ps_nodes_read_lock\n");

	err = find_node(node_id, &node);
	trace_printk("after find_node node = %p, err = %d\n", node, err);
	if (!err) {
		ps_current_read_lock(node);
	trace_puts("after ps_current_read_lock\n");
	}

	ps_nodes_read_unlock();
	trace_puts("after ps_nodes_read_unlock\n");

	if (!err) {
		err = find_publisher_in_node(node, pub_id, &pub);
	trace_printk("after find_publisher_in_node pub = %p, err = %d\n", pub, err);
		if (!err) {
			err = send_message_to_node(node, pub, info);
		trace_printk("after send_message_to_node pub = %p, info = %p, err = %d\n", pub, info, err);
	}
		ps_current_read_unlock(node);
	trace_puts("after ps_current_read_unlock\n");
	}
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

	ps_nodes_read_lock();
	trace_puts("after ps_nodes_read_lock\n");

	err = find_node(node_id, &node);
	trace_printk("after find_node node = %p, err = %d\n", node, err);
	if (!err) {
		ps_current_read_lock(node);
	trace_puts("after ps_current_read_lock\n");
	}

	ps_nodes_read_unlock();
	trace_puts("after ps_nodes_read_unlock\n");

	if (!err) {
		err = find_subscriber_in_node(node, sub_id, &sub);
	trace_printk("after find_subscriber_in_node sub = %p, err = %d\n", sub, err);
		if (!err) {
			err = receive_message_from_node(node, sub, info);
		trace_printk("after receive_message_from_node sub = %p, info = %p, err = %d\n", sub, info, err);
	}
		ps_current_read_unlock(node);
	trace_puts("after ps_current_read_unlock\n");
	}
	trace_puts("END\n");
	return err;
}
