#include "buffer.h"
#include "subscriber.h"
#include "publisher.h"
#include "node.h"


#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/atomic.h>
#include <linux/delay.h>

#define NODE_HASHTABLE_BITS 4

DEFINE_HASHTABLE(nodes, NODE_HASHTABLE_BITS);
static spinlock_t nodes_lock;
atomic_t process_count;

int init_nodes(void){
	spin_lock_init(&nodes_lock);
	atomic_set(&process_count, 0);
	return 0;
}

//По идее там в начале будут удалены перехватчики
int deinit_nodes(void) {
	struct ps_node *node = NULL;
	int bkt = 0;
	struct hlist_node *tmp = NULL;
	while(atomic_read(&process_count)) {
		mdelay(50);
	};
	hash_for_each_safe(nodes, bkt, tmp, node, hlist) {
		hash_del(&(node->hlist));
		delete_node_struct(node);
	}
	return 0;
}

#ifndef PS_TEST
int get_node_id(struct ps_node *node, unsigned long __user *result) {
#else
int get_node_id(struct ps_node *node, unsigned long *result) {
#endif
	if (!node || !result) {
		return -EINVAL;
	}
#ifndef PS_TEST
	if (copy_to_user(result, &(node->id), sizeof(unsigned long))) {
#else
	if (!memcpy(result, &(node->id), sizeof(unsigned long))) {
#endif
		return -EAGAIN;
	}
	return 0;
}

int create_node_struct(size_t buf_size, size_t block_size, struct ps_node **result) {
	if (buf_size == 0 || block_size == 0 || result == NULL)
		return -EINVAL;
	struct ps_node *node = vzalloc(sizeof(struct ps_node));
	if (!node)
		return -ENOMEM;
	INIT_HLIST_NODE(&(node->hlist));
	node->id = (unsigned long) (&(node->hlist));
	int err = init_buffer(&(node->buf), buf_size, block_size);
	if (err) {
		vfree(node);
		return err;
	}
	init_publisher_collection(&(node->pubs_coll));
	init_subscriber_collection(&(node->subs_coll));
	trace_printk("&subs_lock == %p, &pubs_lock == %p, &nodes_lock == %p\n", &node->subs_lock, &node->pubs_lock, &nodes_lock);
	spin_lock_init(&node->subs_lock);
	spin_lock_init(&node->pubs_lock);
	spin_lock_init(&node->pos_lock);
	atomic_set(&(node->delete_flag), 0);
	atomic_set(&(node->use_count), 0);
	*result = node;
	return 0;
}

int delete_node_struct(struct ps_node *node) {
	if (!node)
		return -EINVAL;
	clear_publisher_collection(&(node->pubs_coll));
	clear_subscriber_collection(&(node->subs_coll));
	deinit_buffer(&(node->buf));
	vfree(node);
	return 0;
}

int delete_node_struct_if_unused(struct ps_node *node) {
	if (!node)
		return -EINVAL;
	//Нужно чтоб во время удаления не оказалось, что нода ещё кем-то используется, но use_count ещё не инкрементирована. 
	synchronize_rcu();
	if (atomic_read(&(node->delete_flag)) && !atomic_read(&(node->use_count))) {
		delete_node_struct(node);
	}
	return 0;
}

void mark_node_unused(struct ps_node *node) {
	atomic_set(&(node->delete_flag), 1);
}

int acquire_node(unsigned long id, struct ps_node **result) {
	if (!result)
		return -EINVAL;
	struct ps_node *node = NULL;
	int err = 0;
	rcu_read_lock();
	hash_for_each_possible_rcu(nodes, node, hlist, id) {
		if (node->id == id) {
			atomic_inc(&node->use_count);
			atomic_inc(&process_count);
			break;
		}
	}
	if (node) {
		*result = node;
	} else {
		err = -ENOENT;
	}
	rcu_read_unlock();
	return err;
}

int release_node(struct ps_node *node) {
	if (!node)
		return -EINVAL;
	atomic_dec(&node->use_count);
	atomic_dec(&process_count);
	return 0;
}

int add_node(struct ps_node *node) {
	if (!node)
		return -EINVAL;
	spin_lock(&nodes_lock);
	hash_add_rcu(nodes, &(node->hlist), node->id);
	spin_unlock(&nodes_lock);
	return 0;
}

int remove_node(struct ps_node *node) {
	if (!node)
		return -EINVAL;
	spin_lock(&nodes_lock);
	hash_del(&(node->hlist));
	spin_unlock(&nodes_lock);
	synchronize_rcu();
	return 0;
}

int add_publisher_in_node(struct ps_node *node, struct ps_publisher *pub) {
	if (!node || !pub)
		return -EINVAL;
	spin_lock(&(node->pubs_lock));
	int err = add_publisher(&(node->pubs_coll), pub);
	spin_unlock(&(node->pubs_lock));
	return err;
}

int find_publisher_in_node(struct ps_node *node, pid_t pid, struct ps_publisher **result) {
	if (!node || pid < 0 || !result)
		return -EINVAL;
	return find_publisher(&(node->pubs_coll), pid, result);
}

int remove_publisher_in_node(struct ps_node *node, struct ps_publisher *pub) {
	if (!node || !pub)
		return -EINVAL;
	spin_lock(&(node->pubs_lock));
	int err = remove_publisher(&(node->pubs_coll), pub);
	spin_unlock(&(node->pubs_lock));
	synchronize_rcu();
	return err;
}

int add_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub) {
	if (!node || !sub)
		return -EINVAL;

	struct ps_position *add_pos = create_position_struct(), *pos = NULL;
	if (!add_pos)
		return -ENOMEM;
	int err = 0;
	spin_lock(&node->pos_lock);
	push_free_position(&node->buf, add_pos);
	pos = find_first_position(&node->buf);
	if (!pos) {
		pos = find_free_position(&node->buf);
		if (pos) {
			pop_free_position(&node->buf, pos);
			push_used_position_begin(&node->buf, pos);
		} else {
			err = -ENOENT;
		}
	}
	if (!err) {
		connect_subscriber_position(sub, pos);
	}
	spin_unlock(&node->pos_lock);
	if (!err) {
		spin_lock(&(node->subs_lock));
		add_subscriber(&(node->subs_coll), sub);
		spin_unlock(&(node->subs_lock));
	}
	return err;
}

void remove_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub) {
	struct ps_position *pos = NULL, *del_pos = NULL;
	spin_lock(&(node->subs_lock));
	remove_subscriber(&(node->subs_coll), sub);
	spin_unlock(&(node->subs_lock));
	spin_lock(&(node->pos_lock));
	pos = get_subscriber_position(sub);
	disconnect_subscriber_position(sub, pos);
	if (!is_position_used(&node->buf, pos)) {
		pop_used_position(&node->buf, pos);
		push_free_position(&node->buf, pos);
	}
	del_pos = find_free_position(&node->buf);
	if (del_pos)
		pop_free_position(&node->buf, del_pos);
	spin_unlock(&node->pos_lock);
	if (del_pos)
		delete_position_struct(del_pos);
	synchronize_rcu();
}

int find_subscriber_in_node(struct ps_node *node, pid_t pid, struct ps_subscriber **result) {
	if (!node || pid < 0 || !result)
		return -EINVAL;
	return find_subscriber(&(node->subs_coll), pid, result);
}

#ifndef PS_TEST
int send_message_to_node(struct ps_node *node, struct ps_publisher *pub, void __user *info) {
#else
int send_message_to_node(struct ps_node *node, struct ps_publisher *pub, void *info) {
#endif
	if (!node || !info || !pub)
		return -EINVAL;
	int err = 0;
	struct ps_prohibition *proh = get_publisher_prohibition(pub);
	trace_printk("pub == %p, proh == %p\n", pub, proh);
	spin_lock(&node->pos_lock);
	if (is_prohibit_success(&node->buf)) {
		prohibit_buffer_end(&node->buf, proh);
		spin_unlock(&node->pos_lock);

		err = write_to_buffer_end(&(node->buf), proh, info);

		spin_lock(&node->pos_lock);
		unprohibit_buffer(&(node->buf), proh);
	} else {
		//Пока не все сообщения прочитаны
		err = -EAGAIN;
	}
	spin_unlock(&node->pos_lock);
	return err;
}

#ifndef PS_TEST
int receive_message_from_node(struct ps_node *node, struct ps_subscriber *sub, void __user *info) {
#else
int receive_message_from_node(struct ps_node *node, struct ps_subscriber *sub, void *info) {
#endif
	if (!node || !info || !sub)
		return -EINVAL;
	int err = 0;
	struct ps_position *pos = get_subscriber_position(sub), *new_pos = NULL;
	//trace_printk("after get_subscriber_position pos = %p, sub = %p\n", pos, sub);
	int flag = is_position_incorrect(&node->buf, pos);
	trace_printk("after is_position_incorrect flag = %d, pos = %p\n", flag, pos);
	if (pos)
		trace_printk("pos->addr = %p, diff_begin = %ld, diff_end_read = %ld\n", pos->addr, node->buf.begin - pos->addr, node->buf.end - pos->addr);
	else
		return -EBADF;
	if (!flag) {
		trace_puts("after is_position_correct\n");
		err = read_from_buffer_at_position(&node->buf, pos, info);
		trace_printk("after read_from_buffer_at_position err = %d\n", err);
		spin_lock(&node->pos_lock);
		if (!err) {
			new_pos = find_next_position(&node->buf, pos);
			trace_printk("after find_next_position new_pos = %p\n", new_pos);
			if (!new_pos) {
				new_pos = find_free_position(&node->buf);
				trace_printk("after find_free_position new_pos = %p\n", new_pos);
				if (new_pos) {
					pop_free_position(&node->buf, new_pos);
					push_used_position_after(&node->buf, new_pos, pos);
				} else {
					err = -ENOSPC;
				}
			}
		}
		if (!err) {
			disconnect_subscriber_position(sub, pos);
			connect_subscriber_position(sub, new_pos);
			if (!is_position_used(&node->buf, pos)) {
				pop_used_position(&node->buf, pos);
				push_free_position(&node->buf, pos);
			}
		}
		spin_unlock(&node->pos_lock);
	} else {
		err = -EAGAIN;//Пока новые сообщения не приходили
	}
	return err;
}
