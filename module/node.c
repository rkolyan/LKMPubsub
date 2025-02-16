#include "position.h"
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
atomic_t nodes_count;

int init_nodes(void){
	spin_lock_init(&nodes_lock);
	atomic_set(&nodes_count, 0);
	return 0;
}

//TODO: По идее там в начале будут удалены перехватчики
int deinit_nodes(void) {
	struct ps_node *node = NULL;
	int bkt = 0, node_unused_count = 0;
	struct hlist_node *tmp = NULL;
	rcu_read_lock();
	hash_for_each_rcu(nodes, bkt, node, hlist) {
		if(atomic_cmpxchg(&node->delete_flag, 0, 1) && !atomic_read(&node->use_count)) {
			node_unused_count++;
		}
	}
	rcu_read_unlock();
	while(atomic_read(&nodes_count) != node_unused_count) {
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
	trace_puts("vzalloc successed!\n");
	INIT_HLIST_NODE(&(node->hlist));
	node->id = (unsigned long) (&(node->hlist));
	int err = init_buffer(&(node->buf), buf_size, block_size);
	if (err) {
		//pr_err(__func__ ":Нельзя выделить памяти для вспомогательной информации ps_buffer!");
		vfree(node);
		return err;
	}
	init_positions_desc(&(node->desc));
	init_publisher_collection(&(node->pubs_coll));
	init_subscriber_collection(&(node->subs_coll));
	trace_printk("&subs_lock == %p, &pubs_lock == %p, &nodes_lock == %p\n", &node->subs_lock, &node->pubs_lock, &nodes_lock);
	mdelay(50);
	spin_lock_init(&node->subs_lock);
	spin_lock_init(&node->pubs_lock);
	atomic_set(&(node->delete_flag), 0);
	atomic_set(&(node->use_count), 0);
	atomic_inc(&(nodes_count));
	*result = node;
	trace_puts("vzalloc ended!\n");
	return 0;
}

int delete_node_struct(struct ps_node *node) {
	if (!node)
		return -EINVAL;
	trace_printk("%s:before clear_publisher_collection\n", __func__);
	clear_publisher_collection(&(node->pubs_coll));
	trace_printk("%s:before clear_subscriber_collection\n", __func__);
	clear_subscriber_collection(&(node->subs_coll));
	trace_printk("%s:before deinit_positions_desc\n", __func__);
	deinit_positions_desc(&(node->desc));
	trace_printk("%s:before deinit_buffer\n", __func__);
	deinit_buffer(&(node->buf));
	trace_printk("%s:before vfree\n", __func__);
	vfree(node);
	atomic_dec(&nodes_count);
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
		if (node->id == id)
			break;
	}
	if (!node || node->id != id) {
		err = -ENOENT;
	}
	if (!err) {
		*result = node;
	}
	rcu_read_unlock();
	return err;
}

int release_node(struct ps_node *node) {
	if (!node)
		return -EINVAL;
	atomic_dec(&node->use_count);
	return 0;
}

int add_position_in_node(struct ps_node *node, struct ps_position *pos) {
	if (!node || !pos)
		return -EINVAL;
	spin_lock(&(node->pos_lock));
	push_free_position(&(node->desc), pos);
	spin_unlock(&(node->pos_lock));
	return 0;
}

int remove_position_in_node(struct ps_node *node, struct ps_position **result) {
	if (!node)
		return -EINVAL;
	struct ps_position *pos = NULL;
	spin_lock(&(node->pos_lock));
	int err = find_free_position(&(node->desc), &pos);
	if (!err) {
		pop_free_position(&(node->desc), pos);
		*result = pos;
	}
	spin_unlock(&(node->pos_lock));
	return err;
}

int add_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub) {
	if (!node || !sub)
		return -EINVAL;

	spin_lock(&(node->subs_lock));
	add_subscriber(&(node->subs_coll), sub);
	spin_unlock(&(node->subs_lock));
	struct ps_position *pos = NULL;
	spin_lock(&(node->pos_lock));
	int err = find_first_position(&(node->desc), &pos);
	trace_printk("after find_first_position err = %d, pos = %p\n", err, pos);
	if (!err) {
		connect_subscriber_position(sub, pos);
	} else if (err == -ENOENT) {
		err = find_free_position(&(node->desc), &pos);
		trace_printk("after find_free_position err = %d, pos = %p\n", err, pos);
		if (!err) {
			pop_free_position(&(node->desc), pos);
			trace_puts("after pop_free_position\n");
			int msg_num = get_buffer_begin_num(&(node->buf));
			trace_printk("after get_buffer_begin_num msg_num = %d\n", msg_num);
			set_position_num(pos, msg_num);
			connect_subscriber_position(sub, pos);
			push_used_position_last(&(node->desc), pos);
			trace_puts("after push_used_position_last\n");
		} else {
			err = -EBADF;
		}
	}
	spin_unlock(&(node->pos_lock));
	return err;
}

int remove_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub) {
	if (!node || !sub)
		return -EINVAL;
	struct ps_position *pos = NULL;
	spin_lock(&(node->subs_lock));
	pos = get_subscriber_position(sub);
	spin_lock(&(node->pos_lock));
	disconnect_subscriber_position(sub);
	if (is_position_not_used(pos)) {
		pop_used_position(&(node->desc), pos);
		push_free_position(&(node->desc), pos);
	}
	spin_unlock(&(node->pos_lock));
	remove_subscriber(&(node->subs_coll), sub);
	spin_unlock(&(node->subs_lock));
	synchronize_rcu();
	return 0;
}

int find_subscriber_in_node(struct ps_node *node, pid_t pid, struct ps_subscriber **result) {
	if (!node || pid < 0 || !result)
		return -EINVAL;
	return find_subscriber(&(node->subs_coll), pid, result);
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

int add_node(struct ps_node *node) {
	if (!node) {
		return -EINVAL;
	}
	spin_lock(&nodes_lock);
	hash_add_rcu(nodes, &(node->hlist), node->id);
	spin_unlock(&nodes_lock);
	return 0;
}

int remove_node(struct ps_node *node) {
	if (!node) {
		return -EINVAL;
	}
	spin_lock(&nodes_lock);
	hash_del(&(node->hlist));
	spin_unlock(&nodes_lock);
	synchronize_rcu();
	return 0;
}

#ifndef PS_TEST
int receive_message_from_node(struct ps_node *node, struct ps_subscriber *sub, void __user *info) {
#else
int receive_message_from_node(struct ps_node *node, struct ps_subscriber *sub, void *info) {
#endif
	if (!node || !info || !sub)
		return -EINVAL;
	struct ps_position *pos = get_subscriber_position(sub), *next_pos = NULL, *new_pos = NULL;
	void *addr = NULL;
	int msg_num = get_position_num(pos), err = 0;
	trace_printk("sub = %p, pos = %p, msg_num = %d\n", sub, pos, msg_num);
	//1)Проверка, находится ли текущий номер в области допустимых значений (для этого в buffer необходимо добавить значение end_read, которое обновляется после каждого завершения записи)
	if (is_buffer_access_reading(&(node->buf), msg_num)) {
		//2)Получаем по номеру адрес буфера
		addr = get_buffer_address(&(node->buf), msg_num);
		trace_printk("after get_buffer_address addr = %p, tmp_address = %p, msg_num = %d\n", addr, ((char *)node->buf.base_begin) + msg_num * node->buf.blk_size, msg_num);
		//3)Читаем
		err = read_from_buffer(&(node->buf), addr, info);
		trace_printk("after read_from_buffer err = %d\n", err);
		//4)Далее отказываемся от позиции на этом номере
		trace_printk("before disconnect_subscriber_position pos->count = %u\n", pos->cnt);
		disconnect_subscriber_position(sub);
		//5)Если позиция не используется - переводим в список свободных позиций
		trace_printk("after disconnect_subscriber_position pos->count = %u\n", pos->cnt);

		spin_lock(&(node->pos_lock));
		if (is_position_not_used(pos)) {
			trace_puts("after is_position_not_used\n");
			pop_used_position(&(node->desc), pos);
			trace_puts("after pop_used_position\n");
			push_free_position(&(node->desc), pos);
			trace_puts("after push_free_position\n");
			if (get_buffer_begin_num(&(node->buf)) == msg_num) {
				trace_puts("after get_buffer_begin_num\n");
				delete_first_message(&(node->buf));
				trace_puts("after delete_first_message\n");
			}
		}
		spin_unlock(&(node->pos_lock));
		msg_num++;
		trace_puts("after msg_num++\n");
		spin_lock(&(node->pos_lock));
		//Тут есть проблема, а как определить подписчику где первое сообщение?(Ответ:по begin, )
		err = find_msg_num_position(&(node->desc), msg_num, &new_pos);
		trace_printk("after find_msg_num_position err = %d, msg_num = %d, new_pos = %p\n", err, msg_num, new_pos);
		if (!err) {
			connect_subscriber_position(sub, new_pos);
			trace_puts("after_subscriber_position\n");
		} else if (err == -ENOENT) {
			err = find_next_position(&(node->desc), pos, &next_pos);
			trace_printk("after_find_next_position err = %d, next_pos = %p\n", err, next_pos);
			if (!err) {
				err = find_free_position(&(node->desc), &new_pos);
				trace_printk("after find_free_position err = %d, new_pos = %p\n", err, new_pos);
				if (!err) {
					pop_free_position(&(node->desc), new_pos);
					trace_puts("after pop_free_position\n");
					set_position_num(new_pos, msg_num);
					connect_subscriber_position(sub, new_pos);
					push_used_position_before(&(node->desc), new_pos, next_pos);
					trace_puts("after push_used_position_before\n");
				}
			} else if (err == -ENOENT) {
				err = find_free_position(&(node->desc), &new_pos);
				trace_printk("after find_free_position err = %d, new_pos = %p\n", err, new_pos);
				if (!err) {
					pop_free_position(&(node->desc), new_pos);
					trace_puts("after pop_free_position\n");
					set_position_num(new_pos, msg_num);
					connect_subscriber_position(sub, new_pos);
					push_used_position_last(&(node->desc), new_pos);
					trace_puts("after push_used_position_last\n");
				}
			}
		}
		spin_unlock(&(node->pos_lock));
	} else {
		err = -EAGAIN;
	}
	return err;
}

#ifndef PS_TEST
int send_message_to_node(struct ps_node *node, struct ps_publisher *pub, void __user *info) {
#else
int send_message_to_node(struct ps_node *node, struct ps_publisher *pub, void *info) {
#endif
	if (!node || !info || !pub)
		return -EINVAL;
	int msg_num = 0, err = 0;
	void *addr = NULL;
	struct ps_prohibition *proh = get_publisher_prohibition(pub);
	spin_lock(&(node->pos_lock));
	if (!is_buffer_full(&(node->buf))) {
		//1)Получить свободный номер (это end_num)
		msg_num = get_buffer_end_num(&(node->buf));
		trace_printk("after get_buffer_end_num msg_num = %d\n", msg_num);
		set_prohibition_num(proh, msg_num);
		//2)Получить адрес свободного блока (это end)
		addr = get_buffer_address(&(node->buf), msg_num);
		trace_printk("after get_buffer_address addr = %p, tmp_addr = %p\n", addr, node->buf.base_begin + msg_num * node->buf.blk_size);
		prohibit_buffer(&(node->buf), proh);

		create_last_message(&(node->buf));//TODO: Название тупое
		spin_unlock(&(node->pos_lock));

		err = write_to_buffer(&(node->buf), addr, info);
		trace_printk("after write_to_buffer str = \"%20s\", addr = \"%10s\", info = \"%10s\"\n", (char *)&node->buf.base_begin, (char *)addr, (char *)info);

		spin_lock(&(node->pos_lock));
		unprohibit_buffer(&(node->buf), proh);
	}
	spin_unlock(&(node->pos_lock));
	return err;
}
