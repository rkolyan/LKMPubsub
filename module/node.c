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

//TODO: Позиции будут контроллироваться внутри буфера, так как имеют отношения только к нему и подписчикам
/*
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
*/
int add_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub) {
	if (!node || !sub)
		return -EINVAL;

	struct ps_position *pos = NULL;
	//TODO: Увеличить количество positions
	int err = buffer_positions_inc(&node->buf);//TODO:
	//TODO: В случае ошибки надо быть осторожней
	//TODO: spin_lock
	if (!positions_used_empty(&node->buf)) {
		pos = find_first_position(&node->buf);
	} else {
		pos = find_free_position(&node->buf);
		pop_free_position(&node->buf, pos);
		push_used_position_begin(&node->buf, pos);
	}
	connect_subscriber_position(sub, pos);
	//TODO: spin_unlock
	
	//TODO: Надо быть осторожней с добавлением sub до или после нахождения position
	spin_lock(&(node->subs_lock));
	add_subscriber(&(node->subs_coll), sub);
	spin_unlock(&(node->subs_lock));
	return err;
}

int remove_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub) {
	if (!node || !sub)
		return -EINVAL;
	//TODO: Хз, стоит ли исправлять всю функцию
	struct ps_position *pos = NULL;
	spin_lock(&(node->subs_lock));
	pos = get_subscriber_position(sub);
	spin_lock(&(node->pos_lock));
	disconnect_subscriber_position(sub);
	if (is_position_not_used(pos)) {
		pop_used_position(&node->buf, pos);
		push_free_position(&node->buf, pos);
	}
	spin_unlock(&node->pos_lock);
	remove_subscriber(&(node->subs_coll), sub);
	spin_unlock(&(node->subs_lock));
	synchronize_rcu();
	buffers_positions_dec(&node->buf);//TODO: 
	return 0;
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
	int msg_num = 0, err = 0;
	void *addr = NULL;
	struct ps_prohibition *proh = get_publisher_prohibition(pub);
	//TODO: Вруби спин-лок защиту или реализуй её при помощи атомарных переменных
	//TODO: is_buffer_access_writing
	if (!is_buffer_access_writing(&(node->buf))) {
		//1)Получить свободный номер (это end_num)
		prohibit_buffer_end(&node->buf, proh);//TODO: Автоматически обновляет end_write
		//TODO: Конец защиты
		err = write_to_buffer_end(&(node->buf), info);//TODO: Автоматически записывает в последний запрещенный адрес
		//TODO:Далее защищаем буфер 
		unprohibit_buffer(&(node->buf), proh);
	} else {
		//Пока не все сообщения прочитаны
		err = -EAGAIN;
	}
	//TODO: Конец защиты
	return err;
}

//TODO: positions = кол-во подписчиков + 1
#ifndef PS_TEST
int receive_message_from_node(struct ps_node *node, struct ps_subscriber *sub, void __user *info) {
#else
int receive_message_from_node(struct ps_node *node, struct ps_subscriber *sub, void *info) {
#endif
	if (!node || !info || !sub)
		return -EINVAL;
	struct ps_position *pos = get_subscriber_position(sub), *new_pos = NULL;
	if (!is_position_out_of_bound(&node->buf, pos)) {
		err = read_from_buffer_at_position(&node->buf, pos, info);
		//TODO: Защита на позиции
		if (!is_position_end_bound(&node->buf, pos)) {
			new_pos = find_next_position(&node->buf, pos);
			if (!new_pos) {
				new_pos = find_free_position(&node->buf);
				if (new_pos) {
					pop_free_position(&node->buf, new_pos);
					push_used_position_after(&node->buf, new_pos, pos);
				} else {
					err = -ENOSPC;
				}
			}
		}
		if (!err) {
			connect_subscriber_position(sub, new_pos);
			disconnect_subscriber_position(sub, pos);
			if (is_position_not_used(pos)) {
				push_used_position(&node->buf, pos);
				push_free_position(&node->buf, pos);
			}
		}
		//TODO: Конец защиты
	} else {
		err = -EAGAIN;//Пока новые сообщения не приходили
	}
	return err;
}
