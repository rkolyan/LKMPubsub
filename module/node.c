#include "position.h"
#include "buffer.h"
#include "subscriber.h"
#include "publisher.h"
#include "node.h"


#include <linux/rwsem.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>

#define NODE_HASHTABLE_BITS 4

DEFINE_HASHTABLE(nodes, NODE_HASHTABLE_BITS);
static rwlock_t nodes_rwlock;

int init_nodes(void){
	//nodes и nodes_rwlock уже до вызова определелены
	ps_nodes_init_lock();
	return 0;
}

int deinit_nodes(void) {
	ps_nodes_write_lock();
	struct ps_node *node = NULL;
	int bkt = 0;
	struct hlist_node *tmp = NULL;
	hash_for_each_safe(nodes, bkt, tmp, node, hlist) {
		hash_del(&(node->hlist));
		delete_node_struct(node);
	}
	ps_nodes_write_unlock();
	return 0;
}

void ps_nodes_init_lock(void) {
	rwlock_init(&nodes_rwlock);
}

void ps_nodes_read_lock(void) {
	read_lock(&nodes_rwlock);
}

void ps_nodes_read_unlock(void) {
	read_unlock(&nodes_rwlock);
}

void ps_nodes_write_lock(void) {
	write_lock(&nodes_rwlock);
}
void ps_nodes_write_unlock(void) {
	//trace_printk("%s:&nodes_rwlock = %p\n", __func__, &nodes_rwlock);
	write_unlock(&nodes_rwlock);
	//trace_printk("%s:after write_unlock\n", __func__);
}

void ps_current_read_lock(struct ps_node *node) {
	down_read(&(node->node_rwsem));
}

void ps_current_read_unlock(struct ps_node *node) {
	up_read(&(node->node_rwsem));
}

void ps_current_write_wait(struct ps_node *node) {
	trace_printk("before down_write, node=%p, &(node->node_rwsem)=%p\n", node, &(node->node_rwsem));
	mdelay(10);
	down_write(&(node->node_rwsem));
	trace_puts("after down_write\n");
	mdelay(10);
	up_write(&(node->node_rwsem));
	mdelay(10);
	trace_puts("after up_write\n");
}

#ifndef PS_TEST
int get_node_id(struct ps_node *node, unsigned long __user *result) {
	if (copy_to_user(result, &(node->id), sizeof(unsigned long))) {
#else
int get_node_id(struct ps_node *node, unsigned long *result) {
	if (!memcpy(result, &(node->id), sizeof(unsigned long))) {
#endif
		return -EAGAIN;
	}
	return 0;
}

int create_node_struct(size_t buf_size, size_t block_size, struct ps_node **result) {
	if (buf_size == 0 || block_size == 0 || block_size > buf_size || result == NULL)
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
	init_rwsem(&(node->node_rwsem));
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

	return 0;
}

int find_node(unsigned long id, struct ps_node **result) {
	if (!result)
		return -EINVAL;
	struct ps_node *node = NULL;
	hash_for_each_possible(nodes, node, hlist, id) {
		if (node->id == id)
			break;
	}
	if (!node || node->id != id)
		return -ENOENT;
	*result = node;
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

int remove_position_in_node(struct ps_node *node) {
	if (!node)
		return -EINVAL;
	struct ps_position *pos = NULL;
	spin_lock(&(node->pos_lock));
	int err = find_free_position(&(node->desc), &pos);
	if (!err)
		pop_free_position(&(node->desc), pos);
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
	if (!err) {
		connect_subscriber_position(sub, pos);
	} else if (err == -ENOENT) {
		err = find_free_position(&(node->desc), &pos);
		if (!err) {
			pop_free_position(&(node->desc), pos);
			int msg_num = get_buffer_begin_num(&(node->buf));
			set_position_num(pos, msg_num);
			connect_subscriber_position(sub, pos);
			push_used_position_last(&(node->desc), pos);
		} else {
			err = EBADF;
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
	return 0;
}

int find_subscriber_in_node(struct ps_node *node, pid_t pid, struct ps_subscriber **result) {
	if (!node || pid < 0 || !result)
		return -EINVAL;
	int err = 0;
	//down_read(node->subs_rwsem);
	err = find_subscriber(&(node->subs_coll), pid, result);
	//up_read(node->subs_rwsem);
	return err;
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
	int err = 0;
	err = find_publisher(&(node->pubs_coll), pid, result);
	return err;
}

int remove_publisher_in_node(struct ps_node *node, struct ps_publisher *pub) {
	if (!node || !pub)
		return -EINVAL;
	spin_lock(&(node->pubs_lock));
	int err = remove_publisher(&(node->pubs_coll), pub);
	spin_unlock(&(node->pubs_lock));
	return err;
}

int add_node(struct ps_node *node) {
	if (!node) {
		return -EINVAL;
	}
	hash_add(nodes, &(node->hlist), node->id);
	return 0;
}

int remove_node(struct ps_node *node) {
	if (!node) {
		return -EINVAL;
	}
	hash_del(&(node->hlist));
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
	//1)Проверка, находится ли текущий номер в области допустимых значений (для этого в buffer необходимо добавить значение end_read, которое обновляется после каждого завершения записи)
	if (is_buffer_access_reading(&(node->buf), msg_num)) {
		//2)Получаем по номеру адрес буфера
		addr = get_buffer_address(&(node->buf), msg_num);
		//3)Читаем
		err = read_from_buffer(&(node->buf), addr, info);
		//4)Далее отказываемся от позиции на этом номере
		disconnect_subscriber_position(sub);
		//5)Если позиция не используется - переводим в список свободных позиций

		spin_lock(&(node->pos_lock));
		if (is_position_not_used(pos)) {
			pop_used_position(&(node->desc), pos);
			push_free_position(&(node->desc), pos);
			if (get_buffer_begin_num(&(node->buf)) == msg_num)
				delete_first_message(&(node->buf));
		}
		spin_unlock(&(node->pos_lock));
		msg_num++;
		spin_lock(&(node->pos_lock));
		//Тут есть проблема, а как определить подписчику где первое сообщение?(Ответ:по begin, )
		err = find_msg_num_position(&(node->desc), msg_num, &new_pos);
		if (!err) {
			connect_subscriber_position(sub, new_pos);
		} else if (err == -ENOENT) {
			err = find_next_position(&(node->desc), pos, &next_pos);
			if (!err) {
				err = find_free_position(&(node->desc), &new_pos);
				if (!err) {
					pop_free_position(&(node->desc), new_pos);
					set_position_num(new_pos, msg_num);
					connect_subscriber_position(sub, new_pos);
					push_used_position_before(&(node->desc), new_pos, next_pos);
				}
			} else if (err == -ENOENT) {
				err = find_free_position(&(node->desc), &new_pos);
				if (!err) {
					pop_free_position(&(node->desc), new_pos);
					set_position_num(new_pos, msg_num);
					connect_subscriber_position(sub, new_pos);
					push_used_position_last(&(node->desc), new_pos);
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
		set_prohibition_num(proh, msg_num);
		//2)Получить адрес свободного блока (это end)
		addr = get_buffer_address(&(node->buf), msg_num);
		prohibit_buffer(&(node->buf), proh);

		create_last_message(&(node->buf));
		spin_unlock(&(node->pos_lock));

		err = write_to_buffer(&(node->buf), addr, info);

		spin_lock(&(node->pos_lock));
		unprohibit_buffer(&(node->buf), proh);
	}
	spin_unlock(&(node->pos_lock));
	return err;
}
