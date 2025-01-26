#include "position.h"
#include "buffer.h"
#include "subscriber.h"
#include "publisher.h"
#include "node.h"

#include <linux/rwsem.h>
#include <linux/vmalloc.h>

#define NODE_HASHTABLE_BITS 4

struct ps_node {
	unsigned long id;
	struct ps_buffer buf;
    spinlock_t buf_lock;
	struct ps_positions_desc desc;
	struct rw_semaphore node_rwsem;//Для защиты от удаления
	spinlock_t subs_lock;//TODO: А нужно ли?
    spinlock_t pubs_lock;//TODO: А нужно ли?
    struct ps_subscribers_collection subs_coll;
    struct ps_publishers_collection pubs_coll;
	struct hlist_node hlist;//Элемент из хеш-таблицы
};

DEFINE_HASHTABLE(nodes, NODE_HASHTABLE_BITS);
static rwlock_t nodes_rwlock;

int init_nodes(void){
    //nodes и nodes_rwlock уже до вызова определелены
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
	write_unlock(&nodes_rwlock);
}

void ps_current_read_lock(struct ps_node *node) {
	down_read(&(node->node_rwsem));
}

void ps_current_read_unlock(struct ps_node *node) {
	up_read(&(node->node_rwsem));
}

void ps_current_write_wait(struct ps_node *node) {
	down_write(&(node->node_rwsem));
	up_write(&(node->node_rwsem));
}

int get_node_id(struct ps_node *node, unsigned long __user *result) {
    if (copy_to_user(result, &(node->id), sizeof(unsigned long)) != sizeof(unsigned long))
        return -EAGAIN;
    return 0;
}

int create_node_struct(size_t buf_size, size_t block_size, unsigned int flag, struct ps_node **result) {
	if (buf_size == 0 || block_size == 0 || block_size > buf_size || result == NULL)
		return -EINVAL;
	struct ps_node *node = vzalloc(sizeof(struct ps_node));
	if (!node)
		return -ENOMEM;
	INIT_HLIST_NODE(&(node->hlist));
	node->id = (unsigned long) &(node->hlist);
	int err = init_buffer(&(node->buf), buf_size, block_size, flag);
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
	return 0;
}

int delete_node_struct(struct ps_node *node) {
	if (!node)
		return -EINVAL;
	struct list_head *ptr = NULL, *tmp = NULL;
	struct ps_message *msg = NULL;

    clear_publisher_collection(&(node->pubs_coll));
    clear_subscriber_collection(&(node->subs_coll));
    deinit_positions_desc();
    deinit_buffer();

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
	return 0;
}

int add_position_in_node(struct ps_node *node, struct ps_position *pos) {
    if (!node || !pos)
        return -EINVAL;
    //TODO: Сделать защиту от одновременного доступа к критической секции
    return push_free_position(&(node->desc), pos);
}

int remove_position_in_node(struct ps_node *node) {
    if (!node)
        return -EINVAL;
    struct ps_position *pos = NULL;
    int err = find_free_position(&(node->desc), &pos);
    if (err)
        return -ENOENT;
    return pop_free_position(&(node->desc), pos);
}

int add_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub) {
    if (!node || !sub)
        return -EINVAL;

    //TODO: Сделай так, что при поиске первой позиции в случае отсутствия таковой создание новой (Или удаление, до тех пор, пока не будет найдена след) можно было
    spin_lock(&(node->subs_lock));
    add_subscriber(&(node->subs_coll), sub);
    spin_unlock(&(node->subs_lock));
    struct ps_position *pos = NULL;
    int err = find_first_position(&(node->desc), &pos);
    if (!err) {
        connect_subscriber_position(sub, pos);
    } else if (err == -ENOENT) {
        err = find_free_position(&(node->desc), &pos);
        if (!err) {
            pop_free_position(&(node->desc), pos);
            int msg_num = 0;
            get_buffer_begin_num(&(node->buf), &msg_num);
            set_position_num(pos, msg_num);
            connect_subscriber_position(sub, pos);
            push_used_position_last(&(node->desc), pos);
        }
    }
    return err;
}

int remove_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub) {
    if (!node || !sub)
        return -EINVAL;
    struct ps_position *pos = NULL;
    spin_lock(&(node->subs_lock));
    get_subscriber_position(sub, &pos);
    disconnect_subscriber_position(sub);
    if (is_position_not_used(pos)) {
        pop_used_position(&(node->desc), pos);
        push_free_position(&(node->desc), pos);
    }
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
    return add_publisher(&(node->pubs_coll), pub);
}

int find_publisher_in_node(struct ps_node *node, pid_t pid, struct ps_publisher **result) {
    if (!node || pid < 0 || !result)
        return -EINVAL;
    int err = 0;
    //down_read(node->pubs_rwsem);
    err = find_publisher(&(node->pubs_coll), pid, result);
    //up_read(node->pubs_rwsem);
    return err;
}

int remove_publisher_in_node(struct ps_node *node, struct ps_publisher *pub) {
    if (!node || !pub)
        return -EINVAL;
    return remove_publisher(&(node->pubs_coll), pub);
}

int add_node(struct ps_node *node) {
    if (!node)
        return -EINVAL;
	hash_add(nodes, &(node->hlist), node->id);
    return 0;
}

int remove_node(struct ps_node *node) {
    if (!node)
        return -EINVAL;
	hash_del(&(node->hlist));
    return 0;
}

/*
 * Заменить pop
 */

int receive_message_from_node(struct ps_node *node, struct ps_subscriber *sub, void __user *info) {
    if (!node || !info)
        return -EINVAL;
    struct ps_position *pos = NULL, *next_pos = NULL, *new_pos = NULL;
    int msg_num = 0, err = get_subscriber_position(sub, &pos);
    if (err)
        return err;
    msg_num = get_position_num(pos);
    err = read_from_buffer(&(node->buf), msg_num, info);
    if (!err) {
        disconnect_subscriber_position(sub);
        //TODO: начало защиты
        if (is_position_not_used(pos)) {
            //Тут либо спинлок, либо какие-то атомарные приколы
            pop_used_position(&(node->desc), pos);
            //TODO: Конец защиты
            //TODO: В свободных листах можно использовать RCU
            push_free_position(&(node->desc), pos);
            spin_lock(&(node->buf_lock));
            if (get_buffer_begin_num(node->buf) == msg_num)
                delete_first_message(node->buf);
            spin_unlock(&(node->buf_lock));
        }
        //TODO: Конец защиты
        //TODO: А у нас другие потоки могли удалить уже сообщение под этим номером
        msg_num++;
        err = find_msg_num_position(&(node->desc), msg_num, &new_pos);
        if (!err) {
            connect_subscriber_position(sub, new_pos);
        } else if (err == -ENOENT) {
            //TODO: Надо спинлоки или RCU использовать
            err = find_next_position(&(node->desc), pos, &next_pos);
            if (!err) {
                err = find_free_position(&(node->desc), &new_pos);
                if (!err) {
                    pop_free_position(&(node->desc), new_pos);
                    set_position_num(new_pos, msg_num);
                    connect_subscriber_position(sub, new_pos);
                    push_used_position_before(&(node->desc), new_pos, next_pos);
                }
            } else if (err = -ENOENT) {
                //TODO: Если позиций вообще нет в списке
                err = find_free_position(&(node->desc), &new_pos);
                if (!err) {
                    pop_free_position(&(node->desc), new_pos);
                    set_position_num(new_pos, msg_num);
                    connect_subscriber_position(sub, new_pos);
                    push_used_position_last(&(node->desc), new_pos);//TODO: Она просто должна добавлять позицию в список и в таблицу
                }
            }
        }
    }
    return err;
}

int send_message_to_node(struct ps_node *node, void __user *info) {
	if (!node || !info)
		return -EINVAL;
	int msg_num = 0, err = 0;
    struct ps_position *pos = NULL, *next_pos = NULL;
	//TODO: Эти функции сделай без защиты от ошибок
    //TODO: При одновременном обращении буфера нужно использовать rwsem
    //TODO: Эту функцию сделали через subposition
	if (is_buffer_full(&(node->buf))) {
		if (!is_buffer_blocking(&(node->buf))) {
            spin_lock(&(node->buf_lock));
            get_buffer_begin_num(&(node->buf), &msg_num);
            delete_first_message(&(node->buf));
            spin_unlock(&(node->buf_lock));
            //TODO: Защита
            err = find_msg_num_position(&(node->desc), msg_num, &pos);
            if (!err) {
                err = find_next_position(&node->desc), pos, next_pos);
                if (!err) {
                    pop_used_position(&(node->desc), pos);
                    msg_num++;
                    set_position_num(pos, msg_num);
                    if (get_position_num(next_pos) == get_position_num(pos))
                        push_used_subposition(&(node->desc), next_pos, pos);
                    else
                        push_used_position_before(&(node->desc), pos, next_pos);
                } else {
                    pop_used_position(&(node->desc), pos);
                    msg_num++;
                    set_position_num(pos, msg_num);
                    push_used_position_last(&(node->desc), pos);
                }
            }
			err = write_to_buffer(&(node->buf), info);
		}
	} else {
        err = write_to_buffer(&(node->buf), info);
	}
	return err;
}
