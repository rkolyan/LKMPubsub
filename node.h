#ifndef PS_NODE_H
#define PS_NODE_H

#include "buffer.h"
#include "subscriber.h"
#include "publisher.h"

/*
 * struct ps_buffer {
 * 	void *base;
 * 	int begin_num, end_num;
 * 	void *begin, *end;
 * 	size_t block_size;
 * 	size_t buf_size;
 * }
 *
 */

/*
#define TABLE_BITS 3

struct ps_positions_desc {
	struct list_head free;
	struct list_head used;
	DECLARE_HASHTABLE(table, TABLE_BITS);
};

struct ps_position {
	int cnt; //Количество текущих подписчиков на структуру
	int msg_num; //Номер текущего сообщения, используется, если hsame указывает на NULL
	struct hlist_head hsame; //Указатель на схожую структуру позиции (которая указывает на тот же номер сообщения)
	struct hlist_head place; //Это для хранения в специальной хеш-таблицы, чтобы при удалении сообщения, сразу найти нотификатор
	struct list_head list; //Указатель на следующий и предыдущий элементы списка нотификаторов
};
 */

struct ps_node;

int init_nodes(void);
int deinit_nodes(void);

void ps_nodes_init_lock(void);
void ps_nodes_read_lock(void);
void ps_nodes_read_unlock(void);
void ps_nodes_write_lock(void);
void ps_nodes_write_unlock(void);

void ps_current_read_lock(struct ps_node *node);
void ps_current_read_unlock(struct ps_node *node);
void ps_current_write_wait(struct ps_node *node);

int get_node_id(struct ps_node *node, unsigned long __user *result);

int create_node_struct(size_t buf_size, size_t block_size, unsigned int flag, struct ps_node **result);
//TODO: ДОДЕЛАТЬ
int delete_node_struct(struct ps_node *node);

int find_node(unsigned long id, struct ps_node **result);
int add_node(struct ps_node *node);
int remove_node(struct ps_node *node);

int add_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub);
int find_subscriber_in_node(struct ps_node *node, pid_t pid, struct ps_subscriber **result);
int remove_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub);

int add_position_in_node(struct ps_node *node, struct ps_position *pos);
int remove_position_in_node(struct ps_node *node);

int add_publisher_in_node(struct ps_node *node, struct ps_publisher *pub);
int find_publisher_in_node(struct ps_node *node, pid_t pid, struct ps_publisher **result);
int remove_publisher_in_node(struct ps_node *node, struct ps_publisher *pub);

int send_message_to_node(struct ps_node *node, void __user *buf);
int receive_message_from_node(struct ps_node *node, struct ps_subscriber *sub, void __user *buf);

#endif