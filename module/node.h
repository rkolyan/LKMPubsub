#ifndef PS_NODE_H
#define PS_NODE_H

#include "buffer.h"
#include "subscriber.h"
#include "publisher.h"

//TODO: Можно перенести в файл, так как используется только указатель
struct ps_node {
	unsigned long id;
	struct ps_buffer buf;
    spinlock_t pos_lock;
	struct ps_positions_desc desc;
	struct rw_semaphore node_rwsem;//Для защиты от удаления
	spinlock_t subs_lock;
    spinlock_t pubs_lock;
    struct ps_subscribers_collection subs_coll;
    struct ps_publishers_collection pubs_coll;
	struct hlist_node hlist;//Элемент из хеш-таблицы
};


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

#ifndef PS_TEST
int get_node_id(struct ps_node *node, unsigned long __user *result);
#else
int get_node_id(struct ps_node *node, unsigned long *result);
#endif

int create_node_struct(size_t buf_size, size_t block_size, struct ps_node **result);
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

#ifndef PS_TEST
int send_message_to_node(struct ps_node *node, struct ps_publisher *pub, void __user *buf);
int receive_message_from_node(struct ps_node *node, struct ps_subscriber *sub, void __user *buf);
#else
int send_message_to_node(struct ps_node *node, struct ps_publisher *pub, void *buf);
int receive_message_from_node(struct ps_node *node, struct ps_subscriber *sub, void *buf);
#endif

#endif
