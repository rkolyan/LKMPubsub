#ifndef PS_NODE_H
#define PS_NODE_H

#include "buffer.h"
#include "subscriber.h"
#include "publisher.h"

//TODO: Можно перенести в файл, так как используется только указатель
struct ps_node {
	unsigned long id;
	struct ps_buffer buf;
	struct ps_positions_desc desc;
	spinlock_t subs_lock;
	spinlock_t pubs_lock;
	spinlock_t pos_lock;
	struct ps_subscribers_collection subs_coll;
	struct ps_publishers_collection pubs_coll;
	struct hlist_node hlist;//Элемент из хеш-таблицы
	atomic_t delete_flag;
	atomic_t use_count;
};


int init_nodes(void);
int deinit_nodes(void);

#ifndef PS_TEST
int get_node_id(struct ps_node *node, unsigned long __user *result);
#else
int get_node_id(struct ps_node *node, unsigned long *result);
#endif

int create_node_struct(size_t buf_size, size_t block_size, struct ps_node **result);
//TODO: ДОДЕЛАТЬ
int delete_node_struct(struct ps_node *node);
int delete_node_struct_if_unused(struct ps_node *node);

int acquire_node(unsigned long id, struct ps_node **result);//Вместо find_node
int release_node(struct ps_node *node);

void mark_node_unused(struct ps_node *node);

int add_node(struct ps_node *node);
int remove_node(struct ps_node *node);

int add_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub);
int find_subscriber_in_node(struct ps_node *node, pid_t pid, struct ps_subscriber **result);
int remove_subscriber_in_node(struct ps_node *node, struct ps_subscriber *sub);

int add_position_in_node(struct ps_node *node, struct ps_position *pos);
int remove_position_in_node(struct ps_node *node, struct ps_position **result);

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
