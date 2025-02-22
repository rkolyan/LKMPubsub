//
// Created by rkolyan on 07.01.2025.
//

#ifndef MOD2_SUBSCRIBER_H
#define MOD2_SUBSCRIBER_H

#include "buffer.h"

#include <linux/hashtable.h>

#define SUBSCRIBER_HASHTABLE_BITS 3

struct ps_subscribers_collection {
    DECLARE_HASHTABLE(subs, SUBSCRIBER_HASHTABLE_BITS);
};

struct ps_subscriber {
    pid_t pid;
    struct hlist_node hlist;
    struct ps_position *pos;
};


int init_subscriber_collection(struct ps_subscribers_collection *coll);
int clear_subscriber_collection(struct ps_subscribers_collection *coll);

int create_subscriber_struct(pid_t pid, struct ps_subscriber **result);
int delete_subscriber_struct(struct ps_subscriber *result);

int find_subscriber(struct ps_subscribers_collection *coll, pid_t pid, struct ps_subscriber **result);
struct ps_position *get_subscriber_position(struct ps_subscriber *sub);

int add_subscriber(struct ps_subscribers_collection *coll, struct ps_subscriber *sub);
int remove_subscriber(struct ps_subscribers_collection *coll, struct ps_subscriber *sub);

int connect_subscriber_position(struct ps_subscriber *sub, struct ps_position *pos);
int disconnect_subscriber_position(struct ps_subscriber *sub, struct ps_position *pos);

#endif //MOD2_SUBSCRIBER_H
