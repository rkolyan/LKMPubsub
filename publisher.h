//
// Created by rkolyan on 07.01.2025.
//

#ifndef MOD2_PUBLISHER_H
#define MOD2_PUBLISHER_H

#include <linux/hashtable.h>
#include <linux/types.h>

#define PUBLISHER_HASHTABLE_BITS 3

struct ps_publishers_collection {
    DECLARE_HASHTABLE(pubs, PUBLISHER_HASHTABLE_BITS);
};

struct ps_publisher {
    pid_t pid;
    struct hlist_node hlist;
};

void init_publisher_collection(struct ps_publishers_collection *coll);
int clear_publisher_collection(struct ps_publishers_collection *coll);

int create_publisher_struct(pid_t pid, struct ps_publisher **result);
int delete_publisher_struct(struct ps_publisher *result);

int find_publisher(struct ps_publishers_collection *coll, pid_t pid, struct ps_publisher **result);

int add_publisher(struct ps_publishers_collection *coll, struct ps_publisher *pub);
int remove_publisher(struct ps_publishers_collection *coll, struct ps_publisher *pub);

#endif //MOD2_PUBLISHER_H
