//
// Created by rkolyan on 07.01.2025.
//

#include "subscriber.h"

#include <linux/vmalloc.h>

int create_subscriber_struct(pid_t pid, struct ps_subscriber **result) {
    if (pid < 0 || !result)
        return -EINVAL;
    struct ps_subscriber *sub = vzalloc(sizeof(struct ps_subscriber));
    if (!sub)
        return -ENOMEM;
    sub->pid = pid;
    INIT_HLIST_NODE(&(sub->hlist));
    sub->pos = NULL;
    *result = sub;
    return 0;
}

int delete_subscriber_struct(struct ps_subscriber *sub) {
    if (!sub)
        return -EINVAL;
    vfree(sub);
    return 0;
}

int find_subscriber(struct ps_subscribers_collection *coll, pid_t pid, struct ps_subscriber **result) {
    if (pid < 0 || !coll || !result)
        return -EINVAL;
    struct ps_subscriber *sub = NULL;
    char flag = 0;
    rcu_read_lock();
    int err = 0;
    hash_for_each_possible_rcu(coll->subs, sub, hlist, pid) {
        if (sub->pid == pid) {
            *result = sub;
            flag = 1;
            err = 0;
        }
    }
    if (flag) {
        *result = sub;
    } else {
        err = -ENOENT;
    }
    rcu_read_unlock();
    return err;
}

int add_subscriber(struct ps_subscribers_collection *coll, struct ps_subscriber *sub) {
    if (!coll || !sub)
        return -EINVAL;
    hash_add_rcu(coll->subs, &(sub->hlist), sub->pid);
    return 0;
}

int remove_subscriber(struct ps_subscribers_collection *coll, struct ps_subscriber *sub) {
    if (!coll || !sub)
        return -EINVAL;
    hash_del_rcu(&(sub->hlist));
    return 0;
}

int get_subscriber_position(struct ps_subscriber *sub, struct ps_position **result) {
    if (!sub || !result)
        return -EINVAL;
    *result = sub->pos;
    return 0;
}

int connect_subscriber_position(struct ps_subscriber *sub, struct ps_position *pos) {
    if (!sub || !pos)
        return -EINVAL;
    //TODO: Защита позиций!
    sub->pos = pos;
    down_position(pos);
    return 0;
}

int disconnect_subscriber_position(struct ps_subscriber *sub) {
    if (!sub)
        return -EINVAL;
    up_position(sub->pos);
    sub->pos = NULL;
    return 0;
}

int init_subscriber_collection(struct ps_subscribers_collection *coll) {
    if (!coll)
        return -EINVAL;
    hash_init(coll->subs);
    return 0;
}

int clear_subscriber_collection(struct ps_subscribers_collection *coll) {
    if (!coll)
        return -EINVAL;
    int bkt = 0;
    struct hlist_node *tmp = NULL;
    struct ps_subscriber *sub = NULL;
    hash_for_each_safe(coll->subs, bkt, tmp, sub, hlist) {
        hash_del(&(sub->hlist));
        delete_subscriber_struct(sub);
    }
    return 0;
}