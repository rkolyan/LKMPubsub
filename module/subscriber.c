//
// Created by rkolyan on 07.01.2025.
//

#include "subscriber.h"

#include <linux/vmalloc.h>

int create_subscriber_struct(pid_t pid, struct ps_subscriber **result) {
	if (!result)
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
	    break;
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
    //Оказывается RCU нельзя одновременно использовать с мьютексами, rwlock и rw_semaphore, из-за влияния на счетчик вытеснения
    //synchronize_rcu();
    return 0;
}

struct ps_position *get_subscriber_position(struct ps_subscriber *sub) {
    return sub->pos;
}

int connect_subscriber_position(struct ps_subscriber *sub, struct ps_position *pos) {
    trace_printk("BEGIN sub = %p, pos = %p\n", sub, pos);
    if (!sub || !pos)
        return -EINVAL;
    //TODO: Защита позиций!
    //trace_printk("BEFORE pos->cnt = %u\n", atomic_read(&pos->cnt));
    down_position(pos);
    //trace_printk("END pos->cnt = %u\n", atomic_read(&pos->cnt));
    sub->pos = pos;
    return 0;
}

int disconnect_subscriber_position(struct ps_subscriber *sub, struct ps_position *pos) {
    trace_printk("BEGIN sub = %p, pos = %p\n", sub, sub->pos);
    if (!sub)
        return -EINVAL;
    trace_printk("BEFORE pos->cnt = %u\n", atomic_read(&sub->pos->cnt));
    up_position(sub->pos);
    trace_printk("END pos->cnt = %u\n", atomic_read(&sub->pos->cnt));
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
