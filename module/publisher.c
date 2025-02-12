//
// Created by rkolyan on 07.01.2025.
//

#include "publisher.h"

#include <linux/vmalloc.h>

int create_publisher_struct(pid_t pid, struct ps_publisher **result) {
    if (pid < 0 || !result)
        return -EINVAL;
    struct ps_publisher *pub = vzalloc(sizeof(struct ps_publisher));
    if (!pub)
        return -ENOMEM;
    INIT_HLIST_NODE(&(pub->hlist));
    pub->pid = pid;
    *result = pub;
    return 0;
}

int delete_publisher_struct(struct ps_publisher *result) {
    if (!result)
        return -EINVAL;
    vfree(result);
    return 0;
}

int find_publisher(struct ps_publishers_collection *coll, pid_t pid, struct ps_publisher **result) {
    if (pid < 0 || !coll || !result)
        return -EINVAL;
    struct ps_publisher *pub = NULL;
    char flag = 0;
    int err = 0;
    rcu_read_lock();
    hash_for_each_possible_rcu(coll->pubs, pub, hlist, pid) {
        if (pub->pid == pid) {
            flag = 1;
            err = 0;
	    break;
        }
    }
    if (flag) {
        *result = pub;
    } else {
        err = -ENOENT;
    }
    rcu_read_unlock();
    return err;
}

int add_publisher(struct ps_publishers_collection *coll, struct ps_publisher *pub) {
    if (!coll || !pub)
        return -EINVAL;
    hash_add_rcu(coll->pubs, &(pub->hlist), pub->pid);
    //TODO: Причиной крахов внезапно является synchronize_rcu
    //synchronize_rcu();
    return 0;
}

int remove_publisher(struct ps_publishers_collection *coll, struct ps_publisher *pub) {
    if (!coll || !pub)
        return -EINVAL;
    hash_del_rcu(&(pub->hlist));
    //TODO: Причиной крахов внезапно является synchronize_rcu, скорее всего
    //synchronize_rcu();
    return 0;
}

//Вызываются только одним потоком, поэтому hash-функции
void init_publisher_collection(struct ps_publishers_collection *coll) {
    hash_init(coll->pubs);
}

int clear_publisher_collection(struct ps_publishers_collection *coll) {
    if (!coll)
        return -EINVAL;
    int bkt = 0;
    struct hlist_node *tmp = NULL;
    struct ps_publisher *pub = NULL;
    hash_for_each_safe(coll->pubs, bkt, tmp, pub, hlist) {
        hash_del(&(pub->hlist));
        delete_publisher_struct(pub);
    }
    return 0;
}

inline struct ps_prohibition *get_publisher_prohibition(struct ps_publisher *pub) {
    return &(pub->proh);
}
