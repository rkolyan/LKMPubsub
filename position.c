#include "position.h"

#include <linux/rculist.h>
#include <linux/vmalloc.h>

//TODO: РЕШИ ПРОБЛЕМЫ С ЗАЩИТОЙ (RCU ЗДЕСЬ НАДО ОСТОРОЖНО ИЛИ БЕЗ НЕГО)

int init_positions_desc(struct ps_positions_desc *desc) {
    if (!desc)
        return -EINVAL;
    INIT_LIST_HEAD(desc->free);
    INIT_LIST_HEAD(desc->used);
    hash_init(desc->table);
    return 0;
}

int deinit_positions_desc(struct ps_positions_desc *desc) {
    if (!desc)
        return -EINVAL;
    struct list_head *pos = NULL, *tmp = NULL;
    list_for_each_safe(pos, tmp, desc->used) {
        vfree(list_entry(pos, struct ps_position, list));
    }
    list_for_each_safe(pos, tmp, desc->free) {
        vfree(list_entry(pos, struct ps_position, list));
    }
    return 0;
}

int create_position_struct(struct ps_position **result) {
    if (!result)
        return -EINVAL;
    struct ps_position *pos = vzalloc(sizeof(struct ps_position));
    INIT_LIST_HEAD(&(pos->list));
    INIT_LIST_HEAD(&(pos->main_list));
    INIT_HLIST_NODE(&(pos->place));
    //pos->cnt = 0;
    //pos->msg_num = 0;
    return 0;
}

int delete_position_struct(struct ps_position *pos) {
    if (!pos)
        return -EINVAL;
    vfree(pos);
    return 0;
}

void set_position_num(struct ps_position *pos, int msg_num) {
    pos->msg_num = msg_num;
    return 0;
}
int get_position_num(struct ps_position *pos, int *msg_num) {
    return pos->msg_num;
}

int is_position_not_used(struct ps_position *pos) {
    if (pos->cnt == 0)
        return 1;
    return 0;
}

int up_position(struct ps_position *pos) {
    if (!pos)
        return -EINVAL;
    pos->cnt--;
    return 0;
}

int down_position(struct ps_position *pos) {
    if (!pos)
        return -EINVAL;
    pos->cnt++;
    return 0;
}

int push_free_position(struct ps_positions_desc *desc, struct ps_position *pos) {
    if (!desc || !pos)
        return -EINVAL;
    //Вроде hsame указывает на NULL
    spin_lock(&(desc->lock));
    list_add_tail(&(pos->main_list), desc->free);
    spin_unlock(&(desc->lock));
    //Вроде place не нужен
    return 0;
}

int pop_free_position(struct ps_positions_desc *desc, struct ps_position *pos) {
    if (!desc || !pos)
        return -EINVAL;
    spin_lock(&(desc->lock));
    list_del(&(pos->main_list));
    spin_unlock(&(desc->lock));
    return 0;
}

int push_used_position_last(struct ps_positions_desc *desc, struct ps_position *pos) {
    if (!desc || !pos || !next_pos)
        return -EINVAL;
    spin_lock(&(desc->lock));
    struct ps_position *pos = NULL;
    hash_add_rcu(desc->table, &(pos->place), pos->msg_num);
    list_add_tail(&(pos->main_list), &(desc->used));
    INIT_LIST_HEAD(&(pos->list));
    spin_unlock(&(desc->lock));
    return 0;
}

int push_used_position_before(struct ps_positions_desc *desc, struct ps_position *pos, struct ps_position *next_pos) {
    if (!desc || !pos)
        return -EINVAL;
    spin_lock(&(desc->lock));
    list_add_tail(&(pos->main_list), &(next_pos->main_list));
    hash_add_rcu(desc->table, &(pos->place), pos->msg_num);
    INIT_LIST_HEAD(&(pos->list));
    spin_unlock(&(desc->lock));
    return 0;
}

int push_used_subposition(struct ps_positions_desc *desc, struct ps_position *pos, struct ps_position *sub_pos); {
    if (!desc || !pos || !sub_pos)
        return -EINVAL;
    spin_lock(&(desc->lock));
    list_add_rcu(&(sub_pos->list), &(pos->list));
    list_add_rcu(&(sub_pos->main_list), &(pos->main_list));
    spin_unlock(&(desc->lock));
    return 0;
}

int pop_used_position(struct ps_positions_desc *desc, struct ps_position *pos) {
    if (!desc || !pos)
        return -EINVAL;
    spin_lock(&(desc->lock));
    if (hlist_unhashed(pos->place)) {
        list_del_rcu(&(pos->list));
    } else {
        if (!list_empty_rcu(&(pos->list))) {
            struct ps_position *pos2 = list_entry(list_next_rcu(&(pos->list)), struct ps_position, list);
            list_del_rcu(&pos->list);
            hlist_replace_rcu(&(pos->place), &(pos2->place));
        } else {
            hash_del_rcu(&(pos->place));
        }
    }
    list_del_rcu(&(pos->main_list));
    spin_unlock(&(desc->lock));
    return 0;
}

int find_free_position(struct ps_positions_desc *desc, struct ps_position **result) {
    if (!desc || !result)
        return -EINVAL;
    if (list_empty(desc->free))
        return -ENOENT;
    struct list_head *list = NULL;
    rcu_read_lock();
    *result = list_entry(list_next_rcu(desc->free), struct ps_position, main_list);
    rcu_read_unlock();
    return 0;
}

int find_msg_num_position(struct ps_positions_desc *desc, int msg_num, struct ps_position **result) {
    if (!desc || !result)
        return -EINVAL;
    struct ps_position *pos = NULL;
    char flag = 0;

    rcu_read_lock();
    hash_for_each_possible_rcu(desc->table, pos, place, msg_num) {
        if (pos->msg_num == msg_num) {
            *result = pos;
            flag = 1;
            break;
        }
    }
    rcu_read_lock();

    if (!flag)
        return -ENOENT;
    return 0;
}

int find_next_position(struct ps_positions_desc *desc, struct ps_position *pos, struct ps_position **result); {
    if (!desc || !pos || !result)
        return -EINVAL;
    struct list_head *cur = NULL;
    struct ps_position *cur_pos = NULL;
    list_for_each_rcu(cur, pos->main_list) {
        if (cur == &(desc->used))
            return -ENOENT;
        cur_pos = list_entry(cur, struct ps_position, main_list);
        if (cur_pos->msg_num > pos->msg_num) {
            *result = cur_pos;
            return 0;
        }
    }
    return -ENOENT;//По идее сюда поток дойти не должен
}

int find_first_position(struct ps_positions_desc *desc, struct ps_position **result) {
    if (!desc || !result)
        return -EINVAL;
    if (list_empty(desc->used))
        return -ENOENT;
    *result = list_entry(list_next_rcu(&(desc->used)), struct ps_position, main_list);
    return 0;
}