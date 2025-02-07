#include "position.h"

#include <linux/rculist.h>
#include <linux/vmalloc.h>

//TODO: Наверное, всё равно на RCU, на верхнем уровне ставятся спин-локи

int init_positions_desc(struct ps_positions_desc *desc) {
    if (!desc)
        return -EINVAL;
    INIT_LIST_HEAD(&(desc->free));
    INIT_LIST_HEAD(&(desc->used));
    hash_init(desc->table);
    return 0;
}

int deinit_positions_desc(struct ps_positions_desc *desc) {
    if (!desc)
        return -EINVAL;
    struct list_head *pos = NULL, *tmp = NULL;
    list_for_each_safe(pos, tmp, &(desc->used)) {
        vfree(list_entry(pos, struct ps_position, list));
    }
    list_for_each_safe(pos, tmp, &(desc->free)) {
        vfree(list_entry(pos, struct ps_position, list));
    }
    return 0;
}

int create_position_struct(struct ps_position **result) {
    if (!result)
        return -EINVAL;
    struct ps_position *pos = vzalloc(sizeof(struct ps_position));
    INIT_LIST_HEAD(&(pos->list));
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
}
int get_position_num(struct ps_position *pos) {
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
    list_add_tail(&(pos->list), &(desc->free));
    //Вроде place не нужен
    return 0;
}

int pop_free_position(struct ps_positions_desc *desc, struct ps_position *pos) {
    if (!desc || !pos)
        return -EINVAL;
    list_del(&(pos->list));
    return 0;
}

int push_used_position_last(struct ps_positions_desc *desc, struct ps_position *pos) {
    if (!desc || !pos)
        return -EINVAL;
    hash_add(desc->table, &(pos->place), pos->msg_num);
    list_add_tail(&(pos->list), &(desc->used));
    return 0;
}

int push_used_position_before(struct ps_positions_desc *desc, struct ps_position *pos, struct ps_position *next_pos) {
    if (!desc || !pos)
        return -EINVAL;
    list_add_tail(&(pos->list), &(next_pos->list));
    hash_add(desc->table, &(pos->place), pos->msg_num);
    return 0;
}

int pop_used_position(struct ps_positions_desc *desc, struct ps_position *pos) {
    if (!desc || !pos)
        return -EINVAL;
    hash_del(&(pos->place));
    list_del(&(pos->list));
    return 0;
}

int find_free_position(struct ps_positions_desc *desc, struct ps_position **result) {
    if (!desc || !result)
        return -EINVAL;
    if (list_empty(&(desc->free)))
        return -ENOENT;
    *result = list_first_entry(&(desc->free), struct ps_position, list);
    return 0;
}

int find_msg_num_position(struct ps_positions_desc *desc, int msg_num, struct ps_position **result) {
    if (!desc || !result)
        return -EINVAL;
    struct ps_position *pos = NULL;
    char flag = 0;

    hash_for_each_possible(desc->table, pos, place, msg_num) {
        if (pos->msg_num == msg_num) {
            *result = pos;
            flag = 1;
            break;
        }
    }

    if (!flag)
        return -ENOENT;
    return 0;
}

int find_next_position(struct ps_positions_desc *desc, struct ps_position *pos, struct ps_position **result) {
    if (!desc || !pos || !result)
        return -EINVAL;
    struct list_head *cur = NULL;
    struct ps_position *cur_pos = NULL;
    list_for_each(cur, &(pos->list)) {
        if (cur == &(desc->used))
            return -ENOENT;
        cur_pos = list_entry(cur, struct ps_position, list);
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
    if (list_empty(&(desc->used)))
        return -ENOENT;
    *result = list_first_entry(&(desc->used), struct ps_position, list);
    return 0;
}
