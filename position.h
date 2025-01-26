//
// Created by rkolyan on 09.01.2025.
//

#ifndef MOD2_POSITION_H
#define MOD2_POSITION_H

#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/spinlock_types.h>

#define POSITION_TABLE_BITS 3

struct ps_positions_desc {
    struct list_head *free;
    spinlock_t lock; //Нужен, для перемещений позиций в пустой список или непустой
    struct list_head *used;
    DECLARE_HASHTABLE(table, POSITION_TABLE_BITS);
};

struct ps_position {
    int cnt; //Количество текущих подписчиков на структуру
    int msg_num; //Номер текущего сообщения, используется, если hsame указывает на NULL
    struct hlist_node place; //Это для хранения в специальной хеш-таблицы, чтобы при удалении сообщения, сразу найти нотификатор
    struct list_head list; //Показывает все элементы
    struct list_head main_list; //Список очередности элементов
};


int init_positions_desc(struct ps_positions_desc *desc);
int deinit_positions_desc(struct ps_positions_desc *desc);

int push_free_position(struct ps_positions_desc *desc, struct ps_position *pos);
int push_used_position_before(struct ps_positions_desc *desc, struct ps_position *pos, struct ps_position *next_pos);
int push_used_position_last(struct ps_positions_desc *desc, struct ps_position *pos);
int push_used_subposition(struct ps_positions_desc *desc, struct ps_position *pos, struct ps_position *sub_pos);

int pop_free_position(struct ps_positions_desc *desc, struct ps_position *pos);
int pop_used_position(struct ps_positions_desc *desc, struct ps_position *pos);

int find_free_position(struct ps_positions_desc *desc, struct ps_position **result);
int find_msg_num_position(struct ps_positions_desc *desc, int msg_num, struct ps_position **result);//Ищет в хеш-таблице нужную позицию
int find_next_position(struct ps_positions_desc *desc, struct ps_position *pos, struct ps_position **result);//Ищет следующую позицию из списка (она нужна, если )
int find_first_position(struct ps_positions_desc *desc, struct ps_position **result);

int set_position_num(struct ps_position *pos, int msg_num);
int get_position_num(struct ps_position *pos);

int is_position_not_used(struct ps_position *pos);

int up_position(struct ps_position *pos);
int down_position(struct ps_position *pos);

int create_position_struct(struct ps_position **pos);
int delete_position_struct(struct ps_position *pos);

#endif //MOD2_POSITION_H
