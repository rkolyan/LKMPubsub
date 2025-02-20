#ifndef PS_BUFFER_H
#define PS_BUFFER_H

#include <linux/uaccess.h>

#define PS_POSITIONS_DEFAULT_COUNT 4

struct ps_position {
    atomic_t cnt; //Количество текущих подписчиков на структуру
    void *addr;
    struct list_head list; //Список очередности элементов
};


struct ps_buffer {
	struct list_head positions_used;
	struct list_head positions_free;
	struct list_head prohibited;
	struct ps_position *stop_pos;
	void *base_begin;
	void *base_end;//Границы буфера в адресе (base_end - включительно)
	void *begin;
	void *end;
	void *end_read;
	atomic_t overflow;
	size_t blk_size;
	size_t buf_size;
};

struct ps_prohibition {
	void *addr;
	struct list_head list;
};

void push_free_position(struct ps_buffer *buf, struct ps_position *pos);
void pop_free_position(struct ps_buffer *buf, struct ps_position *pos);
void push_used_position_after(struct ps_buffer *buf, struct ps_position *new_pos, struct ps_position *pos);
void push_used_position_begin(struct ps_buffer *buf, struct ps_position *pos);
void pop_used_position(struct ps_buffer *buf, struct ps_position *pos);

struct ps_position *find_free_position(struct ps_buffer *buf);
struct ps_position *find_next_position(struct ps_buffer *buf, struct ps_position *pos);//Ищет следующую позицию из списка (она нужна, если )
struct ps_position *find_first_position(struct ps_buffer *buf);

struct ps_position *create_position_struct(void);
void delete_position_struct(struct ps_position *pos);

int is_position_used(const struct ps_buffer *buf, const struct ps_position *pos);
int is_position_incorrect(const struct ps_buffer *buf, const struct ps_position *pos);

void up_position(struct ps_position *pos);
void down_position(struct ps_position *pos);

int init_buffer(struct ps_buffer *buf, size_t buf_size, size_t blk_size);
int deinit_buffer(struct ps_buffer *buf);

#ifndef PS_TEST
int write_to_buffer_end(struct ps_buffer *buf, struct ps_prohibition *proh, void __user *info);
int read_from_buffer_at_position(struct ps_buffer *buf, struct ps_position *pos, void __user *info);
#else
int write_to_buffer_end(struct ps_buffer *buf, struct ps_prohibition *proh, void *info);
int read_from_buffer_at_position(struct ps_buffer *buf, struct ps_position *pos, void *info);
#endif

void prohibition_init(struct ps_prohibition *proh);
int try_prohibit_buffer_end(struct ps_buffer *buf, struct ps_prohibition *proh);
void unprohibit_buffer(struct ps_buffer *buf, struct ps_prohibition *proh);

#endif
