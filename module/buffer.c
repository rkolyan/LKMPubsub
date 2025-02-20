#include <linux/vmalloc.h>
#include <linux/rculist.h>

#ifndef PS_TEST
#include <linux/uaccess.h>
#else
#include <linux/fortify-string.h>
#endif

#include "buffer.h"

//end_num - индекс, указывающий на ячейку, в которую будет записано новое сообщение
int init_buffer(struct ps_buffer *buf, size_t buf_size, size_t blk_size) {
	if (!buf || !buf_size || !blk_size)
		return -EINVAL;
	size_t final_size = buf_size * blk_size;
	buf->base_begin = vzalloc(final_size);
	if (!buf->base_begin)
		return -ENOMEM;
	INIT_LIST_HEAD(&buf->prohibited);
	INIT_LIST_HEAD(&buf->positions_free);
	struct ps_position *pos = create_position_struct();
	if (!pos) {
		vfree(buf->base_begin);
		return -ENOMEM;
	}
	list_add(&pos->list, &buf->positions_free);
	INIT_LIST_HEAD(&buf->positions_used);//Он пока пустой
	atomic_set(&buf->overflow, 0);
	buf->stop_pos = NULL;
	buf->base_end = &((char *)buf->base_begin)[final_size];
	buf->begin = buf->base_begin;
	buf->end = buf->base_begin;
	buf->end_read = buf->base_begin;
	buf->buf_size = buf_size;
	buf->blk_size = blk_size;
	return 0;
}

int deinit_buffer(struct ps_buffer *buf) {
	if (!buf)
		return -EINVAL;
	struct list_head *cur = NULL, *tmp = NULL;
	list_for_each_safe(cur, tmp, &buf->positions_used) {
		vfree(list_entry(cur, struct ps_position, list));
	}
	list_for_each_safe(cur, tmp, &buf->positions_free) {
		vfree(list_entry(cur, struct ps_position, list));
	}
	list_for_each_safe(cur, tmp, &buf->prohibited) {
		vfree(list_entry(cur, struct ps_prohibition, list));
	}
	vfree(buf->base_begin);
	return 0;
}

int is_position_incorrect(const struct ps_buffer *buf, const struct ps_position *pos) {
	//TODO: Удали !pos
	//if (!pos)
	//	return 3;
	if (pos->addr < buf->base_begin || pos->addr >= buf->base_end)
		return 2;
	if (buf->begin < buf->end_read) {
		if (pos->addr >= buf->begin && pos->addr < buf->end_read)
			return 0;
	} else if (buf->begin > buf->end_read) {
		if (pos->addr < buf->end_read || pos->addr >= buf->begin)
			return 0;
	} else {
		if (pos->addr == buf->begin && pos != buf->stop_pos)
			return 0;
	}
	return 1;
}

int is_position_used(const struct ps_buffer *buf, const struct ps_position *pos) {
	return atomic_read(&pos->cnt);
}

int is_prohibit_success(const struct ps_buffer *buf) {
	return !atomic_read(&buf->overflow);
}

inline void prohibition_init(struct ps_prohibition *proh) {
	INIT_LIST_HEAD(&proh->list);
}

//Какие могут быть случаи?
//Век

int try_prohibit_buffer_end(struct ps_buffer *buf, struct ps_prohibition *proh) {
	bool flag = false;
	if (buf->begin != buf->end) {
		flag = true;
	} else {
		//TODO: Переделать
		struct ps_prohibition *first_proh = list_first_entry_or_null(&(buf->prohibited), struct ps_prohibition, list);
		if (first_proh && first_proh->addr == buf->end) {
			flag = false;
		} else {
			struct ps_position *pos = find_first_position(buf);
			//Если позиции нет, писать можно
			//Если позиция есть, но она stop_pos, писать можно
			//Если позиция есть, но её адрес не совпадает с end, то писать можно
			//Иначе нельзя
			//TODO: Здесь если !pos должен
			if (!pos || pos == buf->stop_pos || pos->addr != buf->end) {
				flag = true;
			} else {
				flag = false;
			}
		}
	}
	if (!flag)
		return 0;
	proh->addr = buf->end;
	buf->end += buf->blk_size;
	if (buf->end == buf->base_end)
		buf->end = buf->base_begin;
	list_add_tail_rcu(&(proh->list), &(buf->prohibited));
	return 1;
}

void unprohibit_buffer(struct ps_buffer *buf, struct ps_prohibition *proh) {
	if (proh == list_first_entry_or_null(&(buf->prohibited), struct ps_prohibition, list)) {
		void *proh_addr = proh->addr + buf->blk_size;
		if (proh_addr != buf->base_end) {
			buf->end_read = proh_addr;
		} else {
			buf->end_read = buf->base_begin;
		}
		buf->stop_pos = NULL;
		if (buf->end_read == buf->begin) {
			atomic_set(&buf->overflow, 1);
		} else {
			atomic_set(&buf->overflow, 0);
		}
	}
	list_del_rcu(&proh->list);
}

#ifndef PS_TEST
int write_to_buffer_end(struct ps_buffer *buf, struct ps_prohibition *proh, void __user *user_info) {
#else
int write_to_buffer_end(struct ps_buffer *buf, struct ps_prohibition *proh, void *user_info) {
#endif
	if (!buf || !user_info)
		return -EINVAL;

#ifndef PS_TEST
	if (copy_from_user(proh->addr, user_info, buf->blk_size)) {
#else
	if (memcpy(proh->addr, user_info, buf->blk_size) != proh->addr){
#endif
		return -EFAULT;
	}
	return 0;
}

#ifndef PS_TEST
int read_from_buffer_at_position(struct ps_buffer *buf, struct ps_position *pos, void __user *user_info) {
#else
int read_from_buffer_at_position(struct ps_buffer *buf, struct ps_position *pos, void *user_info) {
#endif
	if (!buf || !pos || !user_info)
		return -EINVAL;
#ifndef PS_TEST
	if (copy_to_user(user_info, pos->addr, buf->blk_size)) {
#else
	if (memcpy(user_info, pos->addr, buf->blk_size) != user_info) {
#endif
		return -EFAULT;
	}
	return 0;
}

void up_position(struct ps_position *pos) {
	atomic_dec(&pos->cnt);
}

void down_position(struct ps_position *pos) {
	atomic_inc(&pos->cnt);
}

void push_free_position(struct ps_buffer *buf, struct ps_position *pos) {
	list_add_tail_rcu(&pos->list, &buf->positions_free);
}

void pop_free_position(struct ps_buffer *buf, struct ps_position *pos) {
	list_del_rcu(&pos->list);
}

void push_used_position_after(struct ps_buffer *buf, struct ps_position *new_pos, struct ps_position *pos) {
	void *addr = pos->addr + buf->blk_size;
	if (addr == buf->base_end)
		addr = buf->base_begin;
	if (addr == buf->end_read)
		buf->stop_pos = new_pos;
	new_pos->addr = addr;
	list_add_rcu(&new_pos->list, &pos->list);
}

void push_used_position_begin(struct ps_buffer *buf, struct ps_position *pos) {
	pos->addr = buf->begin;
	if (buf->begin == buf->end && !atomic_read(&buf->overflow))
		buf->stop_pos = pos;
	list_add_rcu(&pos->list, &buf->positions_used);
}

void pop_used_position(struct ps_buffer *buf, struct ps_position *pos) {
	list_del_rcu(&pos->list);
	if (pos == buf->stop_pos)
		buf->stop_pos = NULL;
	struct ps_position *next_pos = list_first_entry_or_null(&buf->positions_used, struct ps_position, list);
	if (next_pos)
		buf->begin = next_pos->addr;
}

struct ps_position *find_free_position(struct ps_buffer *buf) {
	return list_first_entry_or_null(&buf->positions_free, struct ps_position, list);
}

struct ps_position *find_next_position(struct ps_buffer *buf, struct ps_position *pos) {
	if (!list_is_last(&pos->list, &buf->positions_used)) {
		struct ps_position *next_pos = list_next_entry(pos, list);
		if (pos->addr != ((char *)buf->base_end) - buf->blk_size) {
			if (((char *)next_pos->addr) - ((char *)pos->addr) == buf->blk_size) {
				return next_pos;
			}
		} else {
			if (next_pos->addr == buf->base_begin) {
				return next_pos;
			}
		}
	}
	return NULL;
}

//TODO: Вся защита на запись должны быть в node.c
struct ps_position *find_first_position(struct ps_buffer *buf) {
	return list_first_entry_or_null(&buf->positions_used, struct ps_position, list);
}

struct ps_position *create_position_struct(void) {
	struct ps_position *pos = vzalloc(sizeof(struct ps_position));
	if (pos) {
		atomic_set(&pos->cnt, 0);
		pos->addr = NULL;
		INIT_LIST_HEAD(&pos->list);
	}
	return pos;
}

void delete_position_struct(struct ps_position *pos) {
	vfree(pos);
}
