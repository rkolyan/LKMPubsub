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
	struct ps_position_array *ps_pos_arr = vzalloc(sizeof(struct ps_position_array));
	if (!ps_pos_arr) {
		vfree(buf->base_begin);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&buf->prohibited);
	INIT_LIST_HEAD(&buf->positions_free);
	INIT_LIST_HEAD(&buf->positions_all);
	INIT_LIST_HEAD(&buf->positions_used);//Он пока пустой
	atomic_set(&buf->pos_count, 1);
	atomic_set(&buf->cur_count, 0);
	list_add(&ps_pos_arr->list, &buf->positions_all);
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
	struct ps_position_array *ps_pos_arr = NULL, *tmp = NULL;
	list_for_each_safe(ps_pos_arr, tmp, &node->buf->positions_all, list) {
		vfree(ps_pos_arr);
	}
	vfree(buf->base_begin);
	return 0;
}

int is_buffer_access_writing(struct ps_buffer *buf) {
	if (!buf)
		return 0;
	if (buf->end != buf->begin && !buf->flag_full)
		return 1;
	return 0;
}

int is_position_out_of_bound(struct ps_buffer *buf, struct ps_position *pos) {
	if (pos->addr < buf->base_begin || pos->addr >= buf->base_end)
		return 2;
	if (buf->end_read > buf->begin) {
		if (pos->addr >= buf->end_read || pos->addr < buf->begin) {
			return 1;
		} else {
			return 0;
		}
	} else if (buf->end_read < buf->begin) {
		if (pos->addr < buf->begin && pos->addr >= buf->end_read) {
			return 1;
		} else {
			return 0;
		}
	}
	return 0;
}

int is_position_not_used(struct ps_buffer *buf, struct ps_position *pos) {
	return atomic_read(&pos->cnt);
}

inline void prohibition_init(struct ps_prohibition *proh) {
	INIT_LIST_HEAD(&proh->list);
}

void prohibit_buffer_end(struct ps_buffer *buf, struct ps_prohibition *proh) {
	proh->addr = buf->end;
	list_add_tail_rcu(&(proh->list), &(buf->prohibited));
}

void unprohibit_buffer(struct ps_buffer *buf, struct ps_prohibition *proh) {
	if (proh == list_first_entry_or_null(&(buf->prohibited), struct ps_prohibition, list)) {
		void *proh_addr = proh->addr + buf->blk_size;
		if (proh_addr != buf->base_end) {
			buf->end_read = proh_addr;
		} else {
			buf->end_read = buf->base_begin;
		}
	}
	list_del_rcu(&proh->list);
}

#ifndef PS_TEST
int write_to_buffer_end(struct ps_buffer *buf, void __user *user_info) {
#else
int write_to_buffer_end(struct ps_buffer *buf, void *user_info) {
#endif
	if (!buf || !user_info)
		return -EINVAL;

#ifndef PS_TEST
	if (copy_from_user(buf->end, user_info, buf->blk_size)) {
#else
	if (memcpy(buf->end, user_info, buf->blk_size) != buf->end){
#endif
		return -EFAULT;
	}
	buf->end += buf->blk_size;
	if (buf->end == buf->base_end) {
		buf->end = buf->base_begin;
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
	if (!memcpy(user_info, pos->addr, buf->blk_size)) {
#endif
		return -EFAULT;
	}
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

void push_free_position(struct ps_buffer *buf, struct ps_position *pos) {
	list_add_tail_rcu(&pos->list, &buf->positions_free);
}

void pop_free_position(struct ps_buffer *buf, struct ps_position *pos) {
	list_del_rcu(&pos->list);
}

void push_used_position_after(struct ps_buffer *buf, struct ps_position *new_pos, struct ps_position *pos) {
	list_add_rcu(&new_pos->list, &pos->list);
}

void pop_used_position(struct ps_buffer *buf, struct ps_position *pos) {
	list_del_rcu(&pos->list);
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

struct ps_position *find_first_position(struct ps_buffer *buf) {
	return list_first_entry_or_null(&buf->positions_used, struct ps_position, list);
}

int buffer_positions_inc(struct ps_buffer *buf) {
	//TODO: Короче, ставим спинлок
	//Увеличиваем pos_count
	//Если он равен PS_POSITIONS_DEFAULT_COUNT
	//	
}

int buffer_positions_dec(struct ps_buffer *buf) {
	struct ps_positions_array *pos
}
