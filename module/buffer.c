#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/rculist.h>

#include "buffer.h"

//end_num - индекс, указывающий на ячейку, в которую будет записано новое сообщение
int init_buffer(struct ps_buffer *buf, size_t buf_size, size_t blk_size) {
	if (!buf || !buf_size || !blk_size)
		return -EINVAL;
	size_t final_size = buf_size * blk_size;
	buf->base_begin = vzalloc(final_size);
	if (!buf->base_begin)
		return -ENOMEM;
    //Конечный адрес должен быть включен
	buf->base_end = buf->base_begin + final_size - blk_size;
	buf->begin = buf->base_begin;
	buf->end = buf->base_begin;
	buf->base_begin_num = 0;
	buf->begin_num = 0;
	buf->end_num = 0;
    buf->end_read_num = 0;
	buf->buf_size = buf_size;
	buf->blk_size = blk_size;
	return 0;
}

int deinit_buffer(struct ps_buffer *buf) {
	if (!buf)
		return -EINVAL;
	vfree(buf->base_begin);
	return 0;
}

int is_buffer_full(struct ps_buffer *buf) {
	if (!buf)
		return -EINVAL;
	if (buf->begin == buf->end && buf->end_num > buf->begin_num)
		return 1;
	return 0;
}

int is_buffer_access_reading(struct ps_buffer *buf, int msg_num) {
    if (msg_num - buf->begin_num < 0 || buf->end_read_num - msg_num <= 0)
        return 0;
    return 1;
}

/*
 * Когда увеличивается end_read_num?
 * 1)Когда удаляется значение из списка запрещённых (берется первое значение из списка и уменьшается на 1, либо если список пустой берется endnum-1)
 * в какой функции он увеличивается?
 * 2)prohibit_
 */

void delete_first_message(struct ps_buffer *buf) {
    if (buf->begin != buf->base_end)
        buf->begin += buf->blk_size;
    else
        buf->begin = buf->base_begin;
    buf->begin_num++;
}

void create_last_message(struct ps_buffer *buf) {
    if (buf->end != buf->base_end) {
        buf->end += buf->blk_size;
    } else {
        buf->end = buf->base_begin;
        buf->base_begin_num = buf->end_num;
    }
    buf->end_num++;
}

int write_to_buffer(struct ps_buffer *buf, void *addr, void __user *user_info) {
	if (!buf || !user_info || !addr)
		return -EINVAL;
	size_t n = copy_from_user(addr, user_info, buf->blk_size);
	if (n != buf->blk_size)
		return -EFAULT;
	return 0;
}

void *get_buffer_address(const struct ps_buffer *buf, int msg_num) {
    //TODO: Вот здесь опасная зона
    void *addr = NULL;
	if (buf->begin < buf->end) {
		if (buf->begin_num >= 0 && buf->end_num >= 0) {
			addr = buf->begin + (msg_num - buf->begin_num) * buf->blk_size;
		} else if (buf->begin_num >= 0 && buf->end_num < 0) {//TODO: Че за херня(тут CLion ругается)?
			if (msg_num < 0)
				addr = buf->end - (buf->end_num - msg_num) * buf->blk_size;
			else
				addr = buf->begin + (msg_num - buf->begin_num) * buf->blk_size;
		} else {
			if (msg_num < 0)
				addr = buf->begin + (msg_num - buf->begin_num) * buf->blk_size;
			else
				addr = buf->end - (buf->end_num - msg_num) * buf->blk_size;
		}
	} else {
		if (buf->begin_num >= 0 && buf->end_num >= 0) {
			if (msg_num < buf->base_begin_num)
				addr = buf->begin + (msg_num - buf->begin_num) * buf->blk_size;
			else
				addr = buf->end - (buf->end_num - msg_num) * buf->blk_size;
		} else if (buf->begin_num >= 0 && buf->end_num < 0) {//TODO: И тут тоже
			if(buf->base_begin_num < 0) {
				if (msg_num < 0) { 
					if (buf->base_begin_num <= msg_num) {
						addr = buf->base_begin + (msg_num - buf->base_begin_num) * buf->blk_size;
					} else {
						addr = buf->base_end - (buf->base_begin_num - msg_num - 1) * buf->blk_size;//buf->base_end осторожней с ней
					}
				} else {
					addr = buf->begin + (msg_num - buf->begin_num) * buf->blk_size;
				}
			} else {
				if (msg_num < 0) {
					addr = buf->end - (buf->end_num - msg_num) * buf->blk_size;
				} else {
					if (buf->base_begin_num <= msg_num) {
						addr = buf->base_begin + (msg_num - buf->base_begin_num) * buf->blk_size;
					} else {
                        addr = buf->base_end - (buf->base_begin_num - msg_num - 1) * buf->blk_size;//buf->base_end осторожней с ней
					}
				}
			}
		} else {
			if (msg_num >= buf->base_begin_num)
				addr = buf->base_begin + (msg_num - buf->base_begin_num) * buf->blk_size;
			else
				addr = buf->begin + (msg_num - buf->begin_num) * buf->blk_size;
		}
	}
	return addr;
}

int read_from_buffer(struct ps_buffer *buf, const void *addr, void __user *user_info) {
	if (!buf || !user_info)
		return -EINVAL;
	if (copy_to_user(user_info, addr, buf->blk_size) != buf->blk_size) {
        return -EFAULT;
    }
	return 0;
}

int get_buffer_begin_num(struct ps_buffer *buf) {
    return buf->begin_num;
}

int get_buffer_end_num(struct ps_buffer *buf) {
    return buf->end_num;
}

inline void set_prohibition_num(struct ps_prohibition *proh, int msg_num) {
    proh->msg_num = msg_num;
}

void prohibit_buffer(struct ps_buffer *buf, struct ps_prohibition *proh) {
    list_add_tail_rcu(&(proh->list), &(buf->prohibited));
}

void unprohibit_buffer(struct ps_buffer *buf, struct ps_prohibition *proh) {
    if (proh == list_first_entry_or_null(&(buf->prohibited), struct ps_prohibition, list)) {
        buf->end_read_num = proh->msg_num;
    }
    list_del_rcu(&proh->list);
}
