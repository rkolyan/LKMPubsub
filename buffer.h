#ifndef PS_BUFFER_H
#define PS_BUFFER_H

#include <linux/uaccess.h>

struct ps_buffer {
    void *base_begin;
    void *base_end;//Границы буфера в адресе (base_end - включительно)
    void *begin;
    void *end;
    int base_begin_num;
    int begin_num;//Номер начала сообщений
    int end_num;//Номер конца сообщений (номер БУДУЩЕГО НОВОГО СООБЩЕНИЯ)
    size_t blk_size;
    size_t buf_size;
    int flag;
};

int init_buffer(struct ps_buffer *buf, size_t buf_size, size_t blk_size, int flag);
int deinit_buffer(struct ps_buffer *buf);

int is_buffer_full(struct ps_buffer *buf);
int is_buffer_blocking(struct ps_buffer *buf);

int delete_first_message(struct ps_buffer *buf);

int write_to_buffer(struct ps_buffer *buf, void __user *info);
int read_from_buffer(struct ps_buffer *buf, int msg_num, void __user *info);

int get_buffer_begin_num(struct ps_buffer *buf, int *msg_num);

int msg_num_to_addr(const struct ps_buffer *buf, int msg_num, void **addr);
#endif