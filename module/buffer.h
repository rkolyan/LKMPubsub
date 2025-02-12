#ifndef PS_BUFFER_H
#define PS_BUFFER_H

#include <linux/uaccess.h>

struct ps_buffer {
    struct list_head prohibited;
    void *base_begin;
    void *base_end;//Границы буфера в адресе (base_end - включительно)
    void *begin;
    void *end;
    int base_begin_num;
    int begin_num;//Номер начала сообщений
    int end_read_num;//Номер сообщения последнего для чтения
    int end_num;//Номер конца сообщений (номер БУДУЩЕГО НОВОГО СООБЩЕНИЯ)
    size_t blk_size;
    size_t buf_size;
    int flag;
};

struct ps_prohibition {
    int msg_num;
    struct list_head list;
};

void set_prohibition_num(struct ps_prohibition *proh, int msg_num);

int init_buffer(struct ps_buffer *buf, size_t buf_size, size_t blk_size);
int deinit_buffer(struct ps_buffer *buf);

int is_buffer_full(struct ps_buffer *buf);
int is_buffer_access_reading(struct ps_buffer *buf, int msg_num);
//int is_buffer_blocking(struct ps_buffer *buf);

void delete_first_message(struct ps_buffer *buf);
void create_last_message(struct ps_buffer *buf);

#ifndef PS_TEST
int write_to_buffer(struct ps_buffer *buf, void *addr, void __user *info);
int read_from_buffer(struct ps_buffer *buf, const void *addr, void __user *info);
#else
int write_to_buffer(struct ps_buffer *buf, void *addr, void *info);
int read_from_buffer(struct ps_buffer *buf, const void *addr, void *info);
#endif

int get_buffer_begin_num(struct ps_buffer *buf);
int get_buffer_end_num(struct ps_buffer *buf);

void prohibit_buffer(struct ps_buffer *buf, struct ps_prohibition *proh);
void unprohibit_buffer(struct ps_buffer *buf, struct ps_prohibition *proh);

void *get_buffer_address(const struct ps_buffer *buf, int msg_num);
#endif
