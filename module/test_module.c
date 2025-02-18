#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vmalloc.h>

#include "node.h"
#include "publisher.h"
#include "subscriber.h"
#include "position.h"
#include "buffer.h"
#include "functions.h"

MODULE_AUTHOR("Golovnev Nikolay");
MODULE_DESCRIPTION("Test PubSub module");
MODULE_LICENSE("GPL");

typedef enum {
	SUCCESS = 0,
	ASSERT = -1,
	EXPECT = -2
} test_result_t;

//TODO: 1)Протестируем функции создания и удаления
test_result_t test_create_node_struct(void) {
	struct ps_node *node = NULL;
	
	int err = create_node_struct(20, 10, &node);

	if (err || node == NULL) {
		trace_printk("err == %d, node == %p\n", err, node);
		return EXPECT;
	}
	delete_node_struct(node);
	return SUCCESS;
}

test_result_t test_create_publisher_struct(void) {
	struct ps_publisher *pub = NULL;

	int err = create_publisher_struct(11, &pub);
	
	if (err || pub == NULL) {
		trace_printk("err == %d, pub == %p\n", err, pub);
		return EXPECT;
	}
	delete_publisher_struct(pub);
	return SUCCESS;
}

test_result_t test_create_subscriber_struct(void) {
	struct ps_subscriber *sub = NULL;

	int err = create_subscriber_struct(11, &sub);
	
	if (err || sub == NULL) {
		trace_printk("err == %d, sub == %p\n", err, sub);
		return EXPECT;
	}
	delete_subscriber_struct(sub);
	return SUCCESS;
}

test_result_t test_create_position_struct(void) {
	struct ps_position *pos = create_position_struct(&pos);

	if (pos == NULL) {
		trace_printk("pos == %p\n", pos);
		return EXPECT;
	}
	delete_position_struct(pos);
	return SUCCESS;
}

test_result_t test_init_buffer_struct(void) {
	struct ps_buffer buf;

	int err = init_buffer(&buf, 20, 10);

	if (err || buf.base_begin != buf.begin || buf.begin != buf.end || buf.blk_size != 10 || buf.buf_size != 20 || buf.base_end - buf.base_begin != buf.buf_size * buf.blk_size) {
		trace_printk("err == %d, begin == %p, end == %p, base_begin == %p, base_end == %p, buf_size == %lu, blk_size == %lu\n", err, buf.begin, buf.end, buf.base_begin, buf.base_end, buf.buf_size, buf.blk_size);
		trace_printk("base_end - base_begin = %ld, buf_size * blk_size = %lu\n", buf.base_end - buf.base_begin, buf.buf_size * buf.blk_size);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_publisher_empty(void) {
	struct ps_publisher *pub = NULL;
	struct ps_publishers_collection coll;
	init_publisher_collection(&coll);
	
	int err = find_publisher(&coll, 11, &pub);

	if (err != -ENOENT || pub != NULL) {
		trace_printk("err == %d, pub == %p\n", err, pub);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_publisher(void) {
	struct ps_publisher *pub = NULL, *tmp_pub = NULL;
	struct ps_publishers_collection coll;
	init_publisher_collection(&coll);
	int err = create_publisher_struct(11, &pub);
	add_publisher(&coll, pub);

	err = find_publisher(&coll, 11, &tmp_pub);

	if (err || !tmp_pub || tmp_pub != pub) {
		trace_printk("err == %d, pub == %p, tmp_pub == %p\n", err, pub, tmp_pub);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_publisher_not_right_number(void) {
	struct ps_publisher *pub = NULL, *tmp_pub = NULL;
	struct ps_publishers_collection coll;
	init_publisher_collection(&coll);
	int err = create_publisher_struct(11, &pub);
	add_publisher(&coll, pub);

	err = find_publisher(&coll, 12, &tmp_pub);

	if (!err || tmp_pub) {
		trace_printk("err == %d, pub == %p, tmp_pub == %p\n", err, pub, tmp_pub);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_publisher_double_number(void) {
	struct ps_publisher *pub = NULL, *pub2 = NULL, *pub3 = NULL;
	struct ps_publishers_collection coll;
	init_publisher_collection(&coll);
	int err = create_publisher_struct(11, &pub);
	add_publisher(&coll, pub);
	pub = NULL;
	int err2 = create_publisher_struct(12, &pub), err3 = 0;
	add_publisher(&coll, pub);
	pub = NULL;

	err = find_publisher(&coll, 12, &pub);
	err2 = find_publisher(&coll, 11, &pub2);
	err3 = find_publisher(&coll, 10, &pub3);
	
	if (err || err2 || err3 != -ENOENT || !pub || !pub2 || pub3 || pub == pub2) {
		trace_printk("err == %d, err2 == %d, err3 == %d, pub == %p, pub2 == %p, pub3 == %p\n", err, err2, err3, pub, pub2, pub3);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_publisher_affect(void) {
	struct ps_publisher *pub = NULL, *pub2 = NULL, *pub3 = NULL, *pub4 = NULL;
	struct ps_publishers_collection coll;
	init_publisher_collection(&coll);
	int err = create_publisher_struct(11, &pub);
	add_publisher(&coll, pub);
	pub = NULL;
	int err2 = create_publisher_struct(12, &pub), err3 = 0, err4 = 0;
	add_publisher(&coll, pub);
	pub = NULL;

	err = find_publisher(&coll, 12, &pub);
	err2 = find_publisher(&coll, 11, &pub2);
	err3 = find_publisher(&coll, 12, &pub3);
	err4 = find_publisher(&coll, 11, &pub4);
	
	if (err || err2 || err3 || err4 || !pub || !pub2 || !pub3 || !pub4 || pub != pub3 || pub2 != pub4) {
		trace_printk("err == %d, err2 == %d, err3 == %d, err4 == %d, pub == %p, pub2 == %p, pub3 == %p, pub4 == %p\n", err, err2, err3, err4, pub, pub2, pub3, pub4);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_subscriber_empty(void) {
	struct ps_subscriber *sub = NULL;
	struct ps_subscribers_collection coll;
	init_subscriber_collection(&coll);
	
	int err = find_subscriber(&coll, 11, &sub);

	if (err != -ENOENT || sub != NULL) {
		trace_printk("err == %d, sub == %p\n", err, sub);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_subscriber(void) {
	struct ps_subscriber *sub = NULL, *tmp_sub = NULL;
	struct ps_subscribers_collection coll;
	init_subscriber_collection(&coll);
	int err = create_subscriber_struct(11, &sub);
	add_subscriber(&coll, sub);

	err = find_subscriber(&coll, 11, &tmp_sub);

	if (err || !tmp_sub || tmp_sub != sub) {
		trace_printk("err == %d, sub == %p, tmp_sub == %p\n", err, sub, tmp_sub);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_subscriber_not_right_number(void) {
	struct ps_subscriber *sub = NULL, *tmp_sub = NULL;
	struct ps_subscribers_collection coll;
	init_subscriber_collection(&coll);
	int err = create_subscriber_struct(11, &sub);
	add_subscriber(&coll, sub);

	err = find_subscriber(&coll, 12, &tmp_sub);

	if (!err || tmp_sub || tmp_sub == sub) {
		trace_printk("err == %d, sub == %p, tmp_sub == %p\n", err, sub, tmp_sub);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_subscriber_double_number(void) {
	struct ps_subscriber *sub = NULL, *sub2 = NULL, *sub3 = NULL;
	struct ps_subscribers_collection coll;
	init_subscriber_collection(&coll);
	int err = create_subscriber_struct(11, &sub);
	add_subscriber(&coll, sub);
	sub = NULL;
	int err2 = create_subscriber_struct(12, &sub), err3 = 0;
	add_subscriber(&coll, sub);
	sub = NULL;

	err = find_subscriber(&coll, 12, &sub);
	err2 = find_subscriber(&coll, 11, &sub2);
	err3 = find_subscriber(&coll, 10, &sub3);
	
	if (err || err2 || err3 != -ENOENT || !sub || !sub2 || sub3 || sub == sub2) {
		trace_printk("err == %d, err2 == %d, err3 == %d, sub == %p, sub2 == %p, sub3 == %p\n", err, err2, err3, sub, sub2, sub3);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_subscriber_affect(void) {
	struct ps_subscriber *pub = NULL, *pub2 = NULL, *pub3 = NULL, *pub4 = NULL;
	struct ps_subscribers_collection coll;
	init_subscriber_collection(&coll);
	int err = create_subscriber_struct(11, &pub);
	add_subscriber(&coll, pub);
	pub = NULL;
	int err2 = create_subscriber_struct(12, &pub), err3 = 0, err4 = 0;
	add_subscriber(&coll, pub);
	pub = NULL;

	err = find_subscriber(&coll, 12, &pub);
	err2 = find_subscriber(&coll, 11, &pub2);
	err3 = find_subscriber(&coll, 12, &pub3);
	err4 = find_subscriber(&coll, 11, &pub4);
	
	if (err || err2 || err3 || err4 || !pub || !pub2 || !pub3 || !pub4 || pub != pub3 || pub2 != pub4) {
		trace_printk("err == %d, err2 == %d, err3 == %d, err4 == %d, sub == %p, sub2 == %p, sub3 == %p, sub4 == %p\n", err, err2, err3, err4, pub, pub2, pub3, pub4);
		return EXPECT;
	}
	return SUCCESS;
}

//TODO: 2)Протестируем функции поиска позиции в коллекции
//TODO: Нужно из init_buffer удалить push_free_position и вставить в node.c
test_result_t test_find_free_position_empty(void) {
	struct ps_position *pos1 = NULL;
	struct ps_buffer buf;
	init_buffer(&buf, 3, 10);
	
	pos1 = find_free_position(&buf);

	if (pos1) {
		trace_printk("pos1 == %p\n", pos1);
		return EXPECT;
	}
	deinit_buffer(&buf);
	return SUCCESS;
}

test_result_t test_find_free_position(void) {
	struct ps_position *pos1 = NULL, *pos = NULL;
	struct ps_buffer buf;
	init_buffer(&buf, 3, 4);
	pos = create_position_struct();
	push_free_position(&buf, pos);
	
	pos1 = find_free_position(&buf);

	if (pos != pos1) {
		trace_printk("pos1 == %p, pos == %p\n", pos1, pos);
		return EXPECT;
	}
	deinit_buffer(&buf);
	return SUCCESS;
}

test_result_t test_find_free_position_after_pop(void) {
	struct ps_position *pos1 = NULL, *pos = NULL;
	struct ps_buffer buf;
	init_buffer(&buf, 3, 4);
	pos = create_position_struct();
	push_free_position(&buf, pos);
	pop_free_position(&buf, pos);

	pos1 = find_free_position(&buf);

	if (!err1 || pos) {
		trace_printk("err1 == %d, pos == %p\n", err1, pos);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_free_position_empty_double(void) {
	struct ps_position *pos1 = NULL, *pos2 = NULL, *pos = NULL;
	struct ps_positions_desc desc;
	init_positions_desc(&desc);
	int err1 = create_position_struct(&pos1);
	create_position_struct(&pos2);
	push_free_position(&desc, pos1);
	push_free_position(&desc, pos2);
	pop_free_position(&desc, pos1);
	pop_free_position(&desc, pos2);

	err1 = find_free_position(&desc, &pos);

	if (!err1 || pos) {
		trace_printk("err1 == %d, pos1 == %p, pos2 == %p, pos == %p\n", err1, pos1, pos2, pos);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_msg_num_position_empty(void) {
	struct ps_position *pos1 = NULL;
	struct ps_positions_desc desc;
	init_positions_desc(&desc);

	int err1 = find_msg_num_position(&desc, 10, &pos1);

	if (!err1 || pos1) {
		trace_printk("err1 == %d, pos == %p\n", err1, pos1);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_msg_num_position(void) {
	struct ps_position *pos1 = NULL, *pos = NULL;
	struct ps_positions_desc desc;
	init_positions_desc(&desc);
	int err1 = create_position_struct(&pos1);
	set_position_num(pos1, 10);
	push_used_position_last(&desc, pos1);

	err1 = find_msg_num_position(&desc, 10, &pos);

	if (err1 || !pos || pos != pos1) {
		trace_printk("err1 == %d, pos == %p, pos1 == %p\n", err1, pos, pos1);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_msg_num_position2(void) {
	struct ps_position *pos1 = NULL, *pos2 = NULL, *pos1_2 = NULL, *pos2_2 = NULL, *pos3 = NULL;
	struct ps_positions_desc desc;
	init_positions_desc(&desc);
	int err1 = create_position_struct(&pos1), err2 = create_position_struct(&pos2), err3 = 0;
	set_position_num(pos1, 10);
	set_position_num(pos2, 11);
	push_used_position_last(&desc, pos1);
	push_used_position_last(&desc, pos2);

	err1 = find_msg_num_position(&desc, 10, &pos1_2);
	err2 = find_msg_num_position(&desc, 11, &pos2_2);
	err3 = find_msg_num_position(&desc, 12, &pos3);

	if (err1 || err2 || !err3 || !pos1_2 || !pos2_2 || pos3 || pos1_2 != pos1 || pos2_2 != pos2) {
		trace_printk("err1 == %d, pos1 == %p, pos1_1 == %p, err2 = %d, pos2 == %p, pos2_2 == %p, err3 == %d, pos3 == %p\n", err1, pos1, pos1_2, err2, pos2, pos2_2, err3, pos3);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_msg_num_position_after_pop(void) {
	struct ps_position *pos1 = NULL, *pos = NULL;
	struct ps_positions_desc desc;
	init_positions_desc(&desc);
	int err1 = create_position_struct(&pos1);
	set_position_num(pos1, 10);
	push_used_position_last(&desc, pos1);
	pop_used_position(&desc, pos1);

	err1 = find_msg_num_position(&desc, 10, &pos);

	if (!err1 || pos || pos1 == pos) {
		trace_printk("err1 == %d, pos == %p, pos1 == %p\n", err1, pos, pos1);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_next_position_empty(void) {
	struct ps_position *pos1 = NULL, *pos = NULL;
	struct ps_positions_desc desc;
	int err1 = create_position_struct(&pos1);
	init_positions_desc(&desc);
	set_position_num(pos1, 10);
	push_used_position_last(&desc, pos1);

	err1 = find_next_position(&desc, pos1, &pos);

	if (!err1 || pos) {
		trace_printk("err1 == %d, pos == %p, pos1 == %p\n", err1, pos, pos1);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_next_position(void) {
	struct ps_position *pos1 = NULL, *pos2 = NULL, *pos1_2 = NULL, *pos2_2 = NULL;
	struct ps_positions_desc desc;
	int err1 = create_position_struct(&pos1), err2 = create_position_struct(&pos2);
	init_positions_desc(&desc);
	set_position_num(pos1, 10);
	set_position_num(pos2, 12);
	push_used_position_last(&desc, pos1);
	push_used_position_last(&desc, pos2);

	err1 = find_next_position(&desc, pos1, &pos1_2);
	err2 = find_next_position(&desc, pos2, &pos2_2);

	if (err1 || !err2 || pos2 != pos1_2 || pos2_2) {
		trace_printk("err1 == %d, pos1 == %p, pos1_2 == %p,err2 == %d, pos2 == %p, pos2_2 == %p\n", err1, pos1, pos1_2, err2, pos2, pos2_2);
		return EXPECT;
	}
	return SUCCESS;
}

//TODO: 3)Протестировать буферные функции чтения и записи
//TODO:
test_result_t test_write_buffer_simple(void) {
	char str[3] = {'a', 'b', 'c'};
	struct ps_buffer buf;
	
	int err1 = init_buffer(&buf, 1, 3);
	int msg_num = get_buffer_begin_num(&buf);
	void *addr = get_buffer_address(&buf, msg_num);
	int err2 = write_to_buffer(&buf, addr, str);

	if (err1 || err2 || msg_num != 0 || !addr || addr != buf.base_begin || !(((char *)buf.base_begin)[0] == 'a' && ((char *)buf.base_begin)[1] == 'b' && ((char *)buf.base_begin)[2] == 'c')) {
		trace_printk("err1 == %d, err2 == %d, addr = %p, base_begin = %p, msg_num = %d, base = %3s\n", err1, err2, addr, buf.base_begin, msg_num, (char *)buf.base_begin);
		return EXPECT;
	}

	return SUCCESS;
}

#define BBBLOCK_SSSIZE 2

test_result_t test_get_buffer_address_begin_end_less_bigger(void) {
	struct ps_buffer buf;

	init_buffer(&buf, 6, BBBLOCK_SSSIZE);
	deinit_buffer(&buf);
	buf.base_begin_num = -1;
	buf.begin_num = 2;
	buf.begin = buf.base_begin + (buf.begin_num - buf.base_begin_num) * BBBLOCK_SSSIZE;
	buf.end_num = 4;
	buf.end = buf.base_begin + (buf.end_num - buf.base_begin_num) * BBBLOCK_SSSIZE;

	void *addr1 = get_buffer_address(&buf, 4);
	//void *addr2 = get_buffer_address(&buf, 6);TODO: По идее таких случаев быть не должно... 
	void *addr3 = get_buffer_address(&buf, 1);

	if (addr1 != ((char *)buf.base_end) || addr3 != ((char *)buf.base_begin) + 2 * BBBLOCK_SSSIZE) {
		trace_printk("addr1 = %p, addr3 = %p, buf.base_end = %p, buf.base_begin + 2BLOCK - addr3 = %ld\n", addr1, addr3, buf.base_end, ((char *)buf.base_begin) + 2 * BBBLOCK_SSSIZE - (char*) addr3);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_get_buffer_address_begin_end_bigger_less(void) {
	struct ps_buffer buf;

	init_buffer(&buf, 6, BBBLOCK_SSSIZE);
	deinit_buffer(&buf);
	buf.base_begin_num = 0x7FFFFFFF - 3;
	buf.begin_num = 0x7FFFFFFF - 1;
	buf.begin = buf.base_begin + (buf.begin_num - buf.base_begin_num) * BBBLOCK_SSSIZE;
	buf.end_num = 0x7FFFFFFF + 2;
	buf.end = buf.base_begin + 5 * BBBLOCK_SSSIZE;

	void *addr1 = get_buffer_address(&buf, 0x7FFFFFFF + 1);
	void *addr2 = get_buffer_address(&buf, 0x7FFFFFFF - 2);

	if (addr1 != ((char *)buf.base_begin) + 4 * BBBLOCK_SSSIZE || addr2 != ((char *)buf.base_begin) + 1 * BBBLOCK_SSSIZE) {
		trace_printk("addr1 = %p, addr2 = %p, diff1 = %ld, diff2 = %ld\n", addr1, addr2, ((char *)buf.begin) + 4 * BBBLOCK_SSSIZE - (char *)addr1, ((char *)buf.begin) + 1 * BBBLOCK_SSSIZE - (char *)addr2);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_get_buffer_address_end_begin_less_bigger(void) {
	struct ps_buffer buf;

	init_buffer(&buf, 6, BBBLOCK_SSSIZE);
	deinit_buffer(&buf);
	buf.base_begin_num = 8;
	buf.begin_num = 6;
	buf.begin = buf.base_end - BBBLOCK_SSSIZE;
	buf.end_num = 9;
	//T.O: Можно сделать типо buf->end_num - buf->begin_base_num % (base_end_num - base_begin_num);
	buf.end = buf.base_begin + BBBLOCK_SSSIZE;

	void *addr1 = get_buffer_address(&buf, 8);
	void *addr2 = get_buffer_address(&buf, 7);

	if (addr1 != buf.base_begin || addr2 != buf.base_end) {
		trace_printk("addr1 = %p, addr2 = %p, base_begin = %p, base_end = %p\n", addr1, addr2, buf.base_begin, buf.base_end);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_get_buffer_address_end_begin_bigger_less(void) {
	struct ps_buffer buf;

	init_buffer(&buf, 10, BBBLOCK_SSSIZE);
	deinit_buffer(&buf);
	buf.base_begin_num = 0x7FFFFFFF - 1;
	buf.begin_num = 0x7FFFFFFF - 3;
	buf.begin = buf.base_end - 1 * BBBLOCK_SSSIZE;
	buf.end_num = 0x7FFFFFFF + 2;
	buf.end = buf.base_begin + 3 * BBBLOCK_SSSIZE;

	void *addr1 = get_buffer_address(&buf, 0x7FFFFFFF - 2);
	void *addr2 = get_buffer_address(&buf, 0x7FFFFFFF - 1);

	if (addr1 != buf.base_end || addr2 != buf.base_begin) {
		trace_printk("addr1 = %p, addr2 = %p\n", addr1, addr2);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t stest_create_acquire_node(void) {
	struct ps_node *node = NULL, *tmp_node = NULL;
	unsigned long id = 0;

	int err1 = create_node_struct(30, 20, &node);
	int err2 = get_node_id(node, &id);
	int err3 = add_node(node);
	int err4 = acquire_node(id, &tmp_node);
	int err5 = release_node(tmp_node);
	int err6 = remove_node(tmp_node);
	int err7 = delete_node_struct(node);
	//TODO: Надо попробовать дублирование нескольских add_node и remove_node

	if (err1 || err2 || err3 || err4 || err5 || err6 || err7 || !id || !node || !tmp_node || node != tmp_node) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, err6 == %d, err7 = %d, id == %lu, node == %p, tmp_node == %p\n", err1, err2, err3, err4, err5, err6, err7, id, node, tmp_node);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t stest_create_find_publish_node(void) {
	struct ps_node *node = NULL;
	struct ps_publisher *pub = NULL, *tmp_pub = NULL;
	

	int err1 = create_node_struct(30, 20, &node);
	int err2 = create_publisher_struct(100, &pub);
	int err3 = add_publisher_in_node(node, pub);
	int err4 = find_publisher_in_node(node, 100, &tmp_pub);
	int err5 = remove_publisher_in_node(node, pub);
	int err6 = delete_node_struct(node);
	int err7 = delete_publisher_struct(pub);
	//TODO: Надо попробовать дублирование нескольских add_node и remove_node

	if (err1 || err2 || err3 || err4 || err5 || err6 || err7 || !node || !pub || !tmp_pub || pub != tmp_pub) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, err6 == %d, err7 == %d, node == %p, pub == %p, tmp_pub == %p\n", err1, err2, err3, err4, err5, err6, err7, node, pub, tmp_pub);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t stest_buffer(void) {
	struct ps_buffer buf;
	struct ps_publisher *pub = NULL;
	struct ps_position *pos = NULL;
	int msg_num = 0;
	char output[20] = {'0', '9', '1', '2', '3', '4', '5', '6', '7', '8', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
	char input[20] = {'\0'};

	//TODO: Надо с разными числами поиграться (менять в msg_num)
	//1)Инициализировать все данные
	int err1 = create_position_struct(&pos);
	int err2 = create_publisher_struct(current->pid, &pub);
	int err3 = init_buffer(&buf, 3, 20);
	//2)Написать сообщение в буфер
	int flag = is_buffer_full(&buf);
	void *addr = get_buffer_address(&buf, msg_num);
	set_prohibition_num(&pub->proh, msg_num);
	prohibit_buffer(&buf, &pub->proh);
	create_last_message(&buf);
	int err6 = write_to_buffer(&buf, addr, output);
	//TODO: Надо посмотреть как будут в перемешку c операциями чтения работать
	unprohibit_buffer(&buf, &pub->proh);

	//3)Получение сообщения
	int err8 = is_buffer_access_reading(&buf, msg_num);
	void *addr2 = get_buffer_address(&buf, msg_num);
	int err9 = read_from_buffer(&buf, addr, input);
	//TODO: В самой функции удаляется позиция и последнее сообщение после прочтения
	trace_printk("msg_num = %d, begin_num = %d, end_read_num = %d\n", msg_num, buf.begin_num, buf.end_read_num);

	//4)Удаление всех данных
	int err10 = delete_position_struct(pos);
	int err11 = delete_publisher_struct(pub);
	int err12 = deinit_buffer(&buf);

	if (err1 || err2 || err3 || flag || !addr || err6 || !err8 || err9 || err10 || err11 || err12 || !addr2 || addr != addr2) {
		trace_printk("err1 = %d, err2 = %d, err3 = %d, pub = %p, pos = %p\n", err1, err2, err3, pub, pos);
		trace_printk("err6 = %d, flag = %d, addr = %p\n", err6, flag, addr);
		trace_printk("err8 = %d, err9 = %d, err10 = %d, err11 = %d, err12 = %d, addr2 = %p\n", err8, err9, err10, err11, err12, addr2);
		return EXPECT;
	}
	return SUCCESS;
}

//TODO: 4)Протестировать более высокоуровневые функции
test_result_t ftest_create_delete_node(void) {
	unsigned long id = 0;
	int err1 = ps_node_create(20, 10, &id);
	int err2 = ps_node_delete(id);

	if (err1 || err2 || !id) {
		trace_printk("err1 == %d, err2 == %d, id == %lu\n", err1, err2, id);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_delete_empty(void) {
	//Типа случайное число
	unsigned long id = 12423421;
	
	int err2 = ps_node_delete(id);

	if (!err2) {
		trace_printk("err == %d\n", err2);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_publish_doubled(void) {
	unsigned long id = 0;
	
	int err1 = ps_node_create(30, 10, &id);
	int err2 = ps_node_publish(id);
	int err3 = ps_node_publish(id);
	int err4 = ps_node_delete(id);

	if (err1 || err2 || !err3 || err4 || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, id == %lu\n", err1, err2, err3, err4, id);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_publish_unpublish(void) {
	unsigned long id = 0;
	
	int err1 = ps_node_create(30, 10, &id);
	int err2 = ps_node_publish(id);
	int err3 = ps_node_unpublish(id);
	int err4 = ps_node_delete(id);

	if (err1 || err2 || err3 || err4 || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, id == %lu\n", err1, err2, err3, err4, id);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_publish_unpublished_deleted(void) {
	unsigned long id = 0;

	int err1 = ps_node_create(30, 10, &id);
	int err2 = ps_node_delete(id);
	int err3 = ps_node_publish(id);
	int err4 = ps_node_unpublish(id);

	if (err1 || err2 || !err3 || !err4 || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, id == %lu\n", err1, err2, err3, err4, id);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_unpublish_after_delete(void) {
	unsigned long id = 0;

	int err1 = ps_node_create(2, 10, &id);
	int err2 = ps_node_publish(id);
	int err3 = ps_node_delete(id);
	int err4 = ps_node_unpublish(id);

	if (err1 || err2 || err3 || !err4 || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, id == %lu\n", err1, err2, err3, err4, id);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_subscribe_unsubscribe(void) {
	unsigned long id = 0;

	int err1 = ps_node_create(30, 10, &id);
	int err2 = ps_node_subscribe(id);
	int err3 = ps_node_unsubscribe(id);
	int err4 = ps_node_delete(id);

	if (err1 || err2 || err3 || err4 || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, id == %lu\n", err1, err2, err3, err4, id);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_subscribe_unsubscribe_deleted(void) {
	unsigned long id = 0;

	int err1 = ps_node_create(30, 10, &id);
	int err2 = ps_node_delete(id);
	int err3 = ps_node_subscribe(id);
	int err4 = ps_node_unsubscribe(id);
	int err5 = ps_node_delete(id);

	if (err1 || err2 || !err3 || !err4 || !err5 || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, id == %lu\n", err1, err2, err3, err4, err5, id);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_send_without_publish(void) {
	unsigned long id = 0;
	char buf[10] = "091234567";

	int err1 = ps_node_create(2, 10, &id);
	int err2 = ps_node_send(id, buf);
	int err3 = ps_node_delete(id);

	if (err1 || !err2 || err3 || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, id == %lu\n", err1, err2, err3, id);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_send_with_publish(void) {
	unsigned long id = 0;
	char buf[10] = "091234567";
	trace_printk("BEGIN");

	int err1 = ps_node_create(2, 10, &id);
	int err2 = ps_node_publish(id);
	int err3 = ps_node_send(id, buf);
	int err4 = ps_node_delete(id);

	if (err1 || err2 || err3 || err4 || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, id == %lu\n", err1, err2, err3, err4, id);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_send_receive_without_subscribe(void) {
	unsigned long id = 0;
	char output[10] = {'0', '9', '1', '2', '3', '4', '5', '6', '7', '8'};
	char input[10] = {'\0'};
	trace_printk("BEGIN");

	int err1 = ps_node_create(2, 10, &id);
	int err2 = ps_node_publish(id);
	int err3 = ps_node_send(id, output);
	int err4 = ps_node_receive(id, input);
	int err5 = ps_node_delete(id);

	char flag = 0;
	for (int i = 0; i < 10; i++) {
		if (input[i] == output[i]) {
			flag = 1;
			break;
		}
	}
	if (err1 || err2 || err3 || !err4 || err5 || flag || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, id == %lu,\n input:\"%10s\", output:\"%10s\"\n", err1, err2, err3, err4, err5, id, input, output);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_send_receive_normal(void) {
	unsigned long id = 0;
	char output[10] = {'0', '9', '1', '2', '3', '4', '5', '6', '7', '8'};
	char input[10] = {'\0'};
	trace_printk("BEGIN");

	int err1 = ps_node_create(2, 10, &id);
	int err2 = ps_node_publish(id);
	int err3 = ps_node_send(id, output);
	int err4 = ps_node_subscribe(id);
	int err5 = ps_node_receive(id, input);
	int err6 = ps_node_delete(id);

	char flag = 0;
	for (int i = 0; i < 10; i++) {
		if (input[i] != output[i]) {
			flag = 1;
		}
	}
	if(err1 || err2 || err3 || err4 || err5 || err6 || flag || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, err6 == %d, id == %lu,\n input:\"%10s\", output:\"%10s\"\n", err1, err2, err3, err4, err5, err6, id, input, output);
		return EXPECT;
	}
	return SUCCESS;
}

//TODO: Надо протестировать функции работы буфера
test_result_t ftest_send_receive_doubled(void) {
	unsigned long id = 0;
	char output[20] = {'0', '9', '1', '2', '3', '4', '5', '6', '7', '8', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
	char input[20] = {'\0'};
	trace_printk("BEGIN");

	int err1 = ps_node_create(2, 10, &id);
	int err2 = ps_node_publish(id);
	int err3 = ps_node_send(id, output);
	int err4 = ps_node_send(id, &output[10]);
	int err5 = ps_node_subscribe(id);
	int err6 = ps_node_receive(id, input);
	int err7 = ps_node_receive(id, &input[10]);
	int err8 = ps_node_delete(id);

	char flag = 0;
	for (int i = 0; i < 20; i++) {
		if (input[i] != output[i]) {
			flag = 1;
		}
	}
	if(err1 || err2 || err3 || err4 || err5 || err6 || err7 || err8 || flag || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, err6 == %d, err7 == %d, err8 == %d, id == %lu,\n input:\"%20s\", output:\"%20s\"\n", err1, err2, err3, err4, err5, err6, err7, err8, id, input, output);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_send_recevie_tripled_without_subscribe(void) {
	//TODO: Прикол в том, что пока не попался подписчик можно затирать непрочитанные сообщения
	unsigned long id = 0;
	char output[30] = {'0', '9', '1', '2', '3', '4', '5', '6', '7', '8', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't'};
	char input[30] = {'\0'};
	trace_puts("BEGIN\n");

	int err1 = ps_node_create(2, 10, &id);
	int err2 = ps_node_publish(id);
	int err3 = ps_node_send(id, output);
	int err4 = ps_node_send(id, output + 10);
	int err5 = ps_node_send(id, output + 20);
	int err6 = ps_node_subscribe(id);
	int err7 = ps_node_receive(id, input);
	int err8 = ps_node_receive(id, input + 10);
	int err9 = ps_node_receive(id, input + 20);
	int err10 = ps_node_delete(id);

	char flag = 0;
	for (int i = 0; i < 10; i++) {
		if (input[i] != output[i + 20] || input[i+10] != output[i+10]) {
			flag = 1;
		}
	}
	if(err1 || err2 || err3 || err4 || err5 || err6 || err7 || err8 || !err9 || err10 || flag || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, err6 == %d, err7 == %d, err8 == %d, err9 == %d, err10 == %d, id == %lu,\n input:\"%30s\", output:\"%20s\"\n", err1, err2, err3, err4, err5, err6, err7, err8, err9, err10, id, input, output);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_send_receive_tripled_with_subscribe(void) {
	unsigned long id = 0;
	char output[30] = {'0', '9', '1', '2', '3', '4', '5', '6', '7', '8', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't'};
	char input[30] = {'\0'};
	trace_puts("BEGIN\n");

	int err1 = ps_node_create(2, 10, &id);
	int err2 = ps_node_publish(id);
	int err3 = ps_node_subscribe(id);
	int err4 = ps_node_send(id, output);
	int err5 = ps_node_send(id, output + 10);
	int err6 = ps_node_send(id, output + 20);
	int err7 = ps_node_receive(id, input);
	int err8 = ps_node_receive(id, input + 10);
	int err9 = ps_node_receive(id, input + 20);
	int err10 = ps_node_delete(id);

	char flag = 0;
	for (int i = 0; i < 20; i++) {
		if (input[i] != output[i]) {
			flag = 1;
		}
	}
	if(err1 || err2 || err3 || err4 || err5 || !err6 || err7 || err8 || !err9 || err10 || flag || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, err6 == %d, err7 == %d, err8 == %d, err9 == %d, err10 == %d, id == %lu,\n input:\"%30s\", output:\"%20s\"\n", err1, err2, err3, err4, err5, err6, err7, err8, err9, err10, id, input, output);
		return EXPECT;
	}
	return SUCCESS;
}

static int __init pubsub_init(void) {
	init_nodes();

	/*
	test_create_node_struct();
	test_create_publisher_struct();
	test_create_subscriber_struct();
	test_create_position_struct();
	test_init_buffer_struct();
	test_find_publisher_empty();
	test_find_publisher();
	test_find_publisher_not_right_number();
	test_find_publisher_double_number();
	test_find_publisher_affect();
	test_find_subscriber_empty();
	test_find_subscriber();
	test_find_subscriber_not_right_number();
	test_find_subscriber_double_number();
	test_find_subscriber_affect();
	test_find_free_position_empty();
	test_find_free_position();
	test_find_free_position_after_pop();
	test_find_free_position_empty_double();
	test_find_msg_num_position_empty();
	test_find_msg_num_position();
	test_find_msg_num_position2();
	test_find_msg_num_position_after_pop();
	test_find_next_position_empty();
	test_find_next_position();
	test_write_buffer_simple();
	test_get_buffer_address_end_begin_less_bigger();
	test_get_buffer_address_end_begin_bigger_less();
	test_get_buffer_address_begin_end_less_bigger();
	test_get_buffer_address_begin_end_bigger_less();
	stest_create_acquire_node();
	stest_create_find_publish_node();
	stest_buffer();
	ftest_create_delete_node();
	ftest_delete_empty();
	ftest_publish_doubled();
	ftest_publish_unpublish();
	ftest_publish_unpublished_deleted();
	ftest_unpublish_after_delete();
	ftest_subscribe_unsubscribe();
	ftest_subscribe_unsubscribe_deleted();
	ftest_send_without_publish();
	ftest_send_with_publish();
	ftest_send_receive_without_subscribe();
	ftest_send_receive_normal();
	*/
	ftest_send_receive_doubled();
	/*
	ftest_send_recevie_tripled_without_subscribe();
	ftest_send_receive_tripled_with_subscribe();
	*/
	return 0;
}

static void __exit pubsub_exit(void)
{
}

module_init(pubsub_init);
module_exit(pubsub_exit);
