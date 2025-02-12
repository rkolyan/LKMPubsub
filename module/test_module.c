#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vmalloc.h>

#define PS_TEST

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
	struct ps_position *pos = NULL;

	int err = create_position_struct(&pos);
	
	if (err || pos == NULL) {
		trace_printk("err == %d, pos == %p\n", err, pos);
		return EXPECT;
	}
	delete_position_struct(pos);
	return SUCCESS;
}

test_result_t test_init_buffer_struct(void) {
	struct ps_buffer buf;

	int err = init_buffer(&buf, 20, 10);

	if (err || buf.base_begin != buf.begin || buf.begin != buf.end || buf.blk_size != 10 || buf.buf_size != 20 || buf.base_end - buf.base_begin != (buf.buf_size - 1) * (buf.blk_size) || buf.begin_num != 0 || buf.end_num != 0 || buf.base_begin_num != 0) {
		trace_printk("err == %d, begin == %p, end == %p, base_begin == %p, base_end == %p, begin_num == %d, end_num == %d, base_begin_num == %d, buf_size == %lu, blk_size == %lu\n", err, buf.begin, buf.end, buf.base_begin, buf.base_end, buf.begin_num, buf.end_num, buf.base_begin_num, buf.buf_size, buf.blk_size);
		trace_printk("base_end - base_begin = %d, buf_size * blk_size = %lu\n", buf.base_end - buf.base_begin, (buf.buf_size - 1) * buf.blk_size);
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
test_result_t test_find_free_position_empty(void) {
	struct ps_position *pos1 = NULL;
	struct ps_positions_desc desc;
	init_positions_desc(&desc);
	int err1 = 0;
	
	err1 = find_free_position(&desc, &pos1);

	if (!err1 || pos1) {
		trace_printk("err1 == %d, pos1 == %p\n", err1, pos1);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_free_position(void) {
	struct ps_position *pos1 = NULL, *pos = NULL;
	struct ps_positions_desc desc;
	init_positions_desc(&desc);
	int err1 = create_position_struct(&pos1);
	push_free_position(&desc, pos1);
	
	err1 = find_free_position(&desc, &pos);

	if (err1 || !pos || pos != pos1) {
		trace_printk("err1 == %d, pos1 == %p, pos == %p\n", err1, pos1, pos);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t test_find_free_position_after_pop(void) {
	struct ps_position *pos1 = NULL, *pos = NULL;
	struct ps_positions_desc desc;
	init_positions_desc(&desc);
	int err1 = create_position_struct(&pos1);
	push_free_position(&desc, pos1);
	pop_free_position(&desc, pos1);

	err1 = find_free_position(&desc, &pos);

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
test_result_t test_get_buffer_address(void) {
	struct ps_buffer buf;
	init_buffer(&buf, 10, 20);
	return SUCCESS;
}

test_result_t stest_create_find_node(void) {
	struct ps_node *node = NULL, *tmp_node = NULL;
	unsigned long id = 0;

	int err1 = create_node_struct(30, 20, &node);
	int err2 = get_node_id(node, &id);
	int err3 = add_node(node);
	int err4 = find_node(id, &tmp_node);
	int err5 = remove_node(tmp_node);
	int err6 = delete_node_struct(node);
	//TODO: Надо попробовать дублирование нескольских add_node и remove_node

	if (err1 || err2 || err3 || err4 || err5 || err6 || !id || !node || !tmp_node || node != tmp_node) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, err6 == %d, id == %lu, node == %p, tmp_node == %p\n", err1, err2, err3, err4, err5, err6, id, node, tmp_node);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t stest_create_find_publish_node(void) {
	struct ps_node *node = NULL;
	struct ps_publisher *pub = NULL, *tmp_pub = NULL;
	

	int err1 = create_node_struct(30, 20, &node);
	trace_printk("node = %p, pubs_coll offset = %p, &node->pubs_coll = %p, node + offset = %p, sizeof(ps_node) = %p, node + sizeof(ps_node) = %p\n", node, offsetof(struct ps_node, pubs_coll), &node->pubs_coll, ((char *)node) + offsetof(struct ps_node, pubs_coll), sizeof(struct ps_node), ((char *)node) + sizeof(struct ps_node));
	int err2 = create_publisher_struct(100, &pub);
	int err3 = add_publisher_in_node(node, pub);
	int err4 = find_publisher_in_node(node, 100, &tmp_pub);
	int err5 = remove_publisher_in_node(node, pub);
	int err7 = delete_node_struct(node);
	int err6 = delete_publisher_struct(pub);
	//TODO: Надо попробовать дублирование нескольских add_node и remove_node

	if (err1 || err2 || err3 || err4 || err5 || err6 || err7 || !node || !pub || !tmp_pub || pub != tmp_pub) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, err6 == %d, err7 == %d, node == %p, pub == %p, tmp_pub == %p\n", err1, err2, err3, err4, err5, err6, err7, node, pub, tmp_pub);
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

	if (err1 || err2 || !err3 || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, id == %lu\n", err1, err2, err3, id);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_publish_unpublish(void) {
	unsigned long id = 0;
	
	int err1 = ps_node_create(30, 10, &id);
	int err2 = ps_node_publish(id);
	//int err3 = ps_node_unpublish(id);
	//int err4 = ps_node_delete(id);

	//if (err1 || err2 || err3 || err4 || !id) {
		//trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, id == %lu\n", err1, err2, err3, err4, id);
	if (err1 || err2 || !id) {
		trace_printk("err1 == %d, err2 == %d, id == %lu\n", err1, err2, id);
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

	if (err1 || err2 || err3 || err4 || err5 || !id) {
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

	if (err1 || !err2 || err3 || id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, id == %lu\n", err1, err2, err3, id);
		return EXPECT;
	}
	return SUCCESS;
}

test_result_t ftest_send_with_publish(void) {
	unsigned long id = 0;
	char buf[10] = "091234567";

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

test_result_t ftest_send_receive_doubled(void) {
	unsigned long id = 0;
	char output[20] = {'0', '9', '1', '2', '3', '4', '5', '6', '7', '8', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
	char input[20] = {'\0'};

	int err1 = ps_node_create(2, 10, &id);
	int err2 = ps_node_publish(id);
	int err3 = ps_node_send(id, output);
	int err4 = ps_node_send(id, output + 10);
	int err5 = ps_node_subscribe(id);
	int err6 = ps_node_receive(id, input);
	int err7 = ps_node_receive(id, input + 10);
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
	stest_create_find_node();
	stest_create_find_publish_node();

	ftest_create_delete_node();
	ftest_delete_empty();
	ftest_publish_doubled();
	ftest_publish_unpublish();
	ftest_publish_unpublished_deleted();
	/*
	ftest_unpublish_after_delete();
	ftest_subscribe_unsubscribe();
	ftest_subscribe_unsubscribe_deleted();
	ftest_send_without_publish();
	ftest_send_with_publish();
	ftest_send_receive_without_subscribe();
	ftest_send_receive_normal();
	ftest_send_receive_doubled();
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
