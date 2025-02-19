#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vmalloc.h>

#include "node.h"
#include "publisher.h"
#include "subscriber.h"
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
	struct ps_position *pos = create_position_struct();

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

//TODO: 3)Протестировать буферные функции чтения и записи
//TODO:

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

test_result_t stest_find_free_position_pop(void) {
	struct ps_position *pos1 = NULL, *pos2 = NULL;
	struct ps_buffer buf;
	init_buffer(&buf, 2, 3);
	
	//По умолчанию должна находится 1 позиция
	pos1 = find_free_position(&buf);
	pop_free_position(&buf, pos1);
	pos2 = find_free_position(&buf);
	
	if (!pos1 || pos2) {
		trace_printk("pos1 = %p, pos2 = %p\n", pos1, pos2);
		return EXPECT;
	}
	return ASSERT;
}

test_result_t stest_find_free_position_pop_double(void) {
	struct ps_position *pos1 = NULL, *pos2 = NULL, *pos3 = NULL, *pos4 = NULL;
	struct ps_buffer buf;
	init_buffer(&buf, 2, 3);
	
	//По умолчанию должна находится 1 позиция
	pos1 = find_free_position(&buf);
	pop_free_position(&buf, pos1);
	pos2 = create_position_struct();
	push_free_position(&buf, pos2);
	pos3 = find_free_position(&buf);
	pop_free_position(&buf, pos3);
	pos4 = find_free_position(&buf);
	
	if (!pos1 || !pos2 || pos2 != pos3 || pos4) {
		trace_printk("pos1 = %p, pos2 = %p, pos3 = %p, pos4 = %p\n", pos1, pos2, pos3, pos4);
		return EXPECT;
	}
	return ASSERT;
}

test_result_t stest_send_inside(void) {
	struct ps_buffer buf;
	struct ps_prohibition proh;
	char output[3] = {'a', 'b', 'c'};
	int err = 0;
	init_buffer(&buf, 2, 3);
	
	int flag = try_prohibit_buffer_end(&buf, &proh);
	if (flag) {
		err = write_to_buffer_end(&buf, &proh, output);
		unprohibit_buffer(&buf, &proh);
	}
	
	if (err || buf.end_read != ((char *)buf.base_begin) + 3 || buf.end != ((char *)buf.base_begin) + 3 || buf.stop_pos || memcmp(buf.base_begin, output, 3)) {
		trace_printk("err = %d,base_begin = %p, begin = %p, end_read = %p, end = %p, buf.stop_pos = %p, delta_read = %ld, delta_write = %ld\noutput=%3s\n", err, buf.base_begin, buf.begin, buf.end_read, buf.end, buf.stop_pos, ((char *)buf.end_read) - (char *)buf.base_begin, ((char *)buf.end) - (char *)buf.base_begin, (char *)buf.base_begin);
		return EXPECT;
	}
	return ASSERT;
}

test_result_t stest_send_inside_double(void) {
	struct ps_buffer buf;
	struct ps_prohibition proh1, proh2;
	char output[6] = {'a', 'b', 'c', 'd', 'e', 'f'};
	int err1 = 0, err2 = 0;
	init_buffer(&buf, 2, 3);
	
	int flag1 = try_prohibit_buffer_end(&buf, &proh1);
	if (flag1) {
		err1 = write_to_buffer_end(&buf, &proh1, output);
		unprohibit_buffer(&buf, &proh1);
	}

	int flag2 = try_prohibit_buffer_end(&buf, &proh2);
	if (flag2) {
		err2 = write_to_buffer_end(&buf, &proh2, (char *)output + 3);
		unprohibit_buffer(&buf, &proh2);
	}

	
	if (err1 || err2 || buf.end_read != buf.base_begin || buf.end != buf.base_begin || buf.stop_pos || memcmp(buf.base_begin, output, 6)) {
		trace_printk("err1 = %d, err2 = %d, base_begin = %p, begin = %p, end_read = %p, end = %p, buf.stop_pos = %p, delta_read = %ld, delta_write = %ld\noutput=%3s\n", err1, err2, buf.base_begin, buf.begin, buf.end_read, buf.end, buf.stop_pos, ((char *)buf.end_read) - (char *)buf.base_begin, ((char *)buf.end) - (char *)buf.base_begin, (char *)buf.base_begin);
		return EXPECT;
	}
	return ASSERT;
}
//TODO: Надо проверить функции записи и чтения на

test_result_t stest_write_and_check_position_correct(void) {
	struct ps_buffer buf;
	struct ps_prohibition proh;
	struct ps_position pos;
	char output[6] = {'a', 'b', 'c', 'd', 'e', 'f'};
	int err1 = 0, incorrect = 0;

	init_buffer(&buf, 2, 3);
	int flag = try_prohibit_buffer_end(&buf, &proh);
	if (flag) {
		err1 = write_to_buffer_end(&buf, &proh, output);
		unprohibit_buffer(&buf, &proh);
	}
	push_used_position_begin(&buf, &pos);
	incorrect = is_position_incorrect(&buf, &pos);
	if (!flag || err1 || incorrect) {
		trace_printk("flag = %d, err1 = %d, incorrect = %d\n", flag, err1, incorrect);
		return EXPECT;
	}
	return ASSERT;
}

test_result_t stest_write_and_check_position_correct_read_update(void) {
	struct ps_buffer buf;
	struct ps_prohibition proh;
	struct ps_position pos;
	char output[6] = {'a', 'b', 'c', 'd', 'e', 'f'};
	char input[6] = {'1', '1', '1', '1', '1', '1'};
	int err1 = 0, incorrect = 0;
	int flag2 = 0;

	init_buffer(&buf, 2, 3);
	int flag1 = try_prohibit_buffer_end(&buf, &proh);
	if (flag1) {
		err1 = write_to_buffer_end(&buf, &proh, output);
		unprohibit_buffer(&buf, &proh);
	}
	push_used_position_begin(&buf, &pos);
	incorrect = is_position_incorrect(&buf, &pos);
	int err2 = read_from_buffer_at_position(&buf, &pos, input);
	int err3 = 0;
	struct ps_position *new_pos = find_next_position(&buf, &pos);
	if (!new_pos) {
		new_pos = find_free_position(&buf);
		if (new_pos) {
			pop_free_position(&buf, new_pos);
			push_used_position_after(&buf, new_pos, &pos);
		} else {
			err3 = -ENOSPC;
		}
	}
	if (!err3) {
		//connect_subscriber_position(sub, new_pos);
		//disconnect_subscriber_position(sub, pos);
		flag2 = is_position_used(&buf, &pos);
		if (!flag2) {
			pop_used_position(&buf, &pos);
			push_free_position(&buf, &pos);
		}
	}

	if (!flag1 || flag2 || err1 || err2 || err3 || incorrect || !new_pos || memcmp(input, output, 3)) {
		trace_printk("flag1 = %d, flag2 = %d, err1 = %d, err2 = %d, err3 = %d, new_pos = %p, incorrect = %d\n input = %3s, output = %3s\n", flag1, flag2, err1, err2, err3, new_pos, incorrect, input, output);
		return EXPECT;
	}
	return ASSERT;
}

//TODO: Сделать функции, которые проверяют работу send и receive
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

	int flag = memcmp(input, output, 10);
	if(err1 || err2 || err3 || err4 || err5 || err6 || flag || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, err6 == %d, flag = %d, id == %lu,\n input:\"%10s\", output:\"%10s\"\n", err1, err2, err3, err4, err5, err6, flag, id, input, output);
		return EXPECT;
	}
	return SUCCESS;
}

//TODO: Надо протестировать функции работы буфера
test_result_t ftest_send_receive_doubled(void) {
	unsigned long id = 0;
	char output[20] = {'0', '9', '1', '2', '3', '4', '5', '6', '7', '8', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
	char input[20] = {'\0'};
	trace_puts("BEGIN\n");

	int err1 = ps_node_create(2, 10, &id);
	int err2 = ps_node_publish(id);
	int err3 = ps_node_send(id, output);
	int err4 = ps_node_send(id, &output[10]);
	int err5 = ps_node_subscribe(id);
	int err6 = ps_node_receive(id, input);
	int err7 = ps_node_receive(id, &input[10]);
	int err8 = ps_node_delete(id);

	int flag = memcmp(input, output, 20);
	if(err1 || err2 || err3 || err4 || err5 || err6 || err7 || err8 || flag || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, err6 == %d, err7 == %d, err8 == %d, flag = %d, id == %lu,\n input:\"%20s\", output:\"%20s\"\n", err1, err2, err3, err4, err5, err6, err7, err8, flag, id, input, output);
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

	int flag1 = memcmp(input, output + 20, 10);
	int flag2 = memcmp(input + 10, output + 10, 10);
	if(err1 || err2 || err3 || err4 || err5 || err6 || err7 || err8 || !err9 || err10 || flag1 || flag2 || !id) {
		trace_printk("err1 == %d, err2 == %d, err3 == %d, err4 == %d, err5 == %d, err6 == %d, err7 == %d, err8 == %d, err9 == %d, err10 == %d, flag1 = %d, flag2 = %d, id == %lu,\n input:\"%30s\", output:\"%20s\"\n", err1, err2, err3, err4, err5, err6, err7, err8, err9, err10, flag1, flag2, id, input, output);
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
	stest_find_free_position_pop();
	stest_find_free_position_pop_double();
	stest_send_inside();
	stest_send_inside_double();
	stest_write_and_check_position_correct();
	*/
	stest_write_and_check_position_correct_read_update();
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
	ftest_send_receive_doubled();
	ftest_send_recevie_tripled_without_subscribe();
	ftest_send_receive_tripled_with_subscribe();
	/*
	*/
	return 0;
}

static void __exit pubsub_exit(void)
{
}

module_init(pubsub_init);
module_exit(pubsub_exit);
