//
// Created by rkolyan on 13.01.2025.
//

#include <kunit/test.h>

#include "buffer.h"

static struct ps_buffer *buf;

//TODO: Для тестов исправить copy_to_user, copy_from_user на memcpy

static void test_write_buffer_simple(struct kunit *test) {
    char str[2] = {'a', 'b'};
    int err = 0;

    write_to_buffer(buf, (void *) str);

    KUNIT_EXPECT_EQ(is_buffer_full(buf), 0);
    KUNIT_EXPECT_EQ(buf->begin_num, 0);
    KUNIT_EXPECT_EQ(buf->end_num, 2);
    KUNIT_EXPECT_EQ((*(char *)buf->base_begin), 'a');
    KUNIT_EXPECT_EQ(*(((char *)buf->base_begin) + 1), 'b');
}

static void test_write_buffer_overflow(struct kunit *test) {
    char str[8] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    int err = 0;

    write_to_buffer(buf, (void *) str);

    KUNIT_EXPECT_EQ(is_buffer_full(buf), 0);
    KUNIT_EXPECT_EQ(buf->begin_num, 2);
    KUNIT_EXPECT_EQ(buf->end_num, 8);
    KUNIT_EXPECT_EQ((*(char *)buf->base_begin), 'g');
    KUNIT_EXPECT_EQ(*(((char *)buf->base_begin) + 1), 'h');
    KUNIT_EXPECT_EQ((*(char *)buf->base_begin), 'c');
    KUNIT_EXPECT_EQ(*(((char *)buf->base_begin) + 1), 'd');
    KUNIT_EXPECT_EQ((*(char *)buf->base_begin), 'e');
    KUNIT_EXPECT_EQ(*(((char *)buf->base_begin) + 1), 'f');
}

#define BLOCK_SIZE 3

static void _test_msg_to_addr_begin_end_less_bigger(void) {
    //1.1)Когда end_num > begin_num
    void *addr = NULL;
    buf->base_begin_num = -1;
    buf->begin_num = 2;
    buf->begin = buf->base_begin + (buf->begin_num - buf->base_begin_num) * BLOCK_SIZE;
    buf->end_num = 5;
    buf->end = buf->base_begin + (buf->end_num - buf->base_begin_num) * BLOCK_SIZE;

    int err = msg_num_to_addr(buf, 4, addr);

    KUNIT_EXPECT_EQ(err, 0);
    KUNIT_EXPECT_EQ(addr, buf->begin + 2 * BLOCK_SIZE);

    KUNIT_EXPECT_EQ(msg_num_to_addr(buf, 6, addr), -ENOENT);
    KUNIT_EXPECT_EQ(msg_num_to_addr(buf, 1, addr), -ENOENT);
}

static void _test_msg_to_addr_begin_end_bigger_less(void) {
    //1.1)Когда end_num < begin_num (Такое возможно в случае переполнения)
    void *addr = NULL;
    buf->base_begin_num = 0x7FFFFFFF - 3;
    buf->begin_num = 0x7FFFFFFF - 1;
    buf->begin = buf->base_begin + (buf->begin_num - buf->base_begin_num) * BLOCK_SIZE;
    buf->end_num = 0x7FFFFFFF + 2;
    buf->end = buf->base_begin + (buf->end_num - buf->base_begin_num) * BLOCK_SIZE;

    int err = msg_num_to_addr(buf, Ox7FFFFFFF+1, addr);

    KUNIT_EXPECT_EQ(err, 0);
    KUNIT_EXPECT_EQ(addr, buf->begin + 2 * BLOCK_SIZE);

    KUNIT_EXPECT_EQ(msg_num_to_addr(buf, 0x7FFFFFFF - 2, addr), -ENOENT);
    KUNIT_EXPECT_EQ(msg_num_to_addr(buf, 0x7FFFFFFF + 3, addr), -ENOENT);
}

static void _test_msg_to_addr_end_begin_less_bigger(void) {
    void *addr = NULL;
    buf->base_begin_num = 1;
    buf->begin_num = 6;
    buf->begin = buf->base_begin + (buf->begin_num - buf->base_begin_num) * BLOCK_SIZE;
    buf->end_num = 9;
    //TODO: Можно сделать типо buf->end_num - buf->begin_base_num % (base_end_num - base_begin_num);
    buf->end = buf->base_begin + BLOCK_SIZE;

    int err = msg_num_to_addr(buf, 8, &addr);

    KUNIT_EXPECT_EQ(err, 0);
    KUNIT_EXPECT_EQ(addr, buf->base_begin);

    err = msg_num_to_addr(buf, 7, &addr);

    KUNIT_EXPECT_EQ(err, 0);
    KUNIT_EXPECT_EQ(addr, buf->base_end);
}

static void _test_msg_to_addr_end_begin_bigger_less(void) {
    void *addr = NULL;
    buf->base_begin_num = 0x7FFFFFFF-8;
    buf->begin_num = 0x7FFFFFFF - 2;
    buf->begin = buf->base_begin + (buf->begin_num - buf->base_begin_num) * BLOCK_SIZE;
    buf->end_num = 0x7FFFFFFF + 2;
    buf->end = buf->base_begin + 3 * BLOCK_SIZE;

    int err = msg_num_to_addr(buf, 0x7FFFFFFF - 1, &addr);

    KUNIT_EXPECT_EQ(err, 0);
    KUNIT_EXPECT_EQ(addr, buf->base_end);

    err = msg_num_to_addr(buf, 0x7FFFFFFF, &addr);

    KUNIT_EXPECT_EQ(err, 0);
    KUNIT_EXPECT_EQ(addr, buf->base_begin);
}

static void test_msg_to_addr(struct kunit *test) {
    init_buffer(buf, 21, BLOCK_SIZE, 0);
    _test_msg_to_addr_begin_end_less_bigger();
    _test_msg_to_addr_begin_end_bigger_less();
    _test_msg_to_addr_end_begin_less_bigger();
    _test_msg_to_addr_end_begin_bigger_less();
    deinit_buffer(buf);
}

static void test_read_buffer_simple(struct kunit *test) {
    char *str = (char *)(buf->base_begin + buf->blk_size);
    char str2[2] = {'\0'};
    str[0] = 'a';
    str[1] = 'b';
    buf->begin_num = 0;
    buf->base_begin_num = 0;
    buf->begin = buf->base_begin;
    buf->end_num = 2;
    buf->end = buf->begin + 2 * buf->blk_size;

    int err = read_from_buffer(buf, 1, str2);

    KUNIT_EXPECT_EQ(test, err, 0);
    KUNIT_EXPECT_EQ(test, str2[0], 'a');
    KUNIT_EXPECT_EQ(test, str2[1], 'b');
}

static struct kunit_case buffer_test_cases = {
        KUNIT_CASE(test_write_buffer_simple),
        KUNIT_CASE(test_write_buffer_overflow),
        KUNIT_CASE(test_msg_to_addr),
        KUNIT_CASE(test_read_buffer_simple),
        {}
};

int buffer_test_init(struct kunit *test) {
    init_buffer(buf, 6, 2, 1);
    return 0;
}

void buffer_test_exit(struct kunit *test) {
    deinit_buffer(buf);
}

int buffer_suite_init(struct kunit_suite *suite) {
    //Выделение памяти для буфера
    buf = vmalloc(sizeof(struct ps_buffer));
    return 0;
}

void buffer_suite_exit(struct kunit_suite *suite) {
    //Очистка памяти буфера
    vfree(buf);
}

static struct kunit_suite buffer_test_suite = {
        .name = "Testing buffer",
        .suite_init = buffer_suite_init,
        .suite_exit = buffer_suite_exit,
        .init = buffer_test_init,
        .exit = buffer_test_exit,
        .test_cases = buffer_test_cases
};
kunit_test_suite(buffer_test_suite);

MODULE_LICENSE("GPL");
