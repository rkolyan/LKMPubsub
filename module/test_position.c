//
// Created by rkolyan on 14.01.2025.
//

#include <kunit/test.h>

#include "position.h"

struct ps_positions_desc desc;

int position_suite_init(struct kunit_suite *suite) {
    //Выделение памяти для буфера
    init_positions_desc(&desc);
    return 0;
}

void position_suite_exit(struct kunit_suite *suite) {
    //Очистка памяти буфера
    deinit_positions_desc(&desc);
}

static struct kunit_case position_test_cases = {
        {}
};

static struct kunit_suite position_test_suite = {
        .name = "Testing position",
        .suite_init = position_suite_init,
        .suite_exit = position_suite_exit,
        .test_cases = position_test_cases
};
kunit_test_suite(position_test_suite);

MODULE_LICENSE("GPL");
