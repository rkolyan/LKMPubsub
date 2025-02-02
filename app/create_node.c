#include <stdio.h>

#include "ps_syscall.h"

#define BUF_SIZE 20
#define BLOCK_SIZE 10

int main(void) {
	unsigned long id = 0;
	int err = ps_node_create((size_t)BUF_SIZE, (size_t)BLOCK_SIZE, &id);
	printf("err = %d, id = %lu\n", err, id);
	return 0;
}
