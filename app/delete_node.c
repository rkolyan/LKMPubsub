#include <stdio.h>
#include <stdlib.h>

#include "ps_syscall.h"

int main(int argc, char **argv) {
	if (argc == 2) {
		unsigned long id = strtoul(argv[1], NULL, 10);
		puts(argv[0]);
		putchar('\n');
		puts(argv[1]);
		putchar('\n');
		int err = ps_node_delete(id);
		printf("err = %d, id = %lu\n", err, id);
	}
	return 0;
}
