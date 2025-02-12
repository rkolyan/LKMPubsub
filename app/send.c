#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "ps_syscall.h"

static unsigned long id = 0;
static int end = 1;

void my_handler(int signum) {
	end = 0;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		puts("Правильно: ./send <ID node>\n");
		return 0;
	}
	puts("hello\n");
	id = strtoul(argv[1], NULL, 10);
	int err = ps_node_publish(id);
	char buf[11];
	printf("ps_node_publish:err=%d\n", err);
	if (err) {
		return 0;
	}
	srand(time(NULL));
	signal(SIGINT, my_handler);
	while(end){
		snprintf(buf, 11, "%10d", rand());
		err = ps_node_send(id, buf);
		printf("ps_node_send:err=%d\tbuf=%s\n", err, buf);
		sleep(1);
	}
	err = ps_node_unpublish(id);
	printf("ps_node_unpublish:err=%d\n", err);
	puts("goodbye\n");
	return 0;
}
