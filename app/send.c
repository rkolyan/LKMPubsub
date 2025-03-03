#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>

#include "ps_syscall.h"

int flag = 1;

void handler(int signum) {
	if (signum == SIGINT)
		flag = 0;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		puts("Неверный ввод команды, введите:\n./send.out <номер узла>");
		return 0;
	}
	signal(SIGINT, handler);
	unsigned long id = strtoul(argv[1], NULL, 10);
	int err = ps_node_publish(id);
	printf("ps_node_publish:err = %d\n", err);
	if (err) {
		puts("id not found");
		return 0;
	}
	char buf[11] = {'\0'};
	srand(time(NULL));
	while (flag) {
		sprintf(buf, "%10d", rand());
		err = ps_node_send(id, buf);
		printf("ps_node_send:err = %d\tbuf = %10s\n", err, buf);
		//sleep(1);
	}
	err = ps_node_unpublish(id);
	printf("ps_node_publish:err = %d\n", err);
	return 0;
}
