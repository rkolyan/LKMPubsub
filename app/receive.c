#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#include "ps_syscall.h"

int flag = 1;

void handler(int signum) {
	if (signum == SIGINT)
		flag = 0;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		puts("Неверный ввод команды, введите:\n./receive.out <номер узла>");
		return 0;
	}
	signal(SIGINT, handler);
	unsigned long id = strtoul(argv[1], NULL, 10);
	int err = ps_node_subscribe(id);
	printf("ps_node_subscribe:err = %d\n", err);
	if (err) {
		puts("id not found");
		return 0;
	}
	char buf[11] = {'\0'};
	while (flag) {
		err = ps_node_receive(id, buf);
		printf("ps_node_receive:err = %d\tbuf = %10s\n", err, buf);
		sleep(1);
	}
	err = ps_node_unsubscribe(id);
	printf("ps_node_unsubscribe:err = %d\n", err);
	return 0;
}
