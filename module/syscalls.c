#include <linux/linkage.h>
#include <linux/kprobes.h>

#include "syscalls.h"
#include "functions.h"

enum {
	NR_node_create = 0,//Создать узел PubSub
	NR_node_delete,//Удалить узел PubSub
	NR_node_subscribe, //Подписаться как получатель
	NR_node_unsubscribe, //Отписаться как получатель
	NR_node_publish, //Подписаться как отправитель
	NR_node_unpublish, //Отписаться как отправитель
	NR_node_send, //Отправить сообщение
	NR_node_recv, //Принять сообщение
	NODE_SYSCALL_COUNT
};

#define SYSCALL_TABLE_SIZE 450

static void **syscall_table = NULL, *sys_ni_syscall_addr = NULL;
static int inds[NODE_SYSCALL_COUNT];

static int sys_ni_syscall_kretprobe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	//Хохма в том, что там идет перехват функции, у которой в качестве аргумента был указатель на pt_regs
	struct pt_regs *cur = (struct pt_regs *)(regs->di);
	trace_printk("regs->ax = %ld, regs->orig_ax = %ld\n", regs->ax, regs->orig_ax);
	if (regs->si == inds[NR_node_create]) {
		regs->ax = ps_node_create((size_t)cur->di, (size_t)cur->si, (unsigned long __user *)cur->dx);
	} else if (regs->si == inds[NR_node_delete]) {
		regs->ax = ps_node_delete((unsigned long)cur->di);
	} else if (regs->si == inds[NR_node_subscribe]) {
		regs->ax = ps_node_subscribe((unsigned long)cur->di);
	} else if (regs->si == inds[NR_node_unsubscribe]) {
		regs->ax = ps_node_unsubscribe((unsigned long)cur->di);
	} else if (regs->si == inds[NR_node_publish]) {
		regs->ax = ps_node_publish((unsigned long)cur->di);
	} else if (regs->si == inds[NR_node_unpublish]) {
		regs->ax = ps_node_unpublish((unsigned long)cur->di);
	} else if (regs->si == inds[NR_node_send]) {
		regs->ax = ps_node_send((unsigned long)cur->di, (void __user *)cur->si);
	} else if (regs->si == inds[NR_node_recv]) {
		regs->ax = ps_node_recv((unsigned long)cur->di, (void __user *)cur->si);
	}
	return 0;
}

struct kretprobe syscall_kretprobe = {
	.kp.symbol_name = "__x64_sys_ni_syscall",
	.handler = sys_ni_syscall_kretprobe_handler
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static int find_syscall_table(void) {
	kallsyms_lookup_name_t kallsyms_lookup_name = NULL;
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	//struct kprobe kp = { .symbol_name = "sys_call_table" };
	int err = register_kprobe(&kp);
	if (!err) {
		//pr_info("Адрес sys_call_table найден!!");
		kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
		syscall_table = (void **)kallsyms_lookup_name("sys_call_table");
		unregister_kprobe(&kp);
	}
	return err;
}

static int find_ni_syscall_addr(void) {
    int i = 0;
    for (; i < SYSCALL_TABLE_SIZE-1; i++) {
        if (syscall_table[i] == syscall_table[i+1]) {
            sys_ni_syscall_addr = syscall_table[i];
	    break;
        }
    }
    return register_kretprobe(&syscall_kretprobe);
}

static int find_free_indexes(void) {
	int j = 0, i = 0, err = 0;
	for (; i < SYSCALL_TABLE_SIZE && j < NODE_SYSCALL_COUNT; i++) {
		if (syscall_table[i] == sys_ni_syscall_addr) {
			inds[j] = i;
			j++;
		}
	}
	if (j < NODE_SYSCALL_COUNT) {
		err = -ERANGE;
	}
	return err;
}

static inline void print_free_indexes (void) {
	trace_puts("bzhe_print_free_indexes\n");
	pr_info("Список свободных номеров обработчиков системных вызовов:");
	int j = 0;
	for (; j < NODE_SYSCALL_COUNT; j++)
		trace_printk("bzhe %d\n", inds[j]);
	trace_puts("\nbzhe_print_free_indexes\n");
}

int hook_functions(void) {
	find_syscall_table();
	find_ni_syscall_addr();
	find_free_indexes();
	print_free_indexes();
	return 0;
}

int unhook_functions(void) {
	unregister_kretprobe(&syscall_kretprobe);
	return 0;
}
