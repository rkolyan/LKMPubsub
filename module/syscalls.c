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
	NR_node_receive, //Принять сообщение
	NODE_SYSCALL_COUNT
};

#define SYSCALL_TABLE_SIZE 450

static void **syscall_table = NULL, *sys_ni_syscall_addr = NULL;
static int inds[NODE_SYSCALL_COUNT];

static int sys_ni_syscall_handler(struct pt_regs *regs)
{
	int err = -ENOSYS;
	if (regs->orig_ax == inds[NR_node_create]) {
		err = ps_node_create((size_t)regs->di, (size_t)regs->si, (unsigned long __user *)regs->dx);
	} else if (regs->orig_ax == inds[NR_node_delete]) {
		err = ps_node_delete((unsigned long)regs->di);
	} else if (regs->orig_ax == inds[NR_node_subscribe]) {
		err = ps_node_subscribe((unsigned long)regs->di);
	} else if (regs->orig_ax == inds[NR_node_unsubscribe]) {
		err = ps_node_unsubscribe((unsigned long)regs->di);
	} else if (regs->orig_ax == inds[NR_node_publish]) {
		err = ps_node_publish((unsigned long)regs->di);
	} else if (regs->orig_ax == inds[NR_node_unpublish]) {
		err = ps_node_unpublish((unsigned long)regs->di);
	} else if (regs->orig_ax == inds[NR_node_send]) {
		err = ps_node_send((unsigned long)regs->di, (void __user *)regs->si);
	} else if (regs->orig_ax == inds[NR_node_receive]) {
		err = ps_node_receive((unsigned long)regs->di, (void __user *)regs->si);
	}
	return err;
}

int make_trampoline(void) {
	long offset = (long)((void *)sys_ni_syscall_handler - (sys_ni_syscall_addr + 5));
	char operation[] = {0xE8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
	*((int *)(operation + 1)) = offset;
	unsigned long cr0 = read_cr0();
	cr0 &= (~0x10000);
	asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
	memcpy(sys_ni_syscall_addr, operation, 7);
	asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
	trace_puts("init закончил\n");
	return 0;
}

void unmake_trampoline(void) {
        char operation[] = {0x48, 0xc7, 0xc0, 0xda, 0xff, 0xff, 0xff};
        unsigned long cr0 = read_cr0();
        cr0 &= (~0x10000);
        asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
        memcpy(sys_ni_syscall_addr, operation, 7);
        asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
}

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
	struct kprobe kp = { .symbol_name = "__x64_sys_ni_syscall" };
	int err = register_kprobe(&kp);
	if (err) {
		trace_puts("Не получилось этот адрес определить!\n");
		return err;
	}
	sys_ni_syscall_addr = kp.addr;
	unregister_kprobe(&kp);
	return 0;
}

static int find_free_indexes(void) {
	//TODO: Может здесь засунуть поиск sys_call_table
	void *addr = sys_ni_syscall_addr;
	int count = 0;
	for (unsigned int i = 0; i < SYSCALL_TABLE_SIZE; i++) {
		count = 0;
		for (unsigned int j = i + 1; j < SYSCALL_TABLE_SIZE; j++ ) {
			if (syscall_table[i] == syscall_table[j]) {
				count++;
			}
			if (count == 2) {
				break;
			}
		}
		if (count == 2) {
			addr = syscall_table[i];
			break;
		}
	}
	int j = 0, i = 0, err = 0;
	for (; i < SYSCALL_TABLE_SIZE && j < NODE_SYSCALL_COUNT; i++) {
		if (syscall_table[i] == addr) {
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
	int j = 0;
	for (; j < NODE_SYSCALL_COUNT; j++)
		trace_printk("bzhe %d\n", inds[j]);
	trace_puts("bzhe_print_free_indexes\n");
}

int hook_functions(void) {
	int err = find_ni_syscall_addr();
	if (err)
		return err;
	err = find_syscall_table();
	if (err)
		return err;
	err = find_free_indexes();
	if (err)
		return err;
	err = make_trampoline();
	if (err)
		return err;
	print_free_indexes();
	return 0;
}

void unhook_functions(void) {
	unmake_trampoline();
}
