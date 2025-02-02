#include <linux/linkage.h>
#include <linux/kprobes.h>

#include "functions.h"

asmlinkage long sys_ps_node_create(struct pt_regs *regs) {
	return ps_node_create((size_t)regs->di, (size_t)regs->si, (unsigned long __user *)regs->dx);
}

asmlinkage long sys_ps_node_delete(struct pt_regs *regs) {
	return ps_node_delete((unsigned long)regs->di);
}

asmlinkage long sys_ps_node_subscribe(struct pt_regs *regs) {
	return ps_node_subscribe((unsigned long)regs->di);
}

asmlinkage long sys_ps_node_unsubscribe(struct pt_regs *regs) {
    return ps_node_unsubscribe((unsigned long)regs->di);
}

asmlinkage long sys_ps_node_publish(struct pt_regs *regs) {
    return ps_node_publish((unsigned long)regs->di);
}

asmlinkage long sys_ps_node_unpublish(struct pt_regs *regs) {
    return ps_node_unpublish((unsigned long)regs->di);
}

asmlinkage long sys_ps_node_send(struct pt_regs *regs) {
    return ps_node_send((unsigned long)regs->di, (void __user *)regs->si);
}

asmlinkage long sys_ps_node_recv(struct pt_regs *regs) {
    return ps_node_recv((unsigned long)regs->di, (void __user *)regs->si);
}

//////////////////////////////////////////////////////////

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
    return 0;
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
    for (; j < NODE_SYSCALL_COUNT; j++) {
        trace_printk("bzhe %d ", inds[j]);
    }
    trace_puts("\nbzhe_print_free_indexes\n");
}

//В связи с тем, что в ядре выше версии 5.3 удалили write_cr0
static void write_cr0_unsafe(unsigned long val)
{
    asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");
}

static int hook_handlers(void) {
	unsigned long old_cr0 = 0;
    trace_puts("bzhe_begin");
    trace_printk("bzhe sys_call_table = %p\n sys_ni_syscall = %p\n", syscall_table, sys_ni_syscall_addr);
    old_cr0 = read_cr0();
    write_cr0_unsafe(old_cr0 & ~(X86_CR0_WP));
    syscall_table[inds[NR_node_create]] = sys_ps_node_create;
    syscall_table[inds[NR_node_delete]] = sys_ps_node_delete;
    syscall_table[inds[NR_node_publish]] = sys_ps_node_publish;
    syscall_table[inds[NR_node_unpublish]] = sys_ps_node_unpublish;
    syscall_table[inds[NR_node_subscribe]] = sys_ps_node_subscribe;
    syscall_table[inds[NR_node_unsubscribe]] = sys_ps_node_unsubscribe;
    syscall_table[inds[NR_node_recv]] = sys_ps_node_recv;
    syscall_table[inds[NR_node_send]] = sys_ps_node_send;
    write_cr0_unsafe(old_cr0);
    trace_puts("ura_bzhe_end");
    return 0;
}

int hook_functions(void) {
    find_syscall_table();
    find_ni_syscall_addr();
    find_free_indexes();
    print_free_indexes();
    hook_handlers();
    return 0;
}

int unhook_functions(void) {
	unsigned long old_cr0 = 0;
    int i = 0;
    old_cr0 = read_cr0();
    write_cr0_unsafe(old_cr0 & ~(X86_CR0_WP));
    for (; i < NODE_SYSCALL_COUNT; i++) {
        syscall_table[inds[i]] = sys_ni_syscall_addr;
    }
    write_cr0_unsafe(old_cr0);
    return 0;
}
