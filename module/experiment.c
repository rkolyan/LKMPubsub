#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/preempt.h>
#include <asm/special_insns.h>

static int entry_handler(struct pt_regs *regs) {
	trace_printk("Атомарный контекст:%d\tКонтекст прерывания:%d\tКонтекст процесса:%d\n", in_atomic(), in_interrupt(), in_task());
	trace_printk("regs->di = %lx, regs->si = %lx, regs->dx = %lx\n", regs->di, regs->si, regs->dx);
	return -ENOENT;
}

void *addr1;

static int __init my_module_init(void) {
	//TODO: 1)Определяем адрес __x64_sys_ni_syscall (это можно сделать при помощи kprobe)
	struct kprobe kp = { .symbol_name = "__x64_sys_ni_syscall" };
	int err = register_kprobe(&kp);
	if (!err)
		trace_puts("Не получилось этот адрес определить!\n");
	addr1 = kp.addr;
       	void *addr2 = (void *)entry_handler;
	unregister_kprobe(&kp);
	//TODO: 2)Вычисляем смещение от entry_handler до адреса __x64_sys_ni_syscall
	long offset = (long)(addr2 - (addr1 + 5));
	//TODO: 3)Записываем E9 + 4 байта в буфер
	char operation[] = {0xE9, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
	*((int *)(operation + 1)) = offset;
	//TODO: 4)Отключаем CR0
	unsigned long cr0 = read_cr0();
	cr0 &= (~0x10000);
	asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
	memcpy(addr1, operation, 7);
	asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
	trace_puts("init закончил\n");
	return 0;
}

static void __exit my_module_exit(void) {
	char operation[] = {0x48, 0xc7, 0xc0, 0xda, 0xff, 0xff, 0xff};
	unsigned long cr0 = read_cr0();
	cr0 &= (~0x10000);
	asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
	memcpy(addr1, operation, 7);
	asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
	trace_printk("Module unload\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ваше имя");
