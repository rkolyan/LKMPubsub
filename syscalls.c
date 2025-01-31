#include "node.h"

#include <linux/linkage.h>
#include <linux/kprobes.h>

asmlinkage long sys_ps_node_create(size_t buf_size, size_t buf_block_size, unsigned long __user *result) {
	struct ps_node *node = NULL;
	int err = create_node_struct(buf_size, buf_block_size, &node);
	if (err) {
		//pr_err(__func__ ":Нельзя добавить топик!");
		return err;
	}
	ps_nodes_write_lock();
	add_node(node);
	get_node_id(node, result);
	ps_nodes_write_unlock();
	return 0;
}

asmlinkage long sys_ps_node_delete(unsigned long node_id) {
	struct ps_node *node = NULL;
	long err = 0;
	ps_nodes_write_lock();
	err = find_node(node_id, &node);
	if (!err)
		remove_node(node);
	ps_nodes_write_unlock();
	if (!err) {
		ps_current_write_wait(node);
		//TODO: Доделать delete_node
		err = delete_node_struct(node);
	}
	return err;
}


asmlinkage long sys_ps_node_subscribe(unsigned long node_id) {
	unsigned long sub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_subscriber *sub = NULL;
    struct ps_position *pos = NULL;

    err = create_subscriber_struct(sub_id, &sub);
    if (err)
        return err;
    err = create_position_struct(&pos);
    if (err) {
        delete_position_struct(pos);
        return -ENOMEM;
    }

	ps_nodes_read_lock();

	err = find_node(node_id, &node);
	if (!err)
		ps_current_read_lock(node);

	ps_nodes_read_unlock();

	if (!err) {
		err = find_subscriber_in_node(node, sub_id, &sub);
		if (err == ENOENT) {
            add_position_in_node(node, pos);
            add_subscriber_in_node(node, sub);
		}
		ps_current_read_unlock(node);
	}
    if (err) {
        delete_position_struct(pos);
        delete_subscriber_struct(sub);
    }
	return err;
}

asmlinkage long sys_ps_node_unsubscribe(unsigned long node_id) {
	unsigned long sub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_subscriber *sub = NULL;
    struct ps_position *pos = NULL;
	ps_nodes_read_lock();

	err = find_node(node_id, &node);
	if (!err)
		ps_current_read_lock(node);

	ps_nodes_read_unlock();

	if (!err) {
		err = find_subscriber_in_node(node, sub_id, &sub);
		if (!err) {
            remove_subscriber_in_node(node, sub);
            remove_position_in_node(node);
        }
		ps_current_read_unlock(node);
        if (!err) {
            delete_position_struct(pos);
            delete_subscriber_struct(sub);
        }
	}
	return err;
}

asmlinkage long sys_ps_node_publish(unsigned long node_id) {
	unsigned long pub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_publisher *pub = NULL;
    err = create_publisher_struct(pub_id, &pub);
    if (!err) {
        return err;
    }

	ps_nodes_read_lock();

	err = find_node(node_id, &node);
	if (!err) {
        ps_current_read_lock(node);
    }
	ps_nodes_read_unlock();

	if (!err) {
		err = find_publisher_in_node(node, pub_id, &pub);
		if (err == ENOENT) {
            err = add_publisher_in_node(node, pub);
		}
		ps_current_read_unlock(node);
	}
    if (err) {
        delete_publisher_struct(pub);
    }
	return err;
}

asmlinkage long sys_ps_node_unpublish(unsigned long node_id) {
	unsigned long pub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_publisher *pub = NULL;

	ps_nodes_read_lock();

	err = find_node(node_id, &node);
	if (!err)
		ps_current_read_lock(node);

	ps_nodes_read_unlock();

	if (!err) {
		err = find_publisher_in_node(node, pub_id, &pub);
		if (!err) {
            remove_publisher_in_node(node, pub);
        }
		ps_current_read_unlock(node);
	}

    if (!err) {
        delete_publisher_struct(pub);
    }
	return err;
}

asmlinkage long sys_ps_node_send(unsigned long node_id, void __user *info) {
	unsigned long pub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_publisher *pub = NULL;

	ps_nodes_read_lock();

	err = find_node(node_id, &node);
	if (!err)
		ps_current_read_lock(node);

	ps_nodes_read_unlock();

	if (!err) {
		err = find_publisher_in_node(node, pub_id, &pub);
		if (!err)
			err = send_message_to_node(node, pub, info);
		ps_current_read_unlock(node);
	}
	return err;
}

asmlinkage long sys_ps_node_recv(unsigned long node_id, void __user *info) {
	unsigned long sub_id = current->pid;
	int err = 0;
	struct ps_node *node = NULL;
	struct ps_subscriber *sub = NULL;

	ps_nodes_read_lock();

	err = find_node(node_id, &node);
	if (!err)
		ps_current_read_lock(node);

	ps_nodes_read_unlock();

	if (!err) {
		err = find_subscriber_in_node(node, sub_id, &sub);
		if (!err)
			err = receive_message_from_node(node, sub, info);
		ps_current_read_unlock(node);
	}
	return err;
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
    pr_info("Список свободных номеров обработчиков системных вызовов:");
    int j = 0;
    for (; j < NODE_SYSCALL_COUNT; j++) {
        pr_info("%d ", inds[j]);
    }
}

static int hook_handlers(void) {
    syscall_table[inds[NR_node_create]] = sys_ps_node_create;
    syscall_table[inds[NR_node_delete]] = sys_ps_node_delete;
    syscall_table[inds[NR_node_publish]] = sys_ps_node_publish;
    syscall_table[inds[NR_node_unpublish]] = sys_ps_node_unpublish;
    syscall_table[inds[NR_node_subscribe]] = sys_ps_node_subscribe;
    syscall_table[inds[NR_node_unsubscribe]] = sys_ps_node_unsubscribe;
    syscall_table[inds[NR_node_recv]] = sys_ps_node_recv;
    syscall_table[inds[NR_node_send]] = sys_ps_node_send;
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
    int i = NR_node_create;
    for (; i < NODE_SYSCALL_COUNT; i++) {
        syscall_table[inds[i]] = sys_ni_syscall_addr;
    }
    return 0;
}