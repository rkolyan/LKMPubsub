//
// Created by rkolyan on 02.02.2025.
//

#include "node.h"

long ps_node_create(size_t buf_size, size_t block_size, unsigned long __user *result) {
    struct ps_node *node = NULL;
    //trace_printk("begin buf_size = %lu, block_size = %lu, result = %p\n", buf_size, block_size, result);
    int err = create_node_struct(buf_size, block_size, &node);
    //trace_printk("after create_node_struct:%d,%p\n", err, node);
    if (err) {
    //pr_err(__func__ ":Нельзя добавить топик!");
        return err;
    }
    ps_nodes_write_lock();
    add_node(node);
    get_node_id(node, result);
    ps_nodes_write_unlock();
    //trace_printk("end\n");
    return 0;
}

long ps_node_delete(unsigned long node_id) {
    struct ps_node *node = NULL;
    long err = 0;
    ps_nodes_write_lock();
    trace_printk("begin node_id = %lu\n", node_id);
    err = find_node(node_id, &node);
    trace_printk("after find_node err = %ld, node = %p\n", err, node);
    if (!err) {
        remove_node(node);
        trace_puts("after remove_node\n");
    }
    trace_puts("before ps_nodes_write_unlock\n");
    ps_nodes_write_unlock();
    trace_puts("after ps_nodes_write_unlock\n");
    if (!err) {
        ps_current_write_wait(node);
        trace_puts("after ps_current_write_wait\n");
        //TODO: Доделать delete_node
        trace_puts("before delete_node_struct\n");
        err = delete_node_struct(node);
        trace_puts("after delete_node_struct\n");
    }
    return err;
}

long ps_node_subscribe(unsigned long node_id) {
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

long ps_node_unsubscribe(unsigned long node_id) {
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

long ps_node_publish(unsigned long node_id) {
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

long ps_node_unpublish(unsigned long node_id) {
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

long ps_node_send(unsigned long node_id, void __user *info) {
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

long ps_node_recv(unsigned long node_id, void __user *info) {
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