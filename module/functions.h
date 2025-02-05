//
// Created by rkolyan on 02.02.2025.
//

long ps_node_create(size_t buf_size, size_t block_size, unsigned long __user *result);
//long ps_node_create(size_t buf_size, size_t block_size);
long ps_node_delete(unsigned long node_id);
long ps_node_subscribe(unsigned long node_id);
long ps_node_unsubscribe(unsigned long node_id);
long ps_node_publish(unsigned long node_id);
long ps_node_unpublish(unsigned long node_id);
long ps_node_send(unsigned long node_id, void __user *info);
long ps_node_recv(unsigned long node_id, void __user *info);
