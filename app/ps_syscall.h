#include <unistd.h>

//

#define ps_node_create(buf_size, buf_block_size, id_ptr) syscall(134, (buf_size), (buf_block_size), (id_ptr))
#define ps_node_delete(id) syscall(156, (id))
#define ps_node_subscribe(id) syscall(174, (id))
#define ps_node_unsubscribe(id) syscall(177, (id))
#define ps_node_publish(id) syscall(178, (id))
#define ps_node_unpublish(id) syscall(180, (id))
//TODO: 
#define ps_node_send(id, buf) syscall(181, (id), (buf))
#define ps_node_receive(id, buf) syscall(182, (id), (buf))
