obj-m += pubsub.o
pubsub-objs += buffer.o position.o subscriber.o publisher.o node.o functions.o syscalls.o pubsub_module.o

ccflags-y += -g -DDEBUG -fsanitize=kernel-address

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
