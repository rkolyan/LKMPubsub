obj-m += pubsub.o
pubsub-objs += buffer.o position.o subscriber.o publisher.o node.o syscalls.o pubsub_module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
