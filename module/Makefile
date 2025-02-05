#obj-m += pubsub.o
#pubsub-objs += buffer.o position.o subscriber.o publisher.o node.o functions.o syscalls.o pubsub_module.o

#obj-m += pubsub2.o
#pubsub2-objs += buffer.o position.o subscriber.o publisher.o node.o functions.o pubsub2_module.o

obj-m += experiment.o

#ccflags-y += -g -DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
