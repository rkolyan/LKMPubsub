#obj-m += pubsub.o
#pubsub-objs += buffer.o position.o subscriber.o publisher.o node.o functions.o syscalls.o pubsub_module.o

obj-m += test_pubsub.o
test_pubsub-objs += buffer.o position.o subscriber.o publisher.o node.o functions.o test_module.o

#obj-m += experiment.o

ccflags-y += -g -DDEBUG -DPS_TEST

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
