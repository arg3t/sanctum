obj-m += sanctum.o
sanctum-objs := sanctum_init.o hooker.o

all:
	make -C ../../linux-6.4.5 M=$(PWD) modules
clean:
	make -C ../../linux-6.4.6 M=$(PWD) clean
