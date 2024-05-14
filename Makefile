obj-m += sanctum.o

all:
	make -C ../../linux-6.4.5 M=$(PWD) modules
clean:
	make -C ../../linux-6.4.6 M=$(PWD) clean
