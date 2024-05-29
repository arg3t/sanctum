# Existing kernel module configuration
obj-m += sanctum.o
sanctum-objs := sanctum_init.o hooker.o protected.o hooks.o

# Name of the C program to compile
PROGRAM = sanctum_manager
C_SOURCE = sanctum_manager.c

# All target
all: modules $(PROGRAM)

# Compile kernel modules
modules:
	make -C ../../linux-6.4.5 M=$(PWD) modules

# Compile the C program as a static binary
$(PROGRAM): $(C_SOURCE)
	gcc -o $(PROGRAM) $(C_SOURCE) -static

# Clean target
clean:
	make -C ../../linux-6.4.5 M=$(PWD) clean
	rm -f $(PROGRAM)
