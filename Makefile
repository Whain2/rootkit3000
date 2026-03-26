MODULE_NAME := kernmod

obj-m += $(MODULE_NAME).o

# kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# client compiler
CC := gcc
CFLAGS := -Wall -Wextra -O2

.PHONY: all module client clean load unload log help

all: module client

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

client: client.c
	$(CC) $(CFLAGS) -o client client.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f client

# auxiliary functions

unload:
	sudo rmmod $(MODULE_NAME) || true

load: module unload
	sudo insmod $(MODULE_NAME).ko

log:
	sudo dmesg | tail -30

help:
	@echo "Comands:"
	@echo "  all      - Build module and client"
	@echo "  module   - Build kernel module"
	@echo "  client   - Build userspace client"
	@echo "  clean    - Remove build"
	@echo "  load     - Load module"
	@echo "  unload   - Unload module"
	@echo "  log      - Show log messages"