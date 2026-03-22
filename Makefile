MODULE_NAME := kernmod

obj-m += $(MODULE_NAME).o

KDIR := /lib/modules/$(shell uname -r)/build

.PHONY: module clean help

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# auxiliary functions

unload:
	sudo rmmod $(MODULE_NAME) || true

load: module unload
	sudo insmod $(MODULE_NAME).ko

log:
	sudo dmesg | tail -30

help:
	@echo "Comands:"
	@echo "  module   - Build kernel module"
	@echo "  clean    - Remove build"
	@echo "  load     - Load module"
	@echo "  unload   - Unload module"
	@echo "  log      - Show log messages"
