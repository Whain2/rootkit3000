MODULE_NAME := kernmod

obj-m += $(MODULE_NAME).o

KDIR := /lib/modules/$(shell uname -r)/build

.PHONY: module clean help

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
