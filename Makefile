obj-m += rt_driver.o
rt_driver-objs := entry.o

KDIR ?= /root/kernel_src
PWD := $(shell pwd)

KERNEL_VER := 6.6.118-android15-8-g93e223c276e7-abogki500782043-4k

all:
	@echo "$(KERNEL_VER)" > $(KDIR)/.scmversion
	@cp -f Module.symvers $(KDIR)/Module.symvers
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
