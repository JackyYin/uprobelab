obj-m += myuprobe.o

ccflags-y += -DRETPOLINE
ccflags-y += -g -Wall

KDIR ?= /lib/modules/`uname -r`/build

PWD := $(CURDIR)

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
