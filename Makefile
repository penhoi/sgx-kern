obj-m += sgx.o

sgx-objs =
-include $(PWD)/src/Makefile.objs
-include $(PWD)/polarssl/Makefile.objs
EXTRA_CFLAGS += -mmmx -msse2 -maes -g -I$(PWD)/include
#UNAME=3.19.0-25-generic
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
