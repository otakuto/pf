#KERNELSRCDIR = /usr/src/linux
#BUILD_DIR := $(shell pwd)
#VERBOSE = 0

obj-m += pf.o

#smallmod-objs := pf.o

all:
	make -C /usr/src/linux/ M=/root/work/pf modules
#clean:
#		rm -f *.o
#		rm -f *.ko
#		rm -f *.mod.c
#		rm -f *~
