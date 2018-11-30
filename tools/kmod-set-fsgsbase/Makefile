obj-m += mod_set_cr4_fsgsbase.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

set-cr4-fsgsbase: all
	sudo insmod ./mod_set_cr4_fsgsbase.ko val=1
	sudo rmmod mod_set_cr4_fsgsbase
	dmesg | tail -n 10

unset-cr4-fsgsbase: all
	sudo insmod ./mod_set_cr4_fsgsbase.ko val=0
	sudo rmmod mod_set_cr4_fsgsbase
	dmesg | tail -n 10
