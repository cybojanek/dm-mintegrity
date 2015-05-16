KVERSION = $(shell uname -r)

obj-m = sha256.o
sha256-objs = sha256_ssse3_glue.o sha256-avx-asm.o sha256-avx2-asm.o sha256-ssse3-asm.o

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
        
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean


