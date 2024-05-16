# 该Makefile用于构建Linux内核模块

# 指定内核构建系统的路径
# 通常，这会指向您Linux系统的/lib/modules/$(shell uname -r)/build目录
KDIR := /lib/modules/$(shell uname -r)/build

# 模块名称，应与源文件名相匹配（不包括扩展名）
obj-m := loader-kernel.o

# 默认目标，用于编译模块
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# 清理目标，用于清除构建过程中生成的所有文件
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# 插入模块
insmod:
	sudo insmod hello-kernel.ko

# 移除模块
rmmod:
	sudo rmmod hello-kernel.ko

# 查看模块信息
lsmod:
	lsmod | grep hello_kernel

# 查看内核信息
dmesg:
	dmesg | grep hello-kernel