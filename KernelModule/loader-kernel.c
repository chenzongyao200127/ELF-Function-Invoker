#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

typedef int (*FUNC_ADD)(int a, int b);
typedef int (*FUNC_SUB)(int a, int b);

static int loader_init(void)
{
    printk("loader-kernel init\n");

    // sudo cat /proc/kallsyms | grep hello_kernel
    // ffffffffc107c000 t add  [hello_kernel]
    // ffffffffc107c020 t sub  [hello_kernel]
    FUNC_ADD add = (FUNC_ADD)0xffffffffc107c000;
    FUNC_SUB sub = (FUNC_SUB)0xffffffffc107c020;

    int result = 0;
    result = add(1, 2);
    printk("loader-kernel add(1, 2) = %d\n", result);
    result = sub(9, 8);
    printk("loader-kernel sub(9, 8) = %d\n", result);

    return 0;
}

static void loader_exit(void)
{
    printk("loader-kernel exit\n");
}

module_init(loader_init);
module_exit(loader_exit);

// (required Makefile)
// make
//
// sudo insmod loader-kernel.ko
// sudo lsmod | grep loader_kernel
// sudo rmmod loader-kernel.ko
// sudo dmesg | grep loader-kernel