# 调用 ELF 文件任意函数的几种方式 【转】

本文由 Seebug Paper 发布，如需转载请注明来源。本文地址：https://paper.seebug.org/3163/

> 原始链接：[paper.seebug.org/3163/](https://paper.seebug.org/3163/)
> 5/16/2024

## 前言

动态链接库是一种把共享代码制作为公共库文件，用来减少软件的冗余存储占用并提高运行效率的软件开发优化方案。如 Linux 下的动态链接库(Shared Object) `.so` 文件，设计开发人员可通过调用动态链接库的导出函数，快速实现业务功能。

Linux 下常见的可执行文件 ELF 格式包括：二进制程序(`EXEC`)、动态链接库(`so`)、静态链接库(`a`)、内核模块(`ko`)等等，那么这些格式是否可以像动态链接库的函数一样被外部所调用，从而在闭源情况下实现对软件的二次开发，或者用于辅助逆向分析呢？本文就此进行探讨和实现。

本文实验环境：

```
Ubuntu 5.15.0-92-generic
gcc version 11.4.0
```

## 动态链接库

Linux 下的动态链接库(Shared Object)天然可被调用，我们准备如下的 `.so` 文件，其中 `add()` 函数为导出函数，`sub()` 函数为不可导出函数，`hello-dyn.c`源码如下：

~~~c
// Function with "default" visibility — accessible from other libraries or binaries
__attribute__((visibility("default"))) int add(int a, int b) {
    return a + b;  // Returns the sum of a and b
}

// Function with "hidden" visibility — not accessible from outside this library
__attribute__((visibility("hidden"))) int sub(int a, int b) {
    return a - b;  // Returns the difference of a and b
}

// The following GCC command is used to compile this file into a shared library:
// gcc -fPIC -shared hello-dyn.c -o hello-dyn.so
~~~

对于导出函数我们可以使用符号表进行调用，对于非导出函数我们可以使用地址进行调用，查看 `sub()` 函数的地址

~~~shell
(base)  chenzy@MS-7D36  /disk2/chenzy/ELF/ELF-Function-Invoker/SharedObject  objdump -T hello-dyn.so

hello-dyn.so:     file format elf64-x86-64

DYNAMIC SYMBOL TABLE:
0000000000000000  w   D  *UND*  0000000000000000 __cxa_finalize
0000000000000000  w   D  *UND*  0000000000000000 _ITM_registerTMCloneTable
0000000000000000  w   D  *UND*  0000000000000000 _ITM_deregisterTMCloneTable
0000000000000000  w   D  *UND*  0000000000000000 __gmon_start__
00000000000010f9 g    DF .text  0000000000000018 add
~~~

~~~shell
(base)  chenzy@MS-7D36  /disk2/chenzy/ELF/ELF-Function-Invoker/SharedObject  radare2 hello-dyn.so                      
[0x00001040]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Finding function preludes
[x] Enable constraint types analysis for variables
[0x00001040]> afl
0x00001040    4 41   -> 34   entry0
0x00001070    4 57   -> 51   sym.register_tm_clones
0x000010fd    1 20           fcn.000010fd
0x00001115    1 18           fcn.00001115
[0x00001040]> s 0x00001115
[0x00001115]> pdf
┌ 18: fcn.00001115 ();
│           ; var int64_t var_8h @ rbp-0x8
│           ; var int64_t var_4h @ rbp-0x4
│           0x00001115      55             push rbp
│           0x00001116      4889e5         mov rbp, rsp
│           0x00001119      897dfc         mov dword [var_4h], edi
│           0x0000111c      8975f8         mov dword [var_8h], esi
│           0x0000111f      8b45fc         mov eax, dword [var_4h]
│           0x00001122      2b45f8         sub eax, dword [var_8h]
│           0x00001125      5d             pop rbp
└           0x00001126      c3             ret
[0x00001115]> 
~~~

编写调用代码如下 `loader-dyn.c`：

~~~c
#include <dlfcn.h>
#include <stdio.h>

typedef int (*FUNC_ADD) (int, int);
typedef int (*FUNC_SUB) (int, int);

int main(int argc, char* argv[]) {
    void* handle = dlopen("./hello-dyn.so", RTLD_LAZY);

    FUNC_ADD add = dlsym(handle, "add");
    FUNC_SUB sub = (FUNC_SUB)(*(long*)handle + 0x00001115);

    int result = 0;
    result = add(1, 2);
    printf("add(1, 2) = %d\n", result);
    result = sub(9, 8);
    printf("sub(9, 8) = %d\n", result);

    dlclose(handle);
    return 0;
}

// gcc loader-dyn.c -o test
~~~

~~~shell
(base)  chenzy@MS-7D36  /disk2/chenzy/ELF/ELF-Function-Invoker/SharedObject  gcc loader-dyn.c -o test
(base)  chenzy@MS-7D36  /disk2/chenzy/ELF/ELF-Function-Invoker/SharedObject  ./test                                         
add(1, 2) = 3
sub(9, 8) = 1
~~~


## 二进制EXEC

- **可执行文件（EXEC）**：这是包含完整程序代码和资源的文件，操作系统加载并直接执行。它通常包含程序的入口点（如main函数）。
- **共享库**：在UNIX/Linux中通常以`.so`（共享对象）扩展名出现，Windows中则是`.dll`（动态链接库）。共享库包含可以被多个程序共同使用的代码和数据。它们不包含一个明确的"入口点"，因为它们并非独立运行，而是被其他程序调用。

为什么不能用 `dlopen()` 加载EXEC文件？

1. **设计目的不同**：`dlopen()`函数设计用来加载共享库，这些库不包含main函数或程序入口点，而是提供可以被其他程序调用的函数和资源。相反，可执行文件是为了单独运行而设计，包含一个或多个入口点。
    
2. **内部结构差异**：可执行文件和共享库在内部结构上可能有所不同，尽管它们可能同样遵循例如ELF这样的格式。共享库被设计为可以被映射到任何地址空间（位置无关代码），而可执行文件则可能依赖于特定的加载地址。
    
3. **链接和依赖处理**：可执行文件在链接时通常会解决所有依赖项，而共享库可能在运行时解决依赖，这意味着使用`dlopen()`加载共享库时需要处理的链接方式与加载可执行文件时不同。

因此，尝试使用`dlopen()`来加载一个EXEC文件（无论其是否使用位置无关代码编译）通常会失败，因为这不符合该函数的设计用途和期望的文件格式。如果您需要在运行时动态加载代码，最佳实践是将该代码编译成共享库，而不是可执行文件。

二进制程序(`EXEC`)无法被 `dlopen()` 正确加载，无论是位置无关代码还是固定地址代码的编译方式，测试代码 `hello-exec.c`如下：

~~~c
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

int main(int argc, char* argv[]) {
    printf("[hello-exec]\n");

    int c = add(1, 2);
    printf("add(1, 2) = %d\n", c);

    int d = sub(3, 4);
    printf("sub(3, 4) = %d\n", d);

    return 0;
}

// Position Independent Executable (default: -fPIC)
// gcc hello-exec.c -o test1
// Absolute Address Code
// gcc -fPIC -no-pie hello-exec.c -o test2
~~~

- `-fPIC`（位置无关代码）：这个标志通常用于共享库，但也可以为可执行文件指定。它确保代码不假定它将在任何预定义的内存地址加载。

- `-no-pie`（非位置无关可执行文件）：此标志告诉编译器生成一个非位置无关的可执行文件。因此，可执行文件期望在编译时设置的固定地址加载。这个标志在某些类型的调试中很有用，或者在内存布局可预测且受控的环境中工作时很有用。

编译后使用 `readelf -h [file]` 查看类型如下：

![[Pasted image 20240516165606.png]]

![[Pasted image 20240516165653.png]]

对于这种二进制程序的格式，可以使用 `LD_PRELOAD` 对 `__libc_start_main()` 函数进行 hook，从而改写原始程序的 `main()` 函数，实现对任意函数的调用

`LD_PRELOAD` 是一个在 Linux 系统上非常强大的机制，它允许用户指定在程序启动之前加载的共享库列表。这种方法常被用来修改或增强已有的系统库函数的行为，甚至可以用来拦截和重写这些函数的调用~

`LD_PRELOAD` 是一个环境变量，用于指定一个或多个共享库文件名，这些文件将在程序运行前加载到进程的地址空间中。当一个程序启动时，任何通过 `LD_PRELOAD` 指定的库都会在其他库之前被加载。这样做可以让 `LD_PRELOAD` 中指定的函数覆盖同名的库函数，从而实现对原始函数行为的改变。

**如何使用 `LD_PRELOAD` 来 Hook `__libc_start_main()`？**

`__libc_start_main()` 是 glibc 的一部分，它负责设置 C 程序的执行环境，调用全局构造函数，最终调用程序的 `main()` 函数。通过在 `LD_PRELOAD` 指定的库中提供一个自定义的 `__libc_start_main()` 函数，可以在调用 `main()` 之前执行自定义代码。

编写 `loader-exec.c`代码如下：

~~~c
#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>

typedef int (*FUNC_ADD) (int, int);
typedef int (*FUNC_SUB) (int, int);

static int (*main_orig)(int, char **, char **);

int main_hook(int argc, char **argv, char **envp) {
    printf("main hook\n");
    printf("bypass address(main_orig) = %p\n", main_orig);

    void* handle = dlopen(NULL, RTLD_LAZY);
    FUNC_ADD add = (FUNC_ADD)(*(long*)handle + 0x1169);
    FUNC_SUB sub = (FUNC_SUB)(*(long*)handle + 0x1181);

    int result = 0;
    result = add(1, 2);
    printf("add(1, 2) = %d\n", result);
    result = sub(9, 8);
    printf("sub(9, 8) = %d\n", result);

    return 0;
}

int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc,
    char **argv,
    int (*init)(int, char **, char **),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end) {
    // Save the real main function address
    main_orig = main;

    // Find the real __libc_start_main()...
    typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");

    // ... and call it with our custom main function
    return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}

// gcc -fPIC -shared loader-exec.c -o hook.so
// LD_PRELOAD=./hook.so ./test1
~~~

使用 `LD_PRELOAD=./hook.so` 加载并调用 `add()` 和 `sub()` 函数如下：

~~~shell
(base)  ✘ chenzy@MS-7D36  /disk2/chenzy/ELF/ELF-Function-Invoker/EXEC  gcc -fPIC -shared loader-exec.c -o hook.so
(base)  chenzy@MS-7D36  /disk2/chenzy/ELF/ELF-Function-Invoker/EXEC  LD_PRELOAD=./hook.so ./test1              
main hook
bypass address(main_orig) = 0x561bccd00197
add(1, 2) = 3
sub(9, 8) = 1
~~~

## 静态链接库

除了上文动态链接库外，静态链接库(`.a`)也可以调用其任意函数，静态链接库的本质是编译过程中的目标文件(Object File)即 `.o` 文件，其中包含完整的符号链接，我们可以直接编写代码，通过链接实现对函数的调用，我们这里复用上文动态链接库测试代码为`hello-static.c`，如下：

~~~c
__attribute__((visibility("default"))) int add(int a, int b) {
    return a + b;
}

__attribute__((visibility("hidden"))) int sub(int a, int b) {
    return a - b;
}

// gcc -c hello-static.c
// ar -rcs test.a hello-static.o 
~~~

`ar -rcs test.a hello-static.o` 这行命令是用来创建或更新一个静态库文件的

随后编写代码时直接使用符号调用 `add()` 和 `sub()` 函数即可，注意需要定义为外部函数，`loader-static.c` 代码如下：

~~~c
#include <stdio.h>

extern int add(int a, int b);
extern int sub(int a, int b);

int main() {
    printf("loader-static\n");

    int result = 0;
    result = add(1, 2);
    printf("add(1, 2) = %d\n", result);
    result = sub(9, 8);
    printf("sub(9, 8) = %d\n", result);

    return 0;
}

// gcc loader-static.c test.a -o test
~~~

编译时指定静态链接库文件，目标文件即 `.o` 文件也同理。

# 内核模块

内核模块(`.ko`)也是一种常见的 ELF 文件，而调用内核模块的函数稍微有点不同，我们编写测试文件`hello-kernel.c`

~~~c
#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

static int hello_init(void) {
    printk("hello-kernel init\n");
    return 0;
}

static void hello_exit(void) {
    printk("hello-kernel exit\n");
}

module_init(hello_init);
module_exit(hello_exit);

// (required Makefile)
// make
//
// sudo insmod hello-kernel.ko
// sudo lsmod | grep hello_kernel
// sudo rmmod hello-kernel.ko
// sudo dmesg | grep hello-kernel
~~~


----
PS 内核模块介绍

Linux内核模块是Linux操作系统中用于扩展内核功能的一种机制。这些模块允许用户在不重新编译整个内核的情况下，动态地加载和卸载功能代码。内核模块广泛用于添加设备驱动程序、文件系统类型、网络协议等。

内核模块的特点
1. **动态加载和卸载**：内核模块可以在系统运行时加载和卸载，这使得用户可以根据需要添加或移除功能，而无需重启系统。
2. **独立性**：模块可以独立于内核主体开发和编译。只要模块遵守与内核相同的接口和规则，它就可以与内核交互。
3. **内存效率**：只需要在必要时加载模块，这有助于节省系统资源，因为不使用的功能不会占用内存。
4. **易于维护和升级**：模块化设计使得对特定设备驱动或系统服务的更新更为简单，不需要修改整个内核。

内核模块的组成，内核模块通常包含几个基本部分：
- **初始化函数**：用于设置模块需要的资源，如内存分配、注册设备等。此函数在模块加载时执行。
- **退出函数**：用于清理在初始化函数中设置的所有资源。此函数在模块卸载时执行。
- **模块元数据**：如`MODULE_LICENSE`，它声明模块的许可证类型；还可能包括作者、描述和版本信息。
- **功能实现**：模块的核心功能代码，可能包括处理数据、响应系统事件等。

内核模块的生命周期管理
- **加载**：使用`insmod`命令加载模块。系统会调用模块的初始化函数。
- **运行**：一旦加载，模块就会开始运行，执行其设计的功能。
- **卸载**：使用`rmmod`命令卸载模块。系统会调用模块的退出函数。

内核模块通过一组明确定义的内核API与内核主体交互。这些API允许模块调用内核提供的功能，如内存分配、进程管理和网络功能。模块需要确保兼容当前内核的API版本，因为内核API在不同版本的内核中可能会有所变化。

由于内核模块运行在内核空间，它们有完全访问硬件和内存的能力。因此，编写模块时必须格外小心，错误的代码可能导致系统崩溃或安全漏洞。此外，模块需要遵循严格的编程规范来保证系统的稳定性和安全性。

内核模块提供了一种强大的机制来扩展Linux内核的功能，它们在系统的可扩展性、维护性和效率方面起到了关键作用。

-----

使用 `make` 进行编译，测试运行如下：

使用 `readelf -h [file]` 查看内核模块的类型，其类型 `REL` (Relocatable file)虽然和静态链接库一样，**但内核模块的函数并不能像静态链接库那样被调用**，如下：

![[Pasted image 20240516182722.png]]

内核模块被加载后，可通过 `sudo cat /proc/kallsyms` 在操作系统中查看其符号表和地址，如下：

![[Pasted image 20240516182756.png]]

那么我们可以通过编写内核模块按地址实现对任意函数的调用，我们编写 `loader-kernel.c`代码如下：

~~~c
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
~~~

需要注意的是，每次系统启动或内核模块重新加载，其符号地址都会发生变化。同样编写 `Makefile` 并通过 `make` 编译，运行测试如下：

~~~shell
(base)  chenzy@MS-7D36  /disk2/chenzy/ELF/ELF-Function-Invoker/KernelModule  sudo insmod loader-kernel.ko
(base)  chenzy@MS-7D36  /disk2/chenzy/ELF/ELF-Function-Invoker/KernelModule  sudo lsmod | grep loader_kernel
loader_kernel          16384  0
(base)  chenzy@MS-7D36  /disk2/chenzy/ELF/ELF-Function-Invoker/KernelModule  sudo rmmod loader-kernel.ko
(base)  chenzy@MS-7D36  /disk2/chenzy/ELF/ELF-Function-Invoker/KernelModule  sudo dmesg | grep loader-kernel
[8842342.683288] loader-kernel init
[8842342.683296] loader-kernel add(1, 2) = 3
[8842342.683300] loader-kernel sub(9, 8) = 1
[8842360.621291] loader-kernel exit
~~~

# 总结

本文通过动态链接库调用方式的衍生，实现了 Linux 下常见的二进制程序(`EXEC`)、动态链接库(`so`)、静态链接库(`a`)、内核模块(`ko`) 四种可执行文件(ELF)的任意函数调用，这种调用方式能够帮助我们在闭源情况下实现对软件的二次开发，以及用于辅助逆向分析。

- 对于动态链接库，可以使用 `dlopen` 和 `dlsym` 两个函数进行动态的函数调用。
- 静态链接库在编译时已经被整合到可执行文件中。要调用静态库的函数，只需在编译时链接该库：

```bash
gcc -o myprogram myprogram.c -L/path/to/library -lstaticlibname
```

在程序中直接调用库中的函数即可，无需运行时加载。

- 如果需要从一个独立的二进制文件中调用函数，通常需要了解该程序的内存布局和函数地址。可以用 `gdb` 或其他逆向工具来分析二进制文件，找到函数的地址。然而，直接从另一个程序调用是复杂的，通常需要用到进程间通信（IPC）或者通过修改二进制来实现间接调用。
- 内核模块的函数通常是为内核或其他模块服务的，不能直接从用户空间调用。要调用内核函数，可以通过编写另一个内核模块来与之交互，或者通过创建字符设备和使用 `ioctl` 系统调用来从用户空间触发内核空间的函数调用。

```c
#include <linux/kernel.h>
#include <linux/module.h>

int init_module(void) {
    printk("Hello, kernel!\n");
    return 0;
}

void cleanup_module(void) {
    printk("Goodbye, kernel!\n");
}

MODULE_LICENSE("GPL");
```

### 跨平台的函数调用

在 Windows 下，动态链接库（DLL）的处理与 Linux 的 `.so` 文件类似，可以使用 Windows API 中的 `LoadLibrary` 和 `GetProcAddress` 函数来动态加载 DLL 并获取函数地址进行调用。

除此之外，借助以上思路我们还可以对非常规的可执行文件(ELF)进行任意函数的调用，甚至在 Windows 下，我们也可以按照类似方法实现这一点。


# Reference

- https://man7.org/linux/man-pages/man3/dlsym.3.html
- https://stackoverflow.com/questions/34519521/why-does-gcc-create-a-shared-object-instead-of-an-executable-binary-according-to/34522357
- https://stackoverflow.com/questions/28937745/how-to-compile-elf-binary-so-that-it-can-be-loaded-as-dynamic-library
- https://reverseengineering.stackexchange.com/questions/29542/how-to-call-a-func-in-an-executable-binary
- https://stackoverflow.com/questions/59074126/loading-executable-or-executing-a-library