__attribute__((visibility("default"))) int add(int a, int b)
{
    return a + b;
}

__attribute__((visibility("hidden"))) int sub(int a, int b)
{
    return a - b;
}

// gcc -c hello-static.c
// ar -rcs test.a hello-static.o