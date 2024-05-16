// Function with "default" visibility — accessible from other libraries or binaries
__attribute__((visibility("default"))) int add(int a, int b)
{
    return a + b; // Returns the sum of a and b
}

// Function with "hidden" visibility — not accessible from outside this library
__attribute__((visibility("hidden"))) int sub(int a, int b)
{
    return a - b; // Returns the difference of a and b
}

// The following GCC command is used to compile this file into a shared library:
// gcc -fPIC -shared hello-dyn.c -o hello-dyn.so