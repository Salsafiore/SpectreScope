#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 * Native helper binary spawned repeatedly to sample real Linux kernel ASLR
 * randomization across PIE text, stack, brk/heap, and anonymous mmap regions.
 */
int main(void) {
    volatile int stack_var = 42;
    void *heap_ptr = malloc(64);
    void *mmap_ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    printf("0x%016lx 0x%016lx 0x%016lx 0x%016lx\n",
           (uintptr_t)&main,
           (uintptr_t)&stack_var,
           (uintptr_t)heap_ptr,
           (uintptr_t)mmap_ptr);

    if (mmap_ptr != MAP_FAILED) {
        munmap(mmap_ptr, 4096);
    }
    free(heap_ptr);
    return 0;
}
