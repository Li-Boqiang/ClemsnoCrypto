// clang -O0 test_jemalloc.c -L. -ljemalloc
// LD_PRELOAD=./libjemalloc.so ./a.out

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void *mpk_malloc(size_t size);
size_t mpk_malloc_usable_size(void *ptr);
void *mpk_realloc(void *ptr, size_t size);
void mpk_free(void *ptr);
int mpk_check_paegs(void *ptr);

int main(int argc, char const* argv[])
{
    pkey_set(1, 0);
    void *p1, *p2;
    size_t s1, s2;

    for (int i = 0; i < 0x1000; i++) {
        p1 = mpk_malloc(0x1000);
        s1 = mpk_check_pages(p1);
        p2 = malloc(0x1000);
        s2 = mpk_check_pages(p2);
        printf("%p\n", p1);
        printf("%x\n", s1);
        printf("%p\n", p2);
        printf("%x\n", s2);
        if (!(s1 >= 0 && s1 < 0x100 && s2 == -1)) {
            puts("failed");
            break;
        }
    }

    return 0;
}
