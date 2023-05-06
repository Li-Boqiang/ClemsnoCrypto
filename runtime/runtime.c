#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void *mpk_malloc(size_t size);
void mpk_free(void *ptr);
void *mpk_realloc(void *ptr, size_t size);
int mpk_check_pages(void *ptr);
size_t mpk_usable_size(void *ptr);

void *u_malloc(size_t size) {
    void *ptr = malloc(size);
    return ptr;
}

void *m_malloc(size_t size) {
    void *ptr = mpk_malloc(size);
    return ptr;
}

void m_free(void *ptr) {
    if (mpk_check_pages(ptr) != -1) {
        // printf("check_pages %p, %x\n", ptr, mpk_check_pages(ptr));
        mpk_free(ptr);
    }
    else  {
        // printf("check_pages %p, %x\n", ptr, mpk_check_pages(ptr));
        free(ptr);
    }
}

void *m_realloc(void *ptr, size_t size) {
    if (mpk_check_pages(ptr) != -1)
        return mpk_realloc(ptr, size);
    else 
        return realloc(ptr, size);
}


void __taint_fdf0f8a65855a52bbe69cd2075f89027(const char *fmt, ...) {  }
void __sinktaint_fdf0f8a65855a52bbe69cd2075f89027(const char *fmt, ...) {  }

#include <malloc.h>
#include <sys/mman.h>
void *__taint_replace_fdf0f8a65855a52bbe69cd2075f89027(void *ptr) {
    pkey_set(1, 0);
    size_t size = 0;
    if (mpk_check_pages(ptr) != -1) {
        size = mpk_malloc_usable_size(ptr);
    } else {
        size = malloc_usable_size(ptr);
    }
    void *new = m_malloc(size);
    memcpy(new, ptr, size);
    memset(ptr, 0, size);
    m_free(ptr);
    pkey_set(1, 3);

    return new;
}


