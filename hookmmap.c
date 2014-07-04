#include "common.h"
#include <asm/uaccess.h>

asmlinkage long (*sys_mmap2)(unsigned long addr, unsigned long len,
                          unsigned long prot, unsigned long flags,
                          unsigned long fd, unsigned long pgoff);
asmlinkage long (*sys_munmap)(unsigned long addr, size_t len);

void hook_mmap2 (unsigned long addr, unsigned long len,
                          unsigned long prot, unsigned long flags,
                          unsigned long fd, unsigned long pgoff)
{
    /* Monitor/manipulate sys_read() arguments here */
    printk("HAHA hook_mmap2\n");
}

void hook_munmap  (unsigned long addr, size_t len)
{
    /* Monitor/manipulate sys_write() arguments here */
    printk("HAHA hook_munmap\n");
}

asmlinkage long n_sys_mmap2(unsigned long addr, unsigned long len,
                          unsigned long prot, unsigned long flags,
                          unsigned long fd, unsigned long pgoff)
{
    long ret;

    hook_mmap2(addr, len, prot, flags, fd, pgoff);

    hijack_pause(sys_mmap2);
    ret = sys_mmap2(addr, len, prot, flags, fd, pgoff);
    hijack_resume(sys_mmap2);

    return ret;
}

asmlinkage long n_sys_munmap (unsigned long addr, size_t len)
{
    long ret;

    hook_munmap(addr, len);

    hijack_pause(sys_munmap);
    ret = sys_munmap(addr, len);
    hijack_resume(sys_munmap);

    return ret;
}

void hookmmap_init ( void )
{
    DEBUG("Hooking sys_mmap2 and sys_munmap\n");

    sys_mmap2 = (void *)sys_call_table[__NR_mmap2];
    hijack_start(sys_mmap2, &n_sys_mmap2);

    sys_munmap = (void *)sys_call_table[__NR_munmap];
    hijack_start(sys_munmap, &n_sys_munmap);
}

void hookmmap_exit ( void )
{
    DEBUG("Unhooking sys_mmap2 and sys_munmap\n");

    hijack_stop(sys_mmap2);
    hijack_stop(sys_munmap);
}
