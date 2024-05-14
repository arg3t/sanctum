#include <linux/syscalls.h>
#include <linux/module.h>
#include "hooker.h"

const unsigned int FNAME_MAX = 256;
sys_call_ptr_t SYSCALL_ADDRESSES[1024];
sys_call_ptr_t* sys_call_table;

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

unsigned long locate_symbol_brute(char* fname) {
  /* https://github.com/xcellerator/linux_kernel_hacking/issues/3 */
  unsigned long i;
  unsigned long kaddr;
  unsigned int fname_len;
  char* lookup_buf, *fname_buf;

  fname_len = strlen(fname);
  lookup_buf = kzalloc(FNAME_MAX, GFP_KERNEL);

  if (!lookup_buf)
    return 0;

  fname_buf = kzalloc(fname_len + 5, GFP_KERNEL);

  if (!fname_buf)
    return 0;

  strcpy(fname_buf, fname);
  strcpy(fname_buf + fname_len, "+0x0");
  // printk(KERN_INFO "Searching for %s\n", fname_buf);

  kaddr = (unsigned long) &sprint_symbol;
  // printk(KERN_INFO "%lx\n", kaddr);
  kaddr &= 0xffffffffff000000;
  // printk(KERN_INFO "%lx\n", kaddr);

  for (i = 0; i < 0xFFFFFFFFFFF; i++) {
    sprint_symbol(lookup_buf, kaddr);

    // if(i % 0xFF == 0)
    //   printk(KERN_INFO "%lx %s\n", kaddr, lookup_buf);
    if (!strncmp(lookup_buf, fname_buf, fname_len + 4)) {
      kfree(fname_buf);
      kfree(lookup_buf);

      return kaddr;
    }

    kaddr += 0x10;
  }

  return 0;
}

int hook_syscall(unsigned int nr, sys_call_ptr_t f) {
  if(nr > sizeof(SYSCALL_ADDRESSES))
    return -3;

  if(!sys_call_table)
    if (!(sys_call_table = (sys_call_ptr_t*) locate_symbol_brute("sys_call_table")))
      return -2;

  // Do not overwrite once original address is known!
  if(!SYSCALL_ADDRESSES[nr])
    SYSCALL_ADDRESSES[nr] = sys_call_table[nr];

  disable_write_protection();
  sys_call_table[nr] = f;
  enable_write_protection();

  return 0;
}

int unhook_syscall(unsigned int nr) {
  if(nr > sizeof(SYSCALL_ADDRESSES))
    return -3;

  if(!sys_call_table)
    return -1; // Nothing has been hooked yet!

  // Do not overwrite once original address is known!
  if(!SYSCALL_ADDRESSES[nr])
    return -1; // That syscall has not been hooked yet!

  disable_write_protection();
  sys_call_table[nr] = SYSCALL_ADDRESSES[nr];
  enable_write_protection();

  return 0;
}

unsigned int unhook_all(void) {
  unsigned int i = 0;
  unsigned int c = 0;

  if(!sys_call_table)
    return 0; // Nothing has been hooked yet!

  disable_write_protection();
  for(i = 0; i < 1024; i++){
    if(SYSCALL_ADDRESSES[i] != 0){
      sys_call_table[i] = SYSCALL_ADDRESSES[i];
      c += 1;
    }
  }
  enable_write_protection();

  return c;
}

sys_call_ptr_t get_original_syscall(unsigned int nr) {
  if(nr > sizeof(SYSCALL_ADDRESSES))
    return 0;

  if(!sys_call_table)
    if (!(sys_call_table = (sys_call_ptr_t*) locate_symbol_brute("sys_call_table")))
      return 0;

  SYSCALL_ADDRESSES[nr] = sys_call_table[nr];
  return SYSCALL_ADDRESSES[nr];
}

