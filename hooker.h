#include <linux/module.h>

#ifndef SANCTUM_HOOKER_H
  #define SANCTUM_HOOKER_H

  typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs*);

  unsigned long locate_symbol_brute(char* fname);

  int hook_syscall(unsigned int nr, sys_call_ptr_t f);

  int unhook_syscall(unsigned int nr);

  sys_call_ptr_t get_original_syscall(unsigned int nr);

  unsigned int unhook_all(void);
#endif
