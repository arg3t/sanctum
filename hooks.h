#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include "hooker.h"
#include "protected.h"

#ifndef SANCTUM_HOOKS_H
#define SANCTUM_HOOKS_H
  asmlinkage long sanctum_read(const struct pt_regs* regs);

  asmlinkage long sanctum_mkdir(const struct pt_regs* regs);

  asmlinkage long sanctum_write(const struct pt_regs*);

  // Global linked list containing sanctums
  extern sanctum_t* sanctums;

  extern void* HOOKED_CALLS[][2];
#endif
