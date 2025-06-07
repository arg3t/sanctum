#include <linux/cred.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/types.h>      // for size_t, ssize_t, pid_t, loff_t
#include <linux/sched.h>      // for struct task_struct
#include <linux/ptrace.h>     // for struct pt_regs
#include <linux/kernel.h>     // for asmlinkage
#include "hooker.h"
#include "protected.h"

#ifndef SANCTUM_HOOKS_H
#define SANCTUM_HOOKS_H
  void xor_data(char* data, char* k, size_t offset, size_t len, size_t keylen);
  int is_child_process(struct task_struct *c, pid_t p);

  asmlinkage long sanctum_read(const struct pt_regs* regs);
  asmlinkage long sanctum_write(struct pt_regs*);

  /* Function declared in hooks.c */
  extern ssize_t dev_write(struct file *, const char *, size_t len, loff_t *);

  // Global linked list containing sanctums
  extern sanctum_t* sanctums;

  extern void* HOOKED_CALLS[][2];
#endif
