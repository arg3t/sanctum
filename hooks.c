#include "asm/current.h"
#include "asm/unistd_64.h"
#include "linux/dcache.h"
#include "linux/file.h"
#include "linux/printk.h"
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include "hooker.h"
#include "linux/sched.h"
#include "linux/namei.h"
#include "linux/slab.h"
#include "linux/uaccess.h"
#include "protected.h"
#include "sanctum_init.h"
#include "sanctum_init.h"
#include "errors.h"
#include "hooks.h"
#define KEY 0x31

void* HOOKED_CALLS[][2] = {
   {(void*) __NR_read, &sanctum_read},
   {(void*) __NR_write, &sanctum_write},
   {(void*) __NR_mkdir, &sanctum_mkdir},
   {0, 0}
 };

sanctum_t* sanctums;

void xor_data(char* data, char k, size_t len) {
  int i;

  for(i = 0; i < len; i++){
    data[i] = data[i] ^ k;
  }
}

asmlinkage long sanctum_write(struct pt_regs* regs) {
  long fd = regs->di;
  char* __user ubuf = (char*) regs->si;
  long len = regs->dx;
  pid_t pid;
  struct path path;
  char* buf_dec;
  char* buf_enc;
  sanctum_t* sanctum;
  int status = -1;

  path = __to_fd(__fdget(fd)).file->f_path;

  if ((sanctum = find_sanctum(sanctums, &path))) {
    printk("Writing to sanctum\n");
    pid = task_pid_nr(current);

    // if (pid != sanctum->owner)
    //   return status;

    buf_dec = kmalloc(len, GFP_ATOMIC);
    buf_enc = kmalloc(len, GFP_ATOMIC);

    if(copy_from_user(buf_enc, ubuf, len)){
      kfree(buf_dec);
      kfree(buf_enc);
      return -1;
    }

    memcpy(buf_dec, buf_enc, len);
    xor_data(buf_enc, KEY, len);

    if(copy_to_user(ubuf, buf_enc, len)) {
      kfree(buf_dec);
      kfree(buf_enc);
      return -1;
    }

    kfree(buf_enc);

    status = ORIG_SYSCALL(__NR_write);


    if(copy_to_user(ubuf, buf_dec, len)) {
      kfree(buf_dec);
      return -1;
    }

    kfree(buf_dec);
  } else {
    status = ORIG_SYSCALL(__NR_write);
  }

  return status;
}


asmlinkage long sanctum_read(const struct pt_regs* regs) {
  long fd = regs->di;
  char* __user ubuf = (char*) regs->si;
  int status;
  pid_t pid;
  struct path path;
  char* buf;
  sanctum_t* sanctum;

  // umode_t mode = regs->si;
  status = ORIG_SYSCALL(__NR_read);

  if (status == -1 || status == 0)
    return status;

  path = __to_fd(__fdget(fd)).file->f_path;

  if ((sanctum = find_sanctum(sanctums, &path))) {
    pid = task_pid_nr(current);

    // if (pid != sanctum->owner)
    //   return status;

    if((buf = kmalloc(status, GFP_ATOMIC)) == 0) {
      return status;
    }

    if ((copy_from_user(buf, ubuf, status))) {
      kfree(buf);
      return status;
    }

    xor_data(buf, KEY, status);

    if(copy_to_user(ubuf, buf, status))
      kfree(buf);
    else
      kfree(buf);
  }

  return status;
}

asmlinkage long sanctum_mkdir(const struct pt_regs* regs){
  char __user *user_path_c = (char*) regs->di;
  int status;
  pid_t pid;
  struct path path;
  sanctum_t* new_sanctum;

  // umode_t mode = regs->si;
  if ((status = ORIG_SYSCALL(__NR_mkdir))) {
    return status;
  }

  if (user_path_at(AT_FDCWD, user_path_c, LOOKUP_FOLLOW, &path))
    return status;

  if(!strncmp(path.dentry->d_name.name, SANCTUM_PREFIX, sizeof(SANCTUM_PREFIX) - 1)){
    pid = task_pid_nr(current);

    if((new_sanctum = init_sanctum(&path, pid)) == 0){
      return status;
    }

    switch(add_sanctum(sanctums, new_sanctum)){
      case 0:
        print_sanctum(sanctums);
        return status;

      case SEXIST:
        free_sanctum(new_sanctum);
        return EEXIST;

      default:
        free_sanctum(new_sanctum);
    }

  }

  return status;
}

