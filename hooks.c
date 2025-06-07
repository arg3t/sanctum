#include "asm/current.h"
#include "asm/unistd_64.h"
#include "linux/dcache.h"
#include "linux/file.h"
#include "linux/printk.h"
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/module.h>
#include "hooker.h"
#include "linux/sched.h"
#include "linux/namei.h"
#include "linux/slab.h"
#include "linux/uaccess.h"
#include "protected.h"
#include "sanctum_init.h"
#include "errors.h"
#include "hooks.h"
#include "linux/device.h"

void* HOOKED_CALLS[][2] = {
   {(void*) __NR_read, &sanctum_read},
   {(void*) __NR_write, &sanctum_write},
   {0, 0}
 };

sanctum_t* sanctums;

void xor_data(char* data, char* k, size_t offset, size_t len, size_t keylen) {
  int i;

  for(i = 0; i < len; i++){
    data[i] = data[i] ^ k[(offset + i) % keylen];
  }
}


int is_child_process(struct task_struct *c, pid_t p) {
  while (c != NULL && c->pid != p) {
    c = c->parent;
  }

  return c->pid == p;
}

asmlinkage long sanctum_write(struct pt_regs* regs) {
  long fd = regs->di;
  struct fd fdt;
  char* __user ubuf = (char*) regs->si;
  long len = regs->dx;
  pid_t pid;
  struct path path;
  char* buf_dec;
  char* buf_enc;
  sanctum_t* sanctum;
  int status = -1;
  struct task_struct *task;

  fdt = __to_fd(__fdget(fd));

	if (!fdt.file)
    return -EBADF;

  path = fdt.file->f_path;

  if ((sanctum = find_sanctum(sanctums, &path))) {
    pid = task_pid_nr(current);
    task = pid_task(find_vpid(pid), PIDTYPE_PID);

    if (!is_child_process(task, sanctum->owner))
      return status;

    buf_dec = kmalloc(len, GFP_ATOMIC);
    buf_enc = kmalloc(len, GFP_ATOMIC);

    if(copy_from_user(buf_enc, ubuf, len)){
      kfree(buf_dec);
      kfree(buf_enc);
      return -1;
    }

    memcpy(buf_dec, buf_enc, len);
    xor_data(buf_enc, sanctum->key, fdt.file->f_pos, len, sanctum->keylen);

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
  struct fd fdt;
  char* __user ubuf = (char*) regs->si;
  int status;
  pid_t pid;
  struct path path;
  char* buf;
  sanctum_t* sanctum;
  struct task_struct* task;

  status = ORIG_SYSCALL(__NR_read);

  if (status == -1 || status == 0)
    return status;

  fdt = __to_fd(__fdget(fd));
  path = fdt.file->f_path;

  if ((sanctum = find_sanctum(sanctums, &path))) {
    pid = task_pid_nr(current);
    task = pid_task(find_vpid(pid), PIDTYPE_PID);

    if (!is_child_process(task, sanctum->owner)){
      return status;
    }

    if((buf = kmalloc(status, GFP_ATOMIC)) == 0) {
      return status;
    }

    if ((copy_from_user(buf, ubuf, status))) {
      kfree(buf);
      return status;
    }

    xor_data(buf, sanctum->key, fdt.file->f_pos - status, status, sanctum->keylen);

    if(copy_to_user(ubuf, buf, status))
      kfree(buf);
    else
      kfree(buf);
  }

  return status;
}

ssize_t dev_write(struct file *f, const char *msg, size_t len, loff_t *) {
    int status;
    pid_t pid;
    struct path path;
    char* kbuf;
    sanctum_t* new_sanctum;

    pid = task_pid_nr(current);

    kbuf = kmalloc(len, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, msg, len)) {
        kfree(kbuf);
        return -EFAULT;
    }

    get_fs_pwd(current->fs, &path);

    new_sanctum = init_sanctum(&path, pid, kbuf, len);
    kfree(kbuf);

    if (new_sanctum == NULL) {
        path_put(&path);
        return -ENOMEM;
    }

    status = len;

    switch (add_sanctum(sanctums, new_sanctum)) {
        case 0:
            print_sanctum(sanctums);
            return status;

        case SEXIST:
            free_sanctum(new_sanctum);
            path_put(&path);
            return -EEXIST;

        default:
            free_sanctum(new_sanctum);
            path_put(&path);
            return -EFAULT;
    }
}
