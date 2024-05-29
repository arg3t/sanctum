#include "asm/current.h"
#include "asm/unistd_64.h"
#include "linux/dcache.h"
#include "linux/file.h"
#include "linux/gfp_types.h"
#include "linux/printk.h"
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include "hooker.h"
#include "linux/sched.h"
#include "linux/fs_struct.h"
#include "linux/namei.h"
#include "fs/namei.h"
#include "linux/slab.h"
#include "linux/uaccess.h"
#include "protected.h"
#include "sanctum_init.h"
#include "sanctum_init.h"
#include "errors.h"
#include "hooks.h"

void* HOOKED_CALLS[][2] = {
   {(void*) __NR_read, &sanctum_read},
   {(void*) __NR_mkdir, &sanctum_mkdir},
   {0, 0}
 };

sanctum_t* sanctums;


static char* get_last_nonempty_token(char* str, char delim){
  int i = 0;
  int c = 0;
  int b = 0;

  for(i = 0; i < strlen(str); i++){
    if(str[i] == delim){
      if (i != b)
        c = b;
      b = i + 1;
    }
  }

  if (i != b)
    c = b;

  return str + c;
}


static char* replace_first(char* str, char c, char r, char* limit){
  while(str != limit){
    if(*str == c) {
      *str = r;
      return str;
    }
    str++;
  }

  return str;
}

static char* find_first(char* str, char* limit, char c, int step) {
  while(str >= limit) {
    if(*str == c)
      return str;

    str += step;
  }

  return limit;
}

int collapse_and_normalize_path(char* path) {
  char* path_end = path + strlen(path);
  char* cursor;
  char* bookmark;

  if (*path == '/')
    cursor = path + 1;
  else
    cursor = path;

  while(cursor){
    bookmark = cursor;
    cursor = replace_first(cursor, '/', 0, path_end);

    if (strcmp("..", bookmark) == 0) {
      bookmark = find_first(bookmark - 1, path, '/', -1);

      if(bookmark != path)
        bookmark = find_first(bookmark - 1, path, '/', -1);

      memset(bookmark, 0, cursor - bookmark);

      if(bookmark == path)
        cursor = path;

    } else if (strcmp(".", bookmark) == 0) {
      *bookmark = 0;
    } else if (bookmark == cursor) {
      *(cursor - 1) = 0;
    }

    if (cursor == path_end)
      break;

    *cursor = '/';
    cursor++;
  }

  cursor = path;
  bookmark = path;
  while(cursor != path_end){
    if (*cursor) {
      *bookmark = *cursor;
      bookmark++;
    }

    cursor++;
  }
  *bookmark = 0;
  return 0;
}

// The pointer from this address MUST BE FREED
static char* combine_path_with_cwd(char* path, struct fs_struct *fs){
  struct path pwd;
  char* buf;
  char* cwd;
  char* abs_path;

  if(*path == '/') {
    abs_path = path;
  } else {
    get_fs_pwd(fs, &pwd);

    buf = kmalloc(MAX_PATH_LENGTH, GFP_ATOMIC);

    if (buf) {
      cwd = d_path(&pwd, buf, MAX_PATH_LENGTH);
      // TODO: check if an error pointer was returned
      abs_path = kmalloc(strlen(path) + strlen(cwd) + 2, GFP_ATOMIC);
      strcpy(abs_path, cwd);
      if (abs_path[strlen(cwd) - 1] != '/') {
        abs_path[strlen(cwd) + 1] = 0;
        abs_path[strlen(cwd)] = '/';
      }

      strcat(abs_path, path);
      kfree(buf);
    } else
      return 0;
  }

  collapse_and_normalize_path(abs_path);
  return abs_path;
}

asmlinkage long sanctum_read(const struct pt_regs* regs) {
  long fd = regs->di;
  char pathname[MAX_PATH_LENGTH];
  unsigned int pathlength;
  sanctum_t* sanctum;
  char *abs_path;
  int status;

  // umode_t mode = regs->si;
  if((status = ORIG_SYSCALL(__NR_read)) == -1)
    return status;


  if ((abs_path = combine_path_with_cwd(pathname, current->fs)) == 0)
    return status;


  if (strncmp("/host", pathname, 5) == 0)
    printk("Reading from relpath %s\n", pathname);

  if ((sanctum = find_sanctum(sanctums, abs_path))) {
    printk("Trying to read from sanctum %s\n", abs_path);
  }

  kfree(abs_path);

  return status;
}

asmlinkage long sanctum_mkdir(const struct pt_regs* regs){
  char __user *pathname_u = (char*) regs->di;
  char pathname[MAX_PATH_LENGTH];
  unsigned int pathlength;
  pid_t pid;
  sanctum_t* new_sanctum;
  char *abs_path;
  int status;
  struct dentry *dentry = ERR_PTR(-EEXIST);
  struct qstr last;
  unsigned int create_flags = LOOKUP_CREATE | LOOKUP_EXCL;
  int type;
  int err2;
  int error;


  pathlength = copy_from_user(pathname, pathname_u, MAX_PATH_LENGTH);

  // umode_t mode = regs->si;
  if ((status = ORIG_SYSCALL(__NR_mkdir))) {
    return status;
  }

  if(!strncmp(get_last_nonempty_token(pathname, '/'), SANCTUM_PREFIX, sizeof(SANCTUM_PREFIX) - 1)){
    abs_path = combine_path_with_cwd(pathname, current->fs);

    if(!abs_path)
      return status;

    printk("Mkdir on path %s, %s\n", abs_path, get_last_nonempty_token(abs_path, '/'));

    printk("Trying to create sanctum\n");

    pid = task_pid_nr(current);

    if((new_sanctum = init_sanctum(abs_path, pid)) == 0){
      kfree(abs_path);
    }

    switch(add_sanctum(sanctums, new_sanctum)){
      case 0:
        print_sanctum(sanctums);
        return 0;

      case SEXIST:
        free_sanctum(new_sanctum);
        return EEXIST;

      default:
        free_sanctum(new_sanctum);
    }
  }

  return status;
}


// asmlinkage long sanctum_write(unsigned int fd, const char __user *buf,
// 			  size_t count){
asmlinkage long sanctum_write(const struct pt_regs* regs){
  // printk(KERN_INFO "Trying to read %ld from %u\n", count, fd);

  return ORIG_SYSCALL(__NR_write);
}
