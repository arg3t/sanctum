#include "device.h"
#include "hooker.h"
#include "hooks.h"
#include "linux/kern_levels.h"
#include "linux/printk.h"
#include "protected.h"
#include <linux/kallsyms.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yigit Colakoglu");
MODULE_DESCRIPTION("TODO");

static int __init sanctum_init(void) {
  int i;

  printk(KERN_INFO "All lights are green...\n");
  printk(KERN_INFO "Found sys_close %lx\n",
         (unsigned long)get_original_syscall(__NR_read));

  i = 0;
  while (HOOKED_CALLS[i][1]) {
    hook_syscall((unsigned int)(uintptr_t)HOOKED_CALLS[i][0],
                 HOOKED_CALLS[i][1]);
    i++;
  }

  sanctums = init_sanctum(NULL, 0, NULL, 0);

  sanctum_device_init(SANCTUM_DEVICE_NAME);

  return 0;
}

static void __exit sanctum_exit(void) {
  free_all_sanctums(sanctums);
  sanctum_device_destroy();
  unhook_all();
}

module_init(sanctum_init);
module_exit(sanctum_exit);
