#include "device.h"

dev_t DEVICE;
struct class *DEVICE_CLASS;

static struct file_operations fops = {.write = dev_write};

int sanctum_device_init(const char *device_name) {
  /*Allocating Major number*/
  if ((alloc_chrdev_region(&DEVICE, 0, 1, device_name)) < 0) {
    pr_err("Cannot allocate major number for device\n");
    return -1;
  }

  pr_info("Major = %d Minor = %d \n", MAJOR(DEVICE), MINOR(DEVICE));

  /*Creating struct class*/
  DEVICE_CLASS = class_create(device_name);

  if (IS_ERR(DEVICE_CLASS)) {
    pr_err("Cannot create the struct class for device\n");
    goto r_class;
  }

  /*Creating device*/
  if (IS_ERR(device_create(DEVICE_CLASS, NULL, DEVICE, NULL, device_name))) {
    pr_err("Cannot create the Device\n");
    goto r_device;
  }

  pr_info("Kernel Module Inserted Successfully...\n");
  return 0;

r_device:
  class_destroy(DEVICE_CLASS);
r_class:
  unregister_chrdev_region(DEVICE, 1);
  return -1;
}

void sanctum_device_destroy() {
  device_destroy(DEVICE_CLASS, DEVICE);
  class_destroy(DEVICE_CLASS);
  unregister_chrdev_region(DEVICE, 1);
}

static ssize_t dev_write(struct file *, const char *, size_t, loff_t *) {}
