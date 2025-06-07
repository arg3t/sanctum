#include <linux/cdev.h>      // Required for cdev functions
#include <linux/device.h>    // Required for device functions
#include "device.h"
#include "hooks.h"

dev_t DEVICE;
struct class *DEVICE_CLASS;
struct cdev DEVICE_CDEV;     // Character device structure

static struct file_operations fops = {
    .owner = THIS_MODULE,    // Important for module reference counting
    .write = dev_write
};

int sanctum_device_init(const char *device_name) {
    int ret;
    struct device *dev;

    /* Allocate major/minor numbers */
    if ((ret = alloc_chrdev_region(&DEVICE, 0, 1, device_name)) < 0) {
        pr_err("Cannot allocate major number\n");
        return ret;
    }

    /* Create device class */
    DEVICE_CLASS = class_create(device_name);
    if (IS_ERR(DEVICE_CLASS)) {
        pr_err("Cannot create device class\n");
        ret = PTR_ERR(DEVICE_CLASS);
        goto r_class;
    }

    /* Initialize and add character device */
    cdev_init(&DEVICE_CDEV, &fops);
    if ((ret = cdev_add(&DEVICE_CDEV, DEVICE, 1)) < 0) {
        pr_err("Cannot add character device\n");
        goto r_cdev;
    }

    /* Create device node */
    dev = device_create(DEVICE_CLASS, NULL, DEVICE, NULL, device_name);
    if (IS_ERR(dev)) {
        pr_err("Cannot create device\n");
        ret = PTR_ERR(dev);
        goto r_device;
    }

    pr_info("Device initialized successfully\n");
    return 0;

r_device:
    cdev_del(&DEVICE_CDEV);
r_cdev:
    class_destroy(DEVICE_CLASS);
r_class:
    unregister_chrdev_region(DEVICE, 1);
    return ret;
}

void sanctum_device_destroy() {
    device_destroy(DEVICE_CLASS, DEVICE);
    cdev_del(&DEVICE_CDEV);
    class_destroy(DEVICE_CLASS);
    unregister_chrdev_region(DEVICE, 1);
}
