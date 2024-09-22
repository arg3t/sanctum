#include <linux/cred.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/module.h>

#ifndef SANCTUM_DEVICE_H
#define SANCTUM_DEVICE_H

extern dev_t DEVICE;
extern struct class *DEVICE_CLASS;

int sanctum_device_init(const char *device_name);

void sanctum_device_destroy(void);

static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

#endif
