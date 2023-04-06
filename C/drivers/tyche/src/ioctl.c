#include <linux/ioctl.h>
#include <linux/kernel.h>   /* printk() */
#include <linux/cdev.h> 
#include <linux/device.h>
#include <linux/fs.h>

#include "common.h"
#include "enclaves.h"
#define _IN_MODULE
#include "tyche_enclave.h"
#include "tyche_ioctl.h"
#undef _IN_MODULE
// —————————————————————— Global Driver Configuration ——————————————————————— //
static char* device_name = "tyche";
static char* device_class = "tyche";
static char* device_region = "tyche";

dev_t dev = 0;
static struct cdev tyche_cdev;
static struct class *dev_class;

// —————————————————————————————— Local State ——————————————————————————————— //
static enclave_handle_t tyche_ids = 0; 

// ———————————————————————————— File Operations ————————————————————————————— //

// File operation structure
static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .open           = tyche_open,
        .unlocked_ioctl = tyche_ioctl,
        .mmap           = tyche_mmap,
};

// ———————————————————————————— Driver Functions ———————————————————————————— //


int tyche_enclave_register(void)
{
  // Allocating Major number
  if((alloc_chrdev_region(&dev, 0, 1, device_region)) <0){
    ERROR("cannot allocate major number\n");
    return FAILURE;
  }
  LOG("Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

  // Creating the cdev structure
  cdev_init(&tyche_cdev, &fops);

  // Adding character device to the system.
  if ((cdev_add(&tyche_cdev, dev, 1)) < 0)
  {
    ERROR("Cannot add the device to the system.\n");
    goto r_class;
  }

  // Creating the struct class.
  if ((dev_class = class_create(THIS_MODULE, device_class)) == NULL)
  {
    ERROR("Cannot create the struct class.\n");
    goto r_class;
  }

  // Creating the device.
  if ((device_create(dev_class, NULL, dev, NULL, device_name)) == NULL)
  {
    ERROR("Cannot create the Device 1\n");
    goto r_device;
  }

  init_enclaves();
  LOG("Tyche driver registered!\n");
  return SUCCESS; 

r_device:
  class_destroy(dev_class);
r_class:
  unregister_chrdev_region(dev, 1);
  return FAILURE;
}

void tyche_unregister(void)
{
  device_destroy(dev_class, dev);
  class_destroy(dev_class);
  cdev_del(&tyche_cdev);
  unregister_chrdev_region(dev, 1);
  LOG("Tyche driver unregistered!\n");
}

// —————————————————————————————————— API ——————————————————————————————————— //

int tyche_open(struct inode* inode, struct file* file) 
{
  LOG("Tyche opened from user space.");
  return SUCCESS;
}


long tyche_ioctl(struct file* file, unsigned int cmd, unsigned long arg)
{
  //TODO
  return FAILURE;
}

int tyche_mmap(struct file *file, struct vm_area_struct *vma)
{
  //TODO
  return FAILURE;
}
