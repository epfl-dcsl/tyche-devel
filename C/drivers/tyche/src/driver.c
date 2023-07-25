#include "tyche_ioctl.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "common.h"

// —————————————————————————————— Module Info ——————————————————————————————— //

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tyche team");
MODULE_DESCRIPTION("Tyche Driver");
MODULE_VERSION("0.01");


// —————————————————————— Loading/Unloading  functions —————————————————————— //
static int __init tyche_init(void)
{
  int result = 0;
  printk(KERN_INFO "Loading Tyche driver.");
  result = tyche_register();
  return result;
}

static void __exit tyche_exit(void)
{
  printk(KERN_INFO "Removing Tyche driver.");
  tyche_unregister();
}

// ————————————————————————— Module's Registration —————————————————————————— //

module_init(tyche_init);
module_exit(tyche_exit);
