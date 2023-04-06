#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

// —————————————————————————————— Module Info ——————————————————————————————— //

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tyche team");
MODULE_DESCRIPTION("Tyche Driver");
MODULE_VERSION("0.01");


// —————————————————————— Loading/Unloading  functions —————————————————————— //
static int __init tyche_enclave_init(void)
{
  int result = 0;
  printk(KERN_INFO "Loading Tyche Enclave LKM driver.");
  return result;
}

static void __exit tyche_enclave_exit(void)
{
  printk(KERN_INFO "Removing Tyche Enclave LKM driver.");
}

// ————————————————————————— Module's Registration —————————————————————————— //

module_init(tyche_enclave_init);
module_exit(tyche_enclave_exit);
