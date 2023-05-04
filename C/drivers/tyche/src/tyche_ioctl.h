#ifndef __TYCHE_IOCTL_H__
#define __TYCHE_IOCTL_H__

#include <linux/fs.h>
#include <linux/mm_types.h>

// —————————————————————— Registration/Unregistration ——————————————————————— //
int tyche_register(void);
void tyche_unregister(void);

// —————————————————————————————————— API ——————————————————————————————————— //
int tyche_open(struct inode* inode, struct file* file);
int tyche_close(struct inode* inode, struct file* file);
long tyche_ioctl(struct file* file, unsigned int cmd, unsigned long arg);
int tyche_mmap(struct file*, struct vm_area_struct*);

#endif /*__TYCHE_IOCTL_H__*/
