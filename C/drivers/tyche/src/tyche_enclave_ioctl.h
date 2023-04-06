#ifndef TYCHE_ENCLAVE_IOCTL
#define TYCHE_ENCLAVE_IOCTL

// —————————————————————— Registration/Unregistration ——————————————————————— //
int tyche_enclave_register(void);
void tyche_enclave_unregister(void);

// —————————————————————————————————— API ——————————————————————————————————— //
int tyche_enclave_open(struct inode* inode, struct file* file);
long tyche_enclave_ioctl(struct file* file, unsigned int cmd, unsigned long arg);

#endif
