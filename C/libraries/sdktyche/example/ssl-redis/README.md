# SSL Redis

## What we run

```
     TDO           TD1           TD2
| untrusted | <=> | ssl | <=> | redis |
               |     |      |
               |     |      |-> 1 pipe confidential w/ channel
               |     |-> decrypt/encrypt
               |
               |-> Shared untrusted memory w/ channel
```

## Compilation

We need to disable relro (similar to tyche-redis) because otherwise globals are not initialized.
We also need to disable stack protection that accesses stack guards through FS register.
