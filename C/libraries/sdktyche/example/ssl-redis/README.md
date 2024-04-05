# Encryption Redis

## What we run

```
     TDO           TD1           TD2
| untrusted | <=> | encr | <=> | redis |
               |     |      |
               |     |      |-> 1 pipe confidential w/ channel
               |     |-> decrypt/encrypt
               |
               |-> Shared untrusted memory w/ channel
```
