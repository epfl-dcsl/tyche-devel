# Ringbuf

A non-libc implementation of ring buffers.
The library avoids performing allocations as it needs to be used in a non-libc environment.
It supports only single writer and single readers!
It should however support reading and writing from separate threads when the `RB_NO_ATOMICS` is not defined.
