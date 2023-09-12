.globl bricks_divide_by_zero_exception
bricks_divide_by_zero_exception: 
    sti
    mov $0, %ebx
    div %ebx

.globl bricks_int_exception
bricks_int_exception: 
    sti
    int $1