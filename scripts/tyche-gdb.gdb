# This file is autoloaded by tyche-gdb and contains helper functions
# and setups to debug tyche+linux

# Load the linux kernel symbols along side tyche
# @warn removed so that we support rawc as well
# This is now done in the tyche-gdb script.
#add-symbol-file linux-image/images/vmlinux

# Workaround to set hardware breakpoints by default
define b
  hb $arg0
end

# Reply yes for pending breakpoints
set breakpoint pending on

# Dump the content of memory from a host physical address.
# The first argument is the format, the second is the physical host address.
define x_host_phys2virt
  x/$arg0 0x18000000000+$arg1
end

define symbol_rawc
  add-symbol-file guest/rawc
  set $tyche_guest_image=0
end

define symbol_linux
  add-symbol-file builds/linux-x86/vmlinux
  set $tyche_guest_image=1
  source builds/linux-x86/vmlinux-gdb.py
  #lx-symbols
end

define plog
  lx-dmesg
end

source scripts/tyche_debug.py

b tyche_hook_stage1
commands
tyche_set_convenience_vars
tyche_load_stage2
end

set print asm-demangle on
