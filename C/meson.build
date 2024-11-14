project('tyche-c', 'c')

## —————————————————————— Get the target architecture ——————————————————————— ##
arch = get_option('arch')
sdk = get_option('sdk')
current_dir = meson.current_source_dir()

if arch == 'x86'
  message('Building for x86')
  gcc_version = 'gcc'
elif arch == 'riscv'
  message('Building for riscv')
  if sdk == 'kvm'
    error('sdk kvm is not supported for riscv!')
  endif
  ##gcc_version = current_dir+'/../target/riscv64gc-unknown-linux-gnu/release'
else 
  error('Unsupported architecture: '+ arch)
endif

## ———————————————————————————— Global variables ———————————————————————————— ##

library_paths = {
    'common': include_directories('../linux/drivers/tyche/libraries/common'),
    'tyche-driver': include_directories('../linux/drivers/tyche'),
    'contalloc-driver': include_directories('../linux/drivers/contalloc'),
    'dll': include_directories('../linux/drivers/tyche/libraries/dll'),
    'capas': include_directories('../linux/drivers/tyche/libraries/capabilities'),
    'elf': include_directories('libraries/elf64'),
    'pts': include_directories('libraries/pts'),
  }

include_paths = {
    'common': include_directories('../linux/drivers/tyche/libraries/common/include'),
    'tyche-driver': include_directories('../linux/drivers/tyche/include'),
    'contalloc-driver': include_directories('../linux/drivers/contalloc/include'),
    'dll': include_directories('../linux/drivers/tyche/libraries/dll/include'),
    'capas': include_directories('../linux/drivers/tyche/libraries/capabilities/include'),
    'elf': include_directories('libraries/elf64/include'),
    'pts': include_directories('libraries/pts/include'),
  }

tychools_path = join_paths(meson.current_source_dir(), '../crates/tychools/')

## ————————————————————————— Tychools configuration ————————————————————————— ##
tychools_install_cmd = ['cargo', '-Z', 'unstable-options', '-C', tychools_path,
  'install', '--path', '.', '--locked']
tychools_cmd = ['tychools', 'instrument', '-s']

install_tychools = custom_target('install-tychools',
  command: tychools_install_cmd, output: 'install-tychools')

## ————————————————————————————— Subdirectories ————————————————————————————— ##
subdir('libraries')
subdir('microbenchmarks')
