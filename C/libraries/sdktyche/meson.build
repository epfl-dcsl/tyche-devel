
## ———————————— Includes separated into useful logical variables ———————————— ##
common_includes = [
    include_paths['common'],
    include_paths['dll'],
    include_paths['capas'],
    include_directories('include/'),
  ]

loader_includes =  [include_paths['elf']] + common_includes

with_pts_includes = loader_includes + [
    include_paths['pts']
  ]

tyche_loader_includes = with_pts_includes + [
    include_paths['tyche-driver'],
  ]

kvm_loader_includes = with_pts_includes + [
    include_paths['tyche-driver'],
    include_paths['contalloc-driver'],
  ]

## —————————————————————————————— Source files —————————————————————————————— ##

c_runtime_src = [files('runtime/lib.c')]
if arch == 'x86'
  c_runtime_src += files('runtime/asm.S')
elif arch == 'riscv'
  c_runtime_src += files('runtime/riscv_asm.S')
endif

c_loader_src = [files('loader/lib.c'), files('loader/helper.c')]
c_back_tyche_src = [files('loader/backends/back_tyche.c')]
c_back_kvm_src = [files('loader/backends/back_kvm.c')]
c_code_capas = [
    files(meson.source_root() + '/../linux/drivers/tyche/libraries/capabilities/src/ecs.c'),
    files(meson.source_root() + '/../linux/drivers/tyche/libraries/capabilities/src/lib.c'),
    files(meson.source_root() + '/../linux/drivers/tyche/libraries/capabilities/src/tyche_api.c'),
  ]

## ——————————————————————————— SDKs as libraries ———————————————————————————— ##
sdktyche_loader = static_library('sdktyche_loader', c_loader_src + c_back_tyche_src,
  include_directories: tyche_loader_includes, c_args: ['-DTYCHE_USER_SPACE=1', '-D_GNU_SOURCE'], link_with: elf64_static)

if arch == 'x86'
sdkkvm_loader = static_library('sdk_kvm_loader', c_loader_src + c_back_kvm_src,
  include_directories: kvm_loader_includes, c_args: ['-DTYCHE_USER_SPACE=1', '-DRUN_WITH_KVM=1'], link_with: elf64_static)
endif

## —————————————— Useful cflags for the sdk-based applications —————————————— ##
tyche_ucflags = ['-DTYCHE_USER_SPACE=1', '-static']
tyche_tcflags = ['-DTYCHE_USER_SPACE=2', '-nostdlib', '-static']
if sdk == 'kvm'
  tyche_ucflags += ['-DRUN_WITH_KVM=1']
  tyche_tcflags += ['-DRUN_WITH_KVM=1']
endif

# TODO: figure out how to allow undefined symbols.
#sdk_tyche_runtime = shared_library('sdk_tyche_runtime', c_code_capas + c_runtime_src, 
#  include_directories: common_includes, c_args: ['-DTYCHE_USER_SPACE=1', '-g'], link_args: ['-Wl,--undefined'])

## —————————————————————————————— Subprojects ——————————————————————————————— ##
subdir('example')
