if arch == 'x86'
  c_sources = ['src/lib.c', 'src/x86_64_pt.c']
elif arch == 'riscv'
  c_sources = ['src/lib.c', 'src/riscv48_pt.c']
else
  error('Unknown architecture: '+ arch)
endif

pts_static = static_library('pts', c_sources, include_directories: ['include/', include_paths['common']], c_args: ['-DTYCHE_USER_SPACE=1', '-nostdlib'])

if arch == 'x86'
  test_x86 = executable('test_x86', 'tests/test_x86.c', include_directories: ['include/', include_paths['common']], c_args: ['-DTYCHE_USER_SPACE=1'], link_with: pts_static)

elif arch == 'riscv'
  test_riscv = executable('test_riscv', 'tests/test_riscv48.c', include_directories: ['include/', include_paths['common']], c_args: ['-DTYCHE_USER_SPACE=1'], link_with: pts_static)
endif
