
elf64_static = static_library('elf64', 'src/lib.c' , include_directories : ['include/', include_paths['common']], c_args: ['-DTYCHE_USER_SPACE=1'])

elf64_shared = shared_library('elf64', 'src/lib.c' , include_directories : ['include/', include_paths['common']], c_args: ['-DTYCHE_USER_SPACE=1'])

test_elf64 = executable('test_elf64', 'tests/test.c', include_directories: ['include', include_paths['common']], link_with: elf64_shared, c_args: ['-DTYCHE_USER_SPACE=1'])
