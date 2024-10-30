
c_sources = ['tests/main.c']

rb_test_no_atomics = executable('rb_test_no_atomics', c_sources, include_directories: ['include/', include_paths['common']], c_args: ['-DTYCHE_USER_SPACE=1', '-DRB_NO_ATOMICS=1'])

rb_test_atomics = executable('rb_test_atomics', c_sources, include_directories: ['include/', include_paths['common']], c_args: ['-DTYCHE_USER_SPACE=1'])
