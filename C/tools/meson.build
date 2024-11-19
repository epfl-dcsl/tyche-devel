transition_code = ['transition.c']
futest_code = ['futest.c']
debugging_registers_code = ['debugging_registers.c']

# Build the binary that allows to transition from non-confidential to confidential.
transition = executable(
  'transition',
  transition_code,
)

# A simple program to test futext
futest = executable(
  'futest',
  futest_code
  )

if arch == 'x86'
  debugging_registers = executable(
    'debugging_registers',
    debugging_registers_code
    )
endif
