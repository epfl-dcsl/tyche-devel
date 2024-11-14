## ————————————————————————— Generate the manifests ————————————————————————— ##
types = ['carve', 'enclaves', 'sandboxes']
sizes = ['8k', '12k', '32k', '64k', '128k', '256k', '512k', '1M', '10M']

type_configs = {
    'carve': {'tpe': 'KernelConfidential', 'security': 'Confidential'},
    'enclaves': {'tpe': 'KernelConfidential', 'security': 'Confidential'},
    'sandboxes': {'tpe': 'KernelConfidential', 'security': 'Confidential'},
  }

real_sizes = {
  '8k': '0',
  '12k': '4096',
  '32k': '24576',
  '64k': '57344',
  '128k': '122880',
  '256k': '253952',
  '512k': '516096',
  '1M': '995328',
  '10M': '10477568',
  }

## ————————————————————————————— Configuration —————————————————————————————— ##
if sdk == 'kvm'
  tyche_loader = sdkkvm_loader
  tyche_includes = kvm_loader_includes
else 
  tyche_loader = sdktyche_loader
  tyche_includes = tyche_loader_includes
endif

trans_code = ['transition/main.c']
linking = ['-static', '-nostdlib']
if arch == 'riscv'
  code_dom = ['domain/riscv_asm.S']
  trans_code += ['transition/riscv_asm.S']
  c_flags = ['-DCONFIG_RISCV']
  linking += ['pthread', '-Wl,--section-start=.data=0x16000']
else
  code_dom = ['domain/asm.S']
  trans_code += ['transition/asm.S']
  c_flags = []
endif

# Mock application to instrument with enclaves.
mock_app = executable('mock_app',
  ['mock/main.c'],
  c_args: ['-static'],
  link_args: ['-static'],
  install: true,
  install_dir: meson.current_source_dir(),
  )

# Mock code for the domain, it has two pages.
mock_dom = executable('mock_dom',
  code_dom,
  c_args: ['-static', '-nostdlib'],
  link_args: linking
  )

trans_dom = executable('trans_dom',
  trans_code + c_code_capas + c_runtime_src,
  include_directories: common_includes + ['include/'], 
  c_args: c_flags + ['-DTYCHE_USER_SPACE=2', '-nostdlib', '-static'],
  link_args: linking,
  )

code_bench = ['src/attestation.c', 'src/creation.c', 'src/display.c',
  'src/environment.c', 'src/hwcomm.c', 'src/main.c', 'src/measurement.c',
  'src/transition.c']

runbench = executable(
  'runbench',
  code_bench + c_code_capas,
  include_directories: tyche_includes + ['include/'],
  c_args: c_flags + ['-DTYCHE_USER_SPACE=1', '-static'],
  link_args: ['-static'],
  link_with: tyche_loader,
  )

# Compile the microbenchmarks for all configurations.
foreach t: types
    # Create the output directory if necessary
    create_dir = custom_target(
      'create_custom_dir_' + t,
      command: ['mkdir', '-p', meson.current_build_dir() / 'bin' / t],
      output: 'custom_dir_marker_' + t 
    )
  foreach s: sizes
    # Generate the manifests.
    out_prefix = s
    manifest = configure_file(
      input: 'templates/default.json',
      output: t + '_' + out_prefix + '_manifest',
      configuration: {
        'UNTRUSTED_PATH': mock_app.full_path(),
        'TRUSTED_PATH': mock_dom.full_path(),
        'SEGMENT_SIZE': real_sizes[s],
        'TPE': type_configs[t]['tpe'],
        'SECURITY': type_configs[t]['security'],
        'OUTPUT': meson.current_build_dir()+ '/bin/' + t + '/' + out_prefix,
        })
    t_cmd = tychools_cmd + manifest.full_path()
    if arch == 'riscv'
      t_cmd += '--riscv-enabled'
    endif
    instr = custom_target(
      t + '_' + out_prefix,
      output: t + '_' + out_prefix,
      command: t_cmd + ['&&', 'chmod', '+x', meson.current_build_dir() + '/bin/' + t + '/' + out_prefix],
      install: true,
      install_dir: 'microbenchmarks/bin/'+t,
      input: [mock_app, mock_dom, trans_dom, create_dir],
      )
  endforeach
endforeach
