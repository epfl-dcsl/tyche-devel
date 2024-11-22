## ————————————————————————————— File specific —————————————————————————————— ##
u_sources = ['untrusted/main.c']
t_sources = ['trusted/main.c']

path = meson.current_source_dir()
out_name = 'app'
in_name = 'enclave'
end_name = 'cpuid_enclave'

## —————————————————————————— Common configuration —————————————————————————— ##
if sdk == 'kvm'
  tyche_loader = sdkkvm_loader
  tyche_includes = kvm_loader_includes
else 
  tyche_loader = sdktyche_loader
  tyche_includes = tyche_loader_includes
endif

linking = ['-static', '-nostdlib']
if arch == 'riscv'
  linking += ['-pthread', '-Wl,--section-start=.data=0x16000']
endif

# build the untrusted application.
app = executable(out_name,
  u_sources,
  include_directories: tyche_includes + [include_directories('include/')],
  c_args: tyche_ucflags,
  link_args: ['-static'],
  link_with: tyche_loader)

# build the domain's code.
dom = executable(in_name, 
  t_sources + c_runtime_src + c_code_capas, 
  include_directories: common_includes + ['include/'], 
  c_args: tyche_tcflags,
  link_args: linking,
  )

# Configure the manifest file
# Use configure_file to replace placeholders in the template
manifest = configure_file(
  input: 'manifests/default_input.json',
  output: 'default_output.json',
  configuration: {
    'UNTRUSTED_PATH': app.full_path(),
    'TRUSTED_PATH': dom.full_path(),
  }
)

# call the custom tychool
t_cmd = tychools_cmd + manifest.full_path()
if arch == 'riscv'
  t_cmd += '--riscv-enabled'
endif

instr = custom_target(
    end_name,
    command: t_cmd + ['&&', 'chmod', '+x', end_name],
    install: true,
    install_dir: 'programs',
    input: [app, dom, manifest],
    output: end_name,
  )
