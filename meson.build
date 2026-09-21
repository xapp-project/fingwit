project('fingwit', 'c', version : '1.1.0', meson_version : '>= 0.59.0')

# Python installation
python = import('python').find_installation('python3')

# Get directories
prefix = get_option('prefix')
bindir = get_option('bindir')
datadir = get_option('datadir')
libdir = get_option('libdir')
libexecdir = get_option('libexecdir')

custom_target('fingwit_versioned',
    input: 'fingwit',
    output: 'fingwit',
    command: ['sed', 's/__PROJECT_VERSION__/@0@/g'.format(meson.project_version()), '@INPUT@'],
    capture: true,
    install: true,
    install_dir: bindir,
    install_mode: 'rwxr-xr-x'
)

# Build PAM module
pam_dep = dependency('pam', required: true)

# The PAM module runs the helper with euid 0, so the interpreter must be named
# by an absolute path: resolving it through PATH lets any local user run code
# as root (issue #54) and picks up pyenv/conda interpreters that lack the
# python3-gi bindings (issue #51).
python_executable = get_option('python_executable')
if not python_executable.startswith('/')
    error('python_executable must be an absolute path, got: ' + python_executable)
endif

# PAM configs directory
pam_config_dir = join_paths(get_option('prefix'), datadir, 'pam-configs')
# Install pam config
install_data('fingwit.pam_config',
    rename: 'fingwit',
    install_dir: pam_config_dir
)

# Python script directory
pam_python_dir = join_paths(get_option('prefix'), libdir, 'fingwit')
# PAM module directory
pam_module_dir = join_paths(get_option('prefix'), libdir, 'security')

# Compile C wrapper to .so
pam_fingwit_so = shared_library('pam_fingwit',
    'pam_fingwit.c',
    dependencies: [pam_dep],
    name_prefix: '',
    install: true,
    install_dir: pam_module_dir,
    c_args: ['-DPYTHON_SCRIPT_DIR="' + pam_python_dir + '"',
             '-DPYTHON_EXECUTABLE="' + python_executable + '"']
)

# Install Python script
install_data('pam_fingwit.py',
    install_dir: pam_python_dir,
    install_mode: 'rwxr-xr-x'
)

# Install translations
subdir('data')
subdir('po')

summary({
  'pam_module_dir': pam_module_dir,
  'pam_python_dir': pam_python_dir,
  'python_executable': python_executable,
  'compiler': meson.get_compiler('c').get_id(),
}, section: 'Configuration')
