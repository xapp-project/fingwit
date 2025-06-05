project('fingwit',
        version: '1.0.0',
        meson_version: '>= 0.59.0')

# Python installation
python = import('python').find_installation('python3')

# Get directories
prefix = get_option('prefix')
bindir = get_option('bindir')
datadir = get_option('datadir')
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

# Install translations
subdir('data')
subdir('po')
