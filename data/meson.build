
install_subdir(
  'icons',
  install_dir: join_paths(prefix, datadir)
)

install_subdir(
	'fingwit',
	install_dir: join_paths(prefix, datadir)
)

schema_file = install_data(
    'org.x.fingwit.gschema.xml',
    install_dir: join_paths(datadir, 'glib-2.0', 'schemas')
)

# Desktop file with translations using standard meson i18n
i18n = import('i18n')
desktop_file = i18n.merge_file(
    input: 'fingwit.desktop.in',
    output: 'fingwit.desktop',
    type: 'desktop',
    po_dir: join_paths(meson.project_source_root(), 'po'),
    install: true,
    install_dir: join_paths(get_option('datadir'), 'applications')
)