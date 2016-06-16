#
define postfix::lookup::database (
  $content = undef,
  $source  = undef,
  $type    = $::postfix::default_database_type,
) {

  if ! defined(Class['::postfix']) {
    fail('You must include the postfix base class before using any postfix defined resources') # lint:ignore:80chars
  }

  validate_absolute_path($name)
  validate_re($type, '^(btree|cdb|s?dbm|(text)?hash|cidr|pcre|regexp|lmdb)$')
  if $content and $source {
    fail("You must provide either 'content' or 'source', they are mutually exclusive") # lint:ignore:80chars
  }
  validate_string($content)
  validate_string($source)

  file { $name:
    ensure  => file,
    owner   => 0,
    group   => 0,
    mode    => '0600',
    content => $content,
    source  => $source,
  }

  if has_key($::postfix::lookup_packages, $type) {
    $lookup_package = $::postfix::lookup_packages[$type]
    ensure_packages([$lookup_package])
    Package[$lookup_package] -> File[$name]
  }

  if $type in ['btree', 'cdb', 'dbm', 'hash', 'lmdb', 'sdbm'] {
    $postmap = "postmap ${type}:${name}"

    exec { $postmap:
      path        => $::path,
      refreshonly => true,
      subscribe   => File[$name],
    }

    case $type { # lint:ignore:case_without_default
      'btree', 'hash': {
        file { "${name}.db":
          ensure  => file,
          require => Exec[$postmap],
        }
      }
      'cdb': {
        file { "${name}.cdb":
          ensure  => file,
          require => Exec[$postmap],
        }
      }
      'dbm', 'sdbm': {
        file { "${name}.pag":
          ensure  => file,
          require => Exec[$postmap],
        }

        file { "${name}.dir":
          ensure  => file,
          require => Exec[$postmap],
        }
      }
      'lmdb': {
        file { "${name}.lmdb":
          ensure  => file,
          require => Exec[$postmap],
        }
      }
    }
  }
}
