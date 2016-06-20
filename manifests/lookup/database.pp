#
define postfix::lookup::database (
  $ensure  = 'present',
  $content = undef,
  $source  = undef,
  $type    = $::postfix::default_database_type,
) {

  if ! defined(Class['::postfix']) {
    fail('You must include the postfix base class before using any postfix defined resources') # lint:ignore:80chars
  }

  validate_absolute_path($name)
  validate_re($ensure, '^(?:present|absent)$')
  validate_re($type, '^(?:btree|cdb|s?dbm|(text)?hash|cidr|pcre|regexp|lmdb)$')
  if $content and $source {
    fail("You must provide either 'content' or 'source', they are mutually exclusive") # lint:ignore:80chars
  }
  validate_string($content)
  validate_string($source)

  $_ensure = $ensure ? {
    'absent' => 'absent',
    default  => 'file',
  }

  file { $name:
    ensure  => $_ensure,
    owner   => 0,
    group   => 0,
    mode    => '0600',
    content => $content,
    source  => $source,
  }

  if $ensure != 'absent' and has_key($::postfix::lookup_packages, $type) {
    $lookup_package = $::postfix::lookup_packages[$type]
    ensure_packages([$lookup_package])
    Package[$lookup_package] -> File[$name]
  }

  if $type in ['btree', 'cdb', 'dbm', 'hash', 'lmdb', 'sdbm'] {

    case $type { # lint:ignore:case_without_default
      'btree', 'hash': {
        $files = ["${name}.db"]
      }
      'cdb': {
        $files = ["${name}.cdb"]
      }
      'dbm', 'sdbm': {
        $files = ["${name}.pag", "${name}.dir"]
      }
      'lmdb': {
        $files = ["${name}.lmdb"]
      }
    }

    file { $files:
      ensure => $_ensure,
    }

    if $ensure != 'absent' {
      exec { "postmap ${type}:${name}":
        path        => $::path,
        refreshonly => true,
        subscribe   => File[$name],
        before      => File[$files],
      }
    }
  }
}
