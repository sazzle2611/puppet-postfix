#
define postfix::lookup::sqlite (
  $dbpath,
  $query,
  $ensure          = 'present',
  $result_format   = undef,
  $domain          = undef,
  $expansion_limit = undef,
) {

  if ! defined(Class['::postfix']) {
    fail('You must include the postfix base class before using any postfix defined resources') # lint:ignore:80chars
  }

  validate_absolute_path($name)
  validate_re($ensure, '^(?:present|absent)$')
  validate_absolute_path($dbpath)
  validate_string($query)
  validate_string($result_format)
  if $domain {
    validate_array($domain)
  }
  if $expansion_limit {
    validate_integer($expansion_limit, '', 0)
  }

  $_ensure = $ensure ? {
    'absent' => 'absent',
    default  => 'file',
  }

  file { $name:
    ensure  => $_ensure,
    owner   => 0,
    group   => 0,
    mode    => '0600',
    content => template('postfix/sqlite.cf.erb'),
  }

  if $ensure != 'absent' and has_key($::postfix::lookup_packages, 'sqlite') {
    $sqlite_package = $::postfix::lookup_packages['sqlite']
    ensure_packages([$sqlite_package])
    Package[$sqlite_package] -> File[$name]
  }
}
