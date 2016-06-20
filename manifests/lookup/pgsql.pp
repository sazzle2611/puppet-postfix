#
define postfix::lookup::pgsql (
  $hosts,
  $user,
  $password,
  $dbname,
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
  validate_array($hosts)
  validate_string($user)
  validate_string($password)
  validate_string($dbname)
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
    content => template('postfix/pgsql.cf.erb'),
  }

  if $ensure != 'absent' and has_key($::postfix::lookup_packages, 'pgsql') {
    $pgsql_package = $::postfix::lookup_packages['pgsql']
    ensure_packages([$pgsql_package])
    Package[$pgsql_package] -> File[$name]
  }
}
