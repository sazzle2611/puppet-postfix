#
define postfix::lookup::mysql (
  $hosts,
  $user,
  $password,
  $dbname,
  $query,
  $ensure           = 'present',
  $result_format    = undef,
  $domain           = undef,
  $expansion_limit  = undef,
  $option_file      = undef,
  $option_group     = undef,
  $tls_cert         = undef,
  $tls_key          = undef,
  $tls_ca_cert_file = undef,
  $tls_ca_cert_dir  = undef,
  $tls_verify_cert  = undef,
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
  if $option_file {
    validate_absolute_path($option_file)
  }
  validate_string($option_group)
  if $tls_cert {
    validate_absolute_path($tls_cert)
  }
  if $tls_key {
    validate_absolute_path($tls_key)
  }
  if $tls_ca_cert_file {
    validate_absolute_path($tls_ca_cert_file)
  }
  if $tls_ca_cert_dir {
    validate_absolute_path($tls_ca_cert_dir)
  }
  if $tls_verify_cert {
    validate_bool($tls_verify_cert)
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
    content => template('postfix/mysql.cf.erb'),
  }

  if $ensure != 'absent' and has_key($::postfix::lookup_packages, 'mysql') {
    $mysql_package = $::postfix::lookup_packages['mysql']
    ensure_packages([$mysql_package])
    Package[$mysql_package] -> File[$name]
  }
}
