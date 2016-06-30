#
define postfix::main (
  $value,
  $ensure = 'present',
) {

  if ! defined(Class['::postfix']) {
    fail('You must include the postfix base class before using any postfix defined resources') # lint:ignore:80chars
  }

  validate_re($name, '^\S+$')
  validate_string($value)
  validate_re($ensure, '^(?:present|absent)$')

  postfix_main { $name:
    ensure  => $ensure,
    value   => $value,
    target  => "${::postfix::conf_dir}/main.cf",
    require => Class['::postfix::config'],
    notify  => Class['::postfix::service'],
  }
}
