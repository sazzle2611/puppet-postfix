#
define postfix::lookup::ldap (
  $search_base,
  $server_host               = undef,
  $server_port               = undef,
  $timeout                   = undef,
  $query_filter              = undef,
  $result_format             = undef,
  $domain                    = undef,
  $result_attribute          = undef,
  $special_result_attribute  = undef,
  $terminal_result_attribute = undef,
  $leaf_result_attribute     = undef,
  $scope                     = undef,
  $bind                      = undef,
  $bind_dn                   = undef,
  $bind_pw                   = undef,
  $recursion_limit           = undef,
  $expansion_limit           = undef,
  $size_limit                = undef,
  $dereference               = undef,
  $chase_referrals           = undef,
  $version                   = undef,
  $debuglevel                = undef,
  $sasl_mechs                = undef,
  $sasl_realm                = undef,
  $sasl_authz_id             = undef,
  $sasl_minssf               = undef,
  $start_tls                 = undef,
  $tls_ca_cert_dir           = undef,
  $tls_ca_cert_file          = undef,
  $tls_cert                  = undef,
  $tls_key                   = undef,
  $tls_require_cert          = undef,
  $tls_random_file           = undef,
  $tls_cipher_suite          = undef,
) {

  if ! defined(Class['::postfix']) {
    fail('You must include the postfix base class before using any postfix defined resources') # lint:ignore:80chars
  }

  validate_absolute_path($name)
  validate_string($search_base)
  validate_ldap_dn($search_base)
  if $server_host {
    # FIXME
    validate_array($server_host)
  }
  if $server_port {
    validate_integer($server_port, '', 0)
  }
  if $timeout {
    validate_integer($timeout, '', 0)
  }
  if $query_filter {
    validate_string($query_filter)
    validate_ldap_filter($query_filter)
  }
  validate_string($result_format)
  if $domain {
    validate_array($domain)
  }
  if $result_attribute {
    validate_array($result_attribute)
  }
  if $special_result_attribute {
    validate_array($special_result_attribute)
  }
  if $terminal_result_attribute {
    validate_array($terminal_result_attribute)
  }
  if $leaf_result_attribute {
    validate_array($leaf_result_attribute)
  }
  if $scope {
    validate_re($scope, '^(sub|base|one)$')
  }
  if $bind {
    if ! is_bool($bind) {
      validate_re($bind, '^(sasl|none|simple)$')
    }
  }
  if $bind_dn {
    validate_string($bind_dn)
    validate_ldap_dn($bind_dn)
  }
  validate_string($bind_pw)
  if $recursion_limit {
    validate_integer($recursion_limit, '', 1)
  }
  if $expansion_limit {
    validate_integer($expansion_limit, '', 0)
  }
  if $size_limit {
    validate_integer($size_limit, '', 0)
  }
  if $dereference {
    validate_integer($dereference, 3, 0)
  }
  if $chase_referrals {
    validate_bool($chase_referrals)
  }
  if $version {
    validate_integer($version, 3, 2)
  }
  if $debuglevel {
    validate_integer($debuglevel, '', 0)
  }
  if $sasl_mechs {
    validate_array($sasl_mechs)
  }
  validate_string($sasl_realm)
  validate_string($sasl_authz_id)
  if $sasl_minssf {
    validate_integer($sasl_minssf, '', 0)
  }
  if $start_tls {
    validate_bool($start_tls)
  }
  if $tls_ca_cert_dir {
    validate_absolute_path($tls_ca_cert_dir)
  }
  if $tls_ca_cert_file {
    validate_absolute_path($tls_ca_cert_file)
  }
  if $tls_cert {
    validate_absolute_path($tls_cert)
  }
  if $tls_key {
    validate_absolute_path($tls_key)
  }
  if $tls_require_cert {
    validate_bool($tls_require_cert)
  }
  if $tls_random_file {
    validate_absolute_path($tls_random_file)
  }
  validate_string($tls_cipher_suite)

  file { $name:
    ensure  => file,
    owner   => 0,
    group   => 0,
    mode    => '0600',
    content => template('postfix/ldap.cf.erb'),
  }

  if has_key($::postfix::lookup_packages, 'ldap') {
    $ldap_package = $::postfix::lookup_packages['ldap']
    ensure_packages([$ldap_package])
    Package[$ldap_package] -> File[$name]
  }
}
