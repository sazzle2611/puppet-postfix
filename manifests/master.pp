#
define postfix::master (
  $command,
  $ensure       = 'present',
  $private      = undef,
  $unprivileged = undef,
  $chroot       = undef,
  $wakeup       = undef,
  $limit        = undef,
) {

  if ! defined(Class['::postfix']) {
    fail('You must include the postfix base class before using any postfix defined resources') # lint:ignore:80chars
  }

  validate_re($name, '^[a-z]+/(?:inet|unix|fifo|pass)$')
  validate_string($command)
  validate_re($ensure, '^(?:present|absent)$')
  if $private {
    validate_re($private, '^[-ny]$')
  }
  if $unprivileged {
    validate_re($unprivileged, '^[-ny]$')
  }
  if $chroot {
    validate_re($chroot, '^[-ny]$')
  }
  if $wakeup {
    validate_re($wakeup, '^(?:-|\d+[?]?)$')
  }
  if $limit {
    validate_re($limit, '^(?:-|\d+)$')
  }

  postfix_master { $name:
    ensure       => $ensure,
    command      => $command,
    private      => $private,
    unprivileged => $unprivileged,
    chroot       => $chroot,
    wakeup       => $wakeup,
    limit        => $limit,
    target       => "${::postfix::conf_dir}/master.cf",
    require      => Class['::postfix::config'],
    notify       => Class['::postfix::service'],
  }
}
