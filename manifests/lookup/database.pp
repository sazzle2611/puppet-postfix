# Define lookup tables using static database files.
#
# @example Define a `transport(5)` table
#   postfix::lookup::database { '/etc/postfix/transport':
#     content => @(EOS/L),
#       example.com :
#       | EOS
#     type    => 'hash',
#   }
#
# @example Manage the `aliases(5)` table with `mailalias` resources
#   postfix::lookup::database { '/etc/aliases':
#     type => 'hash',
#   }
#   Mailalias <||> -> Postfix::Lookup::Database['/etc/aliases']
#
# @param ensure
# @param path
# @param type
# @param content
# @param source
#
# @see puppet_classes::postfix postfix
#
# @since 1.0.0
define postfix::lookup::database (
  Enum['present', 'absent']       $ensure  = 'present',
  Stdlib::Absolutepath            $path    = $title,
  Postfix::Type::Lookup::Database $type    = $postfix::default_database_type,
  Optional[String]                $content = undef,
  Optional[String]                $source  = undef,
) {

  include postfix

  if $content and $source {
    fail('Only one of $content or $source should be specified.')
  }

  $_ensure = $ensure ? {
    'absent' => 'absent',
    default  => 'file',
  }

  file { $path:
    ensure  => $_ensure,
    owner   => 0,
    group   => 0,
    mode    => '0644',
    content => $content,
    source  => $source,
  }

  # Changes to files that aren't hashed generally don't get picked up without
  # a reload so trigger one
  if $type =~ Postfix::Type::Lookup::Database::Flat {
    File[$path] ~> Class['postfix::service']
  }

  if $ensure != 'absent' and $type in $postfix::lookup_packages {
    $lookup_package = $postfix::lookup_packages[$type]
    ensure_packages([$lookup_package])
    Package[$lookup_package] -> File[$path]
  }

  if $type =~ Postfix::Type::Lookup::Database::Hashed {

    case $type {
      'btree', 'hash': {
        $files = ["${path}.db"]
      }
      'cdb': {
        $files = ["${path}.cdb"]
      }
      'dbm', 'sdbm': {
        $files = ["${path}.pag", "${path}.dir"]
      }
      'lmdb': {
        $files = ["${path}.lmdb"]
      }
      default: {
        # noop
      }
    }

    file { $files:
      ensure => $_ensure,
      before => Class['postfix::service'],
    }

    if $ensure != 'absent' {

      # The exec resource fires unless each target hashed file exists and the
      # mtime of each is greater than the mtime of the source file
      $unless = join($files.reduce([]) |$memo, $x| {
        $memo + ["[ -f ${x} ]", "[ $(stat -c '%Y' ${x}) -gt $(stat -c '%Y' ${path}) ]"]
      }, ' && ')

      exec { "postmap ${type}:${path}":
        path    => $::path,
        unless  => $unless,
        require => File[$path],
        before  => File[$files],
      }
    }
  }
}
