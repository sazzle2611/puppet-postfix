# @!visibility private
class postfix::params {

  $conf_dir     = '/etc/postfix'
  $package_name = 'postfix'
  $service_name = 'postfix'

  case $::osfamily {
    'RedHat': {
      $lookup_packages                     = {}
      $_services                           = {
        'anvil/unix'      => {
          'chroot'  => 'n',
          'command' => 'anvil',
          'limit'   => '1',
        },
        'bounce/unix'     => {
          'chroot'  => 'n',
          'command' => 'bounce',
          'limit'   => '0',
        },
        'cleanup/unix'    => {
          'chroot'  => 'n',
          'command' => 'cleanup',
          'limit'   => '0',
          'private' => 'n',
        },
        'defer/unix'      => {
          'chroot'  => 'n',
          'command' => 'bounce',
          'limit'   => '0',
        },
        'discard/unix'    => {
          'chroot'  => 'n',
          'command' => 'discard',
        },
        'error/unix'      => {
          'chroot'  => 'n',
          'command' => 'error',
        },
        'flush/unix'      => {
          'chroot'  => 'n',
          'command' => 'flush',
          'limit'   => '0',
          'private' => 'n',
          'wakeup'  => '1000?',
        },
        'lmtp/unix'       => {
          'chroot'  => 'n',
          'command' => 'lmtp',
        },
        'local/unix'      => {
          'chroot'       => 'n',
          'command'      => 'local',
          'unprivileged' => 'n',
        },
        'proxymap/unix'   => {
          'chroot'  => 'n',
          'command' => 'proxymap',
        },
        'proxywrite/unix' => {
          'chroot'  => 'n',
          'command' => 'proxymap',
          'limit'   => '1',
        },
        'relay/unix'      => {
          'chroot'  => 'n',
          'command' => 'smtp',
        },
        'retry/unix'      => {
          'chroot'  => 'n',
          'command' => 'error',
        },
        'rewrite/unix'    => {
          'chroot'  => 'n',
          'command' => 'trivial-rewrite',
        },
        'scache/unix'     => {
          'chroot'  => 'n',
          'command' => 'scache',
          'limit'   => '1',
        },
        'showq/unix'      => {
          'chroot'  => 'n',
          'command' => 'showq',
          'private' => 'n',
        },
        'smtp/inet'       => {
          'chroot'  => 'n',
          'command' => 'smtpd',
          'private' => 'n',
        },
        'smtp/unix'       => {
          'chroot'  => 'n',
          'command' => 'smtp',
        },
        'tlsmgr/unix'     => {
          'chroot'  => 'n',
          'command' => 'tlsmgr',
          'limit'   => '1',
          'wakeup'  => '1000?',
        },
        'trace/unix'      => {
          'chroot'  => 'n',
          'command' => 'bounce',
          'limit'   => '0',
        },
        'verify/unix'     => {
          'chroot'  => 'n',
          'command' => 'verify',
          'limit'   => '1',
        },
        'virtual/unix'    => {
          'chroot'       => 'n',
          'command'      => 'virtual',
          'unprivileged' => 'n',
        },
      }
      $alias_database                      = ['hash:/etc/aliases']
      $alias_maps                          = ['hash:/etc/aliases']
      $command_directory                   = '/usr/sbin'
      $daemon_directory                    = '/usr/libexec/postfix'
      $data_directory                      = '/var/lib/postfix'
      $debug_peer_level                    = '2'
      $debugger_command                    = 'PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin ddd $daemon_directory/$process_name $process_id & sleep 5'
      $default_database_type               = 'hash'
      $html_directory                      = false
      $inet_interfaces                     = ['localhost']
      $inet_protocols                      = ['all']
      $mail_owner                          = 'postfix'
      $mailq_path                          = '/usr/bin/mailq.postfix'
      $manpage_directory                   = '/usr/share/man'
      $mydestination                       = ['$myhostname', 'localhost.$mydomain', 'localhost']
      $newaliases_path                     = '/usr/bin/newaliases.postfix'
      $queue_directory                     = '/var/spool/postfix'
      $sendmail_path                       = '/usr/sbin/sendmail.postfix'
      $setgid_group                        = 'postdrop'
      $unknown_local_recipient_reject_code = '550'

      case $::operatingsystemmajrelease {
        '6': {
          $services         = merge($_services, {
            'pickup/fifo' => {
              'chroot'  => 'n',
              'command' => 'pickup',
              'limit'   => '1',
              'private' => 'n',
              'wakeup'  => '60',
            },
            'qmgr/fifo'   => {
              'chroot'  => 'n',
              'command' => 'qmgr',
              'limit'   => '1',
              'private' => 'n',
              'wakeup'  => '300',
            },
            'relay/unix'  => {
              'chroot'  => 'n',
              'command' => 'smtp -o smtp_fallback_relay=',
            },
          })
          $readme_directory = '/usr/share/doc/postfix-2.6.6/README_FILES'
          $sample_directory = '/usr/share/doc/postfix-2.6.6/samples'
        }
        default: {
          $services         = merge($_services, {
            'pickup/unix' => {
              'chroot'  => 'n',
              'command' => 'pickup',
              'limit'   => '1',
              'private' => 'n',
              'wakeup'  => '60',
            },
            'qmgr/unix'   => {
              'chroot'  => 'n',
              'command' => 'qmgr',
              'limit'   => '1',
              'private' => 'n',
              'wakeup'  => '300',
            },
          })
          $readme_directory = '/usr/share/doc/postfix-2.10.1/README_FILES'
          $sample_directory = '/usr/share/doc/postfix-2.10.1/samples'
        }
      }
    }
    'Debian': {
      $lookup_packages = {
        'cdb'   => 'postfix-cdb',
        'ldap'  => 'postfix-ldap',
        'mysql' => 'postfix-mysql',
        'pcre'  => 'postfix-pcre',
        'pgsql' => 'postfix-pgsql',
      }
    }
    default: {
      fail("The ${module_name} module is not supported on an ${::osfamily} based system.")
    }
  }
}
