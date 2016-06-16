require 'spec_helper'

describe 'postfix' do

  context 'on unsupported distributions' do
    let(:facts) do
      {
        :osfamily => 'Unsupported'
      }
    end

    it { expect { should compile }.to raise_error(/not supported on an Unsupported/) }
  end

  on_supported_os.each do |os, facts|
    context "on #{os}", :compile do
      let(:facts) do
        facts
      end

      it { should contain_anchor('postfix::begin') }
      it { should contain_anchor('postfix::end') }
      it { should contain_class('postfix') }
      it { should contain_class('postfix::config') }
      it { should contain_class('postfix::install') }
      it { should contain_class('postfix::params') }
      it { should contain_class('postfix::service') }
      it { should contain_file('/etc/postfix/main.cf') }
      it { should contain_file('/etc/postfix/master.cf') }
      it { should contain_package('postfix') }

      it { should contain_postfix_main('alias_database') }
      it { should contain_postfix_main('alias_maps') }
      it { should contain_postfix_main('command_directory') }
      it { should contain_postfix_main('daemon_directory') }
      it { should contain_postfix_main('data_directory') }
      it { should contain_postfix_main('debug_peer_level') }
      it { should contain_postfix_main('debugger_command') }
      it { should contain_postfix_main('html_directory') }
      it { should contain_postfix_main('inet_interfaces') }
      it { should contain_postfix_main('inet_protocols') }
      it { should contain_postfix_main('mail_owner') }
      it { should contain_postfix_main('mailq_path') }
      it { should contain_postfix_main('manpage_directory') }
      it { should contain_postfix_main('mydestination') }
      it { should contain_postfix_main('newaliases_path') }
      it { should contain_postfix_main('queue_directory') }
      it { should contain_postfix_main('readme_directory') }
      it { should contain_postfix_main('sample_directory') }
      it { should contain_postfix_main('sendmail_path') }
      it { should contain_postfix_main('setgid_group') }
      it { should contain_postfix_main('unknown_local_recipient_reject_code') }
      it { should contain_postfix_master('anvil/unix') }
      it { should contain_postfix_master('bounce/unix') }
      it { should contain_postfix_master('cleanup/unix') }
      it { should contain_postfix_master('defer/unix') }
      it { should contain_postfix_master('discard/unix') }
      it { should contain_postfix_master('error/unix') }
      it { should contain_postfix_master('flush/unix') }
      it { should contain_postfix_master('lmtp/unix') }
      it { should contain_postfix_master('local/unix') }
      it { should contain_postfix_master('proxymap/unix') }
      it { should contain_postfix_master('proxywrite/unix') }
      it { should contain_postfix_master('relay/unix') }
      it { should contain_postfix_master('retry/unix') }
      it { should contain_postfix_master('rewrite/unix') }
      it { should contain_postfix_master('scache/unix') }
      it { should contain_postfix_master('showq/unix') }
      it { should contain_postfix_master('smtp/inet') }
      it { should contain_postfix_master('smtp/unix') }
      it { should contain_postfix_master('tlsmgr/unix') }
      it { should contain_postfix_master('trace/unix') }
      it { should contain_postfix_master('verify/unix') }
      it { should contain_postfix_master('virtual/unix') }

      it { should contain_resources('postfix_main') }
      it { should contain_resources('postfix_master') }
      it { should contain_service('postfix') }

      case facts[:osfamily]
      when 'RedHat'
        case facts[:operatingsystemmajrelease]
        when '6'
          it { should contain_postfix_master('pickup/fifo') }
          it { should contain_postfix_master('qmgr/fifo') }
        else
          it { should contain_postfix_master('pickup/unix') }
          it { should contain_postfix_master('qmgr/unix') }
        end
      end
    end
  end
end
