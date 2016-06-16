require 'spec_helper'

describe 'postfix::master' do
  let(:title) do
    'submission/inet'
  end

  let(:params) do
    {
      :command => 'smtpd',
      :private => 'n',
      :chroot  => 'n',
    }
  end

  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) do
        facts
      end

      context 'without postfix class included' do
        it { expect { should compile }.to raise_error(/must include the postfix base class/) }
      end

      context 'with postfix class included', :compile do
        let(:pre_condition) do
          'include ::postfix'
        end

        it { should contain_postfix_master('submission/inet') }
        it { should contain_postfix__master('submission/inet') }
      end
    end
  end
end
