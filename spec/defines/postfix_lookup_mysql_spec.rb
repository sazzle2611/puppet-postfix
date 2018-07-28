require 'spec_helper'

describe 'postfix::lookup::mysql' do
  let(:title) do
    '/etc/postfix/test.cf'
  end

  let(:params) do
    {
      :hosts    => ['localhost'],
      :user     => 'user',
      :password => 'password',
      :dbname   => 'database',
      :query    => "SELECT address FROM aliases WHERE alias = '%s'",
    }
  end

  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) do
        facts
      end

      context 'without postfix class included' do
        it { expect { is_expected.to compile }.to raise_error(/must include the postfix base class/) }
      end

      context 'with postfix class included' do
        let(:pre_condition) do
          'include ::postfix'
        end

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/postfix/test.cf') }
        it { is_expected.to contain_postfix__lookup__mysql('/etc/postfix/test.cf') }
      end
    end
  end
end
