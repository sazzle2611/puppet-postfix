require 'spec_helper'

describe 'postfix::lookup::database' do
  let(:title) do
    '/etc/postfix/test'
  end

  let(:params) do
    {
      :type    => 'hash',
      :content => "postmaster\tpostmaster@example.com\n",
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

        it { should contain_exec('postmap hash:/etc/postfix/test') }
        it { should contain_file('/etc/postfix/test') }
        it { should contain_file('/etc/postfix/test.db') }
        it { should contain_postfix__lookup__database('/etc/postfix/test') }
      end
    end
  end
end
