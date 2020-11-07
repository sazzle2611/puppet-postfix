require 'spec_helper'

describe 'postfix::lookup::sqlite' do
  let(:title) do
    '/etc/postfix/test.cf'
  end

  let(:params) do
    {
      dbpath: '/path/to/database',
      query:  "SELECT address FROM aliases WHERE alias = '%s'",
    }
  end

  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) do
        facts
      end

      context 'without postfix class included' do
        it { is_expected.to compile.and_raise_error(%r{must include the postfix base class}) }
      end

      context 'with postfix class included' do
        let(:pre_condition) do
          'include ::postfix'
        end

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/postfix/test.cf') }
        it { is_expected.to contain_postfix__lookup__sqlite('/etc/postfix/test.cf') }
      end
    end
  end
end
