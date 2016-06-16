require 'spec_helper_acceptance'

describe 'postfix' do

  it 'should work with no errors' do

    pp = <<-EOS
      include ::postfix
    EOS

    apply_manifest(pp, :catch_failures => true)
    apply_manifest(pp, :catch_changes  => true)
  end

  describe package('postfix') do
    it { should be_installed }
  end

  describe file('/etc/postfix') do
    it { should be_directory }
    it { should be_mode 755 }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end

  describe file('/etc/postfix/main.cf') do
    it { should be_file }
    it { should be_mode 644 }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end

  describe file('/etc/postfix/master.cf') do
    it { should be_file }
    it { should be_mode 644 }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end

  describe service('postfix') do
    it { should be_enabled }
    it { should be_running }
  end
end
