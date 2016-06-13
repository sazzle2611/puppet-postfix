require 'spec_helper'

describe Puppet::Type.type(:postfix_main) do

  it "should have :name & :setting as its keyattributes" do
    expect(described_class.key_attributes).to eq([:name, :setting])
  end

  describe 'when validating attributes' do
    [:name, :setting, :target].each do |param|
      it "should have a #{param} parameter" do
        expect(described_class.attrtype(param)).to eq(:param)
      end
    end

    [:ensure, :value].each do |property|
      it "should have a #{property} property" do
        expect(described_class.attrtype(property)).to eq(:property)
      end
    end
  end

  describe 'autorequire' do
    let(:catalog) {
      catalog = Puppet::Resource::Catalog.new
    }
    it 'should autorequire the targeted file' do
      file = Puppet::Type.type(:file).new(:name => '/etc/postfix/main.cf')
      catalog.add_resource file
      key = described_class.new(:name => 'inet_interfaces', :target => '/etc/postfix/main.cf', :value => 'localhost', :ensure => :present)
      catalog.add_resource key
      expect(key.autorequire.size).to eq(1)
    end
    it 'should autorequire the service' do
      service = Puppet::Type.type(:postfix_master).new(:name => 'bounce/unix')
      catalog.add_resource service
      key = described_class.new(:name => 'bounce_service_name', :value => 'bounce', :ensure => :present)
      catalog.add_resource key
      expect(key.autorequire.size).to eq(1)
    end
    it 'should autorequire another setting and file' do
      file = Puppet::Type.type(:file).new(:name => '/etc/postfix/mynetworks')
      catalog.add_resource file
      setting = Puppet::Type.type(:postfix_main).new(:name => 'config_directory', :value => '/etc/postfix')
      catalog.add_resource setting
      key = described_class.new(:name => 'mynetworks', :value => '$config_directory/mynetworks', :ensure => :present)
      catalog.add_resource key
      expect(key.autorequire.size).to eq(2)
    end
    it 'should autorequire a hash lookup table' do
      file = Puppet::Type.type(:file).new(:name => '/etc/postfix/network_table.db')
      catalog.add_resource file
      key = described_class.new(:name => 'mynetworks', :value => 'hash:/etc/postfix/network_table', :ensure => :present)
      catalog.add_resource key
      expect(key.autorequire.size).to eq(1)
    end
    it 'should autorequire a cdb lookup table' do
      file = Puppet::Type.type(:file).new(:name => '/etc/postfix/network_table.cdb')
      catalog.add_resource file
      key = described_class.new(:name => 'mynetworks', :value => 'cdb:/etc/postfix/network_table', :ensure => :present)
      catalog.add_resource key
      expect(key.autorequire.size).to eq(1)
    end
    it 'should autorequire a dbm lookup table' do
      ['dir', 'pag'].each do |ext|
        file = Puppet::Type.type(:file).new(:name => "/etc/postfix/network_table.#{ext}")
        catalog.add_resource file
      end
      key = described_class.new(:name => 'mynetworks', :value => 'dbm:/etc/postfix/network_table', :ensure => :present)
      catalog.add_resource key
      expect(key.autorequire.size).to eq(2)
    end
    it 'should autorequire a lmdb lookup table' do
      file = Puppet::Type.type(:file).new(:name => '/etc/postfix/network_table.lmdb')
      catalog.add_resource file
      key = described_class.new(:name => 'mynetworks', :value => 'lmdb:/etc/postfix/network_table', :ensure => :present)
      catalog.add_resource key
      expect(key.autorequire.size).to eq(1)
    end
    it 'should autorequire an ldap lookup table' do
      file = Puppet::Type.type(:file).new(:name => '/etc/postfix/ldap-aliases.cf')
      catalog.add_resource file
      key = described_class.new(:name => 'mynetworks', :value => 'hash:/etc/aliases, ldap:/etc/postfix/ldap-aliases.cf', :ensure => :present)
      catalog.add_resource key
      expect(key.autorequire.size).to eq(1)
    end
  end
end
