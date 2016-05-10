require 'spec_helper'

describe Puppet::Type.type(:postfix_master) do

  it "should have :name, :service & :type as its keyattributes" do
    expect(described_class.key_attributes).to eq([:name, :service, :type])
  end

  describe 'when validating attributes' do
    [:name, :service, :type, :target].each do |param|
      it "should have a #{param} parameter" do
        expect(described_class.attrtype(param)).to eq(:param)
      end
    end

    [:ensure, :private, :unprivileged, :chroot, :wakeup, :limit, :command].each do |property|
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
      file = Puppet::Type.type(:file).new(:name => '/etc/postfix/master.cf')
      catalog.add_resource file
      key = described_class.new(:name => 'submission/inet', :target => '/etc/postfix/master.cf', :command => 'smtpd', :ensure => :present)
      catalog.add_resource key
      expect(key.autorequire.size).to eq(1)
    end
  end
end
