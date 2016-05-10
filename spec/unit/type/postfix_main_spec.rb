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
  end
end
