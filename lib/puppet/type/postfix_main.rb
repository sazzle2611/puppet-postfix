require 'puppet_x/bodgit/postfix/util'

Puppet::Type.newtype(:postfix_main) do

  include PuppetX::Bodgit::Postfix::Util

  @doc = ''

  ensurable do
    defaultvalues
  end

  newparam(:name) do
    desc ''
  end

  newparam(:setting) do
    desc ''
    isnamevar
    munge do |value|
      value.to_s
    end
  end

  def self.title_patterns
    identity = lambda { |x| x }
    [
      [
        /^(\S+)$/,
        [
          [ :setting, identity ],
        ]
      ]
    ]
  end

  newproperty(:value) do
    desc ''
    munge do |value|
      value.to_s
    end
  end

  newparam(:target) do
    desc ''
  end

  def value_split(value)
    value.split(/[\s,]+/)
  end

  autorequire(:file) do
    autos = []
    autos << self[:target] if self[:target]
    if self[:value]
      values = value_split(self[:value]).collect do |x|
        expand(x)
      end

      autos += file_autorequires(values)
    end
    autos
  end

  autorequire(:postfix_main) do
    autos = []
    if self[:value]
      value_split(self[:value]).each do |v|
        value_scan(v) do |x|
          autos << x
        end
      end
    end
    autos
  end

  autorequire(:postfix_master) do
    autos = []
    if self[:setting] =~ /_service_name$/
      autos << "#{self[:value]}/unix"
    end
    autos
  end
end
