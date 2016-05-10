Puppet::Type.newtype(:postfix_main) do
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

  autorequire(:file) do
    self[:target]
  end
end
