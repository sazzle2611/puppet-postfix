Puppet::Type.newtype(:postfix_master) do
  @doc = ''

  ensurable do
    defaultvalues
  end

  newparam(:name) do
    desc ''
  end

  newparam(:service) do
    desc ''
    isnamevar
    munge do |value|
      value.to_s
    end
  end

  newparam(:type) do
    desc ''
    isnamevar
    newvalues('inet', 'unix', 'fifo', 'pass')
    munge do |value|
      value.to_s
    end
  end

  def self.title_patterns
    identity = lambda { |x| x }
    [
      [
        /^(\S+)\/(\S+)$/,
        [
          [ :service, identity ],
          [ :type, identity ],
        ]
      ],
      [
        /(.*)/,
        [
          [ :name, identity ],
        ]
      ]
    ]
  end

  newproperty(:private) do
    desc ''
    newvalues('-', 'n', 'y')
    defaultto('-')
    munge do |value|
      value.to_s
    end
  end

  newproperty(:unprivileged) do
    desc ''
    newvalues('-', 'n', 'y')
    defaultto('-')
    munge do |value|
      value.to_s
    end
  end

  newproperty(:chroot) do
    desc ''
    newvalues('-', 'n', 'y')
    defaultto('-')
    munge do |value|
      value.to_s
    end
  end

  newproperty(:wakeup) do
    desc ''
    newvalues('-', /^\d+[?]?$/)
    munge do |value|
      value.to_s
    end
  end

  newproperty(:limit) do
    desc ''
    newvalues('-', /^\d+$/)
    munge do |value|
      value.to_s
    end
  end

  newproperty(:command) do
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
