begin
  require 'puppet_x/bodgit/postfix/util'
rescue LoadError => detail
  # :nocov:
  require 'pathname'
  require Pathname.new(__FILE__).dirname + '../../' + 'puppet_x/bodgit/postfix/util'
  # :nocov:
end

Puppet::Type.newtype(:postfix_master) do

  include PuppetX::Bodgit::Postfix::Util

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
    defaultto('-')
    munge do |value|
      value.to_s
    end
  end

  newproperty(:limit) do
    desc ''
    newvalues('-', /^\d+$/)
    defaultto('-')
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

  def command_scan(command)
    command.scan(/-o \s+ ([^=]+) = ([^ ]+)/x)
  end

  def value_split(value)
    value.split(/,/)
  end

  autorequire(:file) do
    autos = []
    autos << self[:target] if self[:target]
    if self[:command]
      command_scan(self[:command]).each do |setting, value|
        values = value_split(value).collect do |v|
          expand(v)
        end

        autos += file_autorequires(values)
      end
    end
    autos
  end

  autorequire(:postfix_main) do
    autos = []
    if self[:command]
      settings, values = command_scan(self[:command]).transpose
      if values
        values.each do |value|
          value_split(value).each do |v|
            value_scan(v) do |x|
              # Add the setting unless it's been redefined in this same command
              autos << x unless settings.include?(x)
            end
          end
        end
      end
    end
    autos
  end

  autorequire(:postfix_master) do
    autos = []
    if self[:command]
      command_scan(self[:command]).each do |setting, value|
        if setting =~ /_service_name$/
          autos << "#{value}/unix"
        end
      end
    end
    autos
  end

  autorequire(:user) do
    autos = []
    if self[:command] and self[:command] =~ /^pipe \s/x
      if self[:command] =~ /\s user = ([^: ]+)/x
        autos << $1
      end
    end
    autos
  end

  autorequire(:group) do
    autos = []
    if self[:command] and self[:command] =~ /^pipe \s/x
      if self[:command] =~ /\s user = (?:[^:]+) : ([^ ]+)/x
        autos << $1
      end
    end
    autos
  end
end
