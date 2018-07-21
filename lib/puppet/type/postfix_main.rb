begin
  require 'puppet_x/bodgit/postfix/util'
rescue LoadError => detail
  # :nocov:
  require 'pathname'
  require Pathname.new(__FILE__).dirname + '../../' + 'puppet_x/bodgit/postfix/util'
  # :nocov:
end

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
    [
      [
        /^(\S+)$/,
        [
          [ :setting ],
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
    case self[:setting]
    when /_service_name$/
      autos += [
        "#{self[:value]}/inet",
        "#{self[:value]}/unix",
        "#{self[:value]}/fifo",
        "#{self[:value]}/pass",
      ]
    when /
      ^
      ([^_]+)
      _
      (?:
        delivery_slot_
        (?:
          cost
          |
          discount
          |
          loan
        )
        |
        destination_
        (?:
          concurrency_
          (?:
            (?:
              failed_cohort_
            )?
            limit
            |
            (?:
              negative
              |
              positive
            )
            _feedback
          )
          |
          rate_delay
          |
          recipient_limit
        )
        |
        extra_recipient_limit
        |
        initial_destination_concurrency
        |
        minimum_delivery_slots
        |
        recipient_
        (?:
          limit
          |
          refill_
          (?:
            delay
            |
            limit
          )
        )
      )
      $
      /x
      if $1 != 'default'
        autos += [
          "#{$1}/inet",
          "#{$1}/unix",
          "#{$1}/fifo",
          "#{$1}/pass",
        ]
      end
    end
    autos
  end
end
