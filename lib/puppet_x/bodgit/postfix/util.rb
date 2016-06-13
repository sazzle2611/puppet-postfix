module PuppetX
  module Bodgit
    module Postfix
      module Util

        # Match the following provided it's not preceeded by a $:
        #
        # * $foo_bar_baz
        # * $(foo_bar_baz)
        # * ${foo_bar_baz}
        # * ${foo_bar_baz?value}
        # * ${foo_bar_baz:value}
        #
        # $1 returns the parameter name, $2 returns the ? or : operator and $3
        # returns the value
        PARAMETER_REGEXP = /
          (?<!
            \$
          )
          \$
          (?:
            (
              [a-z0-9]+
              (?:
                _
                [a-z0-9]+
              )*
            )
            |
            \(
            (
              [a-z0-9]+
              (?:
                _
                [a-z0-9]+
              )*
            )
            \)
            |
            \{
            (
              [a-z0-9]+
              (?:
                _
                [a-z0-9]+
              )*
            )
            (?:
              (
                [?:]
              )
              (
                [^}]+
              )
            )?
            \}
          )
        /x

        def expand(value)
          v = value.clone
          loop do
            old = v.clone
            v.gsub!(PARAMETER_REGEXP) do |s|
              replacement = $&
              catalog.resources.select { |r|
                r.is_a?(Puppet::Type.type(:postfix_main)) and r.should(:ensure) == :present
              }.each { |r|
                if r.name.eql?($1) and not $2
                  replacement = r.should(:value)
                end
              }
              replacement
            end
            break if old.eql?(v)
          end
          v
        end

        def file_autorequires(values)
          requires = []
          values.each do |v|
            case v
            when /^(?:\/[^\/]+)+\/?$/
              # File
              requires << v
            when /^([^:]+):((?:\/[^\/]+)+)$/
              # Lookup table
              case $1
              when 'btree', 'hash'
                requires << "#{$2}.db"
              when 'cdb'
                requires << "#{$2}.cdb"
              when 'dbm', 'sdbm'
                requires << "#{$2}.dir"
                requires << "#{$2}.pag"
              when 'lmdb'
                requires << "#{$2}.lmdb"
              else
                # Apart from the above exceptions, target the source file
                requires << $2
              end
            end
          end
          requires
        end

        def value_scan(value)
          value.scan(PARAMETER_REGEXP).each do
            yield $1 if block_given?
          end
        end
      end
    end
  end
end
