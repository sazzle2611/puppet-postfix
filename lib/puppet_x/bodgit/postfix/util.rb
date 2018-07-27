# @!visibility private
module PuppetX
  # @!visibility private
  module Bodgit
    # @!visibility private
    module Postfix
      # Postfix type utility methods
      module Util

        # Match the following provided it's not preceeded by a $:
        #
        # * `$foo_bar_baz`
        # * `$(foo_bar_baz)`
        # * `${foo_bar_baz}`
        # * `${foo_bar_baz?value}`
        # * `${foo_bar_baz:value}`
        #
        # However, due to Ruby 1.8.7 we have to do this backwards as there's
        # no look-behind operator without pulling in Oniguruma. So anywhere
        # this Regexp is used the target string needs to be reversed and then
        # any captures need to be un-reversed again.
        PARAMETER_REGEXP = /
          (?:
            (
              [[:alnum:]]+
              (?:
                _
                [[:alnum:]]+
              )*
            )
            |
            \)
            (
              [[:alnum:]]+
              (?:
                _
                [[:alnum:]]+
              )*
            )
            \(
            |
            \}
            (?:
              (
                [^?:]+
              )
              (
                [?:]
              )
            )?
            (
              [[:alnum:]]+
              (?:
                _
                [[:alnum:]]+
              )*
            )
            \{
          )
          \$
          (?!
            \$
          )
        /x

        # Expand variables where possible
        def expand(value)
          v = value.reverse.clone
          loop do
            old = v.clone
            v.gsub!(PARAMETER_REGEXP) do |s|
              replacement = $&
              # We want all non-nil $1..n captures
              match = $~.to_a[1..-1].compact.reverse.collect { |x| x.reverse }
              catalog.resources.select { |r|
                r.is_a?(Puppet::Type.type(:postfix_main)) and r.should(:ensure) == :present
              }.each { |r|
                if r.name.eql?(match[0]) and not match[1]
                  replacement = r.should(:value).reverse
                end
              }
              replacement
            end
            break if old.eql?(v)
          end
          v.reverse
        end

        # Generate a list of potential candidates for file dependencies
        def file_autorequires(values)
          requires = []
          values.each do |v|
            case v
            when /^(?:\/[^\/]+)+\/?$/
              # File
              requires << v
            when /^([a-z]+):((?:\/[^\/]+)+)$/
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

        # Generate a list of variable names
        def value_scan(value)
          value.reverse.scan(PARAMETER_REGEXP).each do |s|
            s.compact!.reverse!
            yield s[0].reverse if block_given?
          end
        end
      end
    end
  end
end
