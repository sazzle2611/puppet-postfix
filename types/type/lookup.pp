# @since 2.0.0
type Postfix::Type::Lookup = Variant[Postfix::Type::Lookup::Database, Enum['ldap', 'mysql', 'pgsql', 'sqlite']]
