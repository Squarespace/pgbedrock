import logging

from collections import defaultdict, namedtuple

from pgbedrock import common


logger = logging.getLogger(__name__)


Q_GET_ALL_CURRENT_DEFAULTS = """
    WITH relkind_mapping (objkey, objkind) AS (
        VALUES ('f', 'functions'),
               ('r', 'tables'),
               ('S', 'sequences'),
               ('T', 'types')
    ), subq AS (
        SELECT
            auth.rolname AS grantor,
            auth.oid AS grantor_oid,
            (aclexplode(def.defaclacl)).grantee AS grantee_oid,
            nsp.nspname,
            map.objkind,
            (aclexplode(def.defaclacl)).privilege_type
        FROM
            pg_default_acl def
            JOIN pg_authid auth
                    ON def.defaclrole = auth.oid
            JOIN pg_namespace nsp
                    ON def.defaclnamespace = nsp.oid
            JOIN relkind_mapping map
                    ON def.defaclobjtype = map.objkey
        WHERE
            def.defaclacl IS NOT NULL
    )
    SELECT
        t_grantee.rolname AS grantee,
        subq.objkind,
        subq.grantor,
        subq.nspname AS schema,
        subq.privilege_type
    FROM
        subq
        JOIN pg_authid t_grantee
            ON subq.grantee_oid = t_grantee.oid
    WHERE
        subq.grantor_oid != subq.grantee_oid
    ;
    """

Q_GET_ALL_CURRENT_NONDEFAULTS = """
    WITH relkind_mapping (objkey, objkind) AS (
        VALUES ('r', 'tables'),
               ('v', 'tables'),
               ('m', 'tables'),
               ('f', 'tables'),
               ('S', 'sequences')
    ), tables_and_sequences AS (
        SELECT
            nsp.nspname AS schema,
            c.relname AS unqualified_name,
            map.objkind,
            (aclexplode(c.relacl)).grantee AS grantee_oid,
            t_owner.rolname AS owner,
            (aclexplode(c.relacl)).privilege_type
        FROM
            pg_class c
            JOIN pg_authid t_owner
                ON c.relowner = t_owner.OID
            JOIN pg_namespace nsp
                ON c.relnamespace = nsp.oid
            JOIN relkind_mapping map
                ON c.relkind = map.objkey
        WHERE
            nsp.nspname NOT LIKE 'pg\_t%'
            AND c.relacl IS NOT NULL
    ), schemas AS (
        SELECT
             nsp.nspname AS schema,
             NULL::TEXT AS unqualified_name,
             'schemas'::TEXT AS objkind,
             (aclexplode(nsp.nspacl)).grantee AS grantee_oid,
             t_owner.rolname AS owner,
             (aclexplode(nsp.nspacl)).privilege_type
        FROM pg_namespace nsp
        JOIN pg_authid t_owner
            ON nsp.nspowner = t_owner.OID
    ), combined AS (
        SELECT *
        FROM tables_and_sequences
        UNION ALL
        SELECT *
        FROM schemas
    )
    SELECT
        t_grantee.rolname AS grantee,
        combined.objkind,
        combined.schema,
        combined.unqualified_name,
        combined.privilege_type
    FROM
        combined
        JOIN pg_authid t_grantee
            ON combined.grantee_oid = t_grantee.oid
        WHERE combined.owner != t_grantee.rolname
    ;
    """

Q_GET_ALL_ROLE_ATTRIBUTES = """
    SELECT
        rolbypassrls,
        rolcanlogin,
        rolconnlimit,
        rolcreatedb,
        rolcreaterole,
        rolinherit,
        rolname,
        rolpassword,
        rolreplication,
        rolsuper,
        rolvaliduntil
    FROM pg_authid
    WHERE rolname != 'pg_signal_backend'
    ;
    """

Q_GET_ALL_MEMBERSHIPS = """
    SELECT
        auth_member.rolname AS member,
        auth_group.rolname AS group
    FROM
        pg_auth_members link_table
        JOIN pg_authid auth_member
            ON link_table.member = auth_member.oid
        JOIN pg_authid auth_group
            ON link_table.roleid = auth_group.oid
    ;
    """

Q_GET_ALL_RAW_OBJECT_ATTRIBUTES = """
    WITH relkind_mapping (objkey, kind) AS (
        VALUES ('r', 'tables'),
               ('v', 'tables'),
               ('m', 'tables'),
               ('f', 'tables'),
               ('S', 'sequences')
    ), tables_and_sequences AS (
        SELECT
            map.kind,
            nsp.nspname AS schema,
            c.relname AS unqualified_name,
            c.relowner AS owner_id,
            -- Auto-dependency means that a sequence is linked to a table. Ownership of
            -- that sequence automatically derives from the table's ownership
            COUNT(deps.refobjid) > 0 AS is_dependent
        FROM
            pg_class c
            JOIN relkind_mapping map
                ON c.relkind = map.objkey
            JOIN pg_namespace nsp
                ON c.relnamespace = nsp.OID
            LEFT JOIN pg_depend deps
                ON deps.objid = c.oid
                AND deps.classid = 'pg_class'::REGCLASS
                AND deps.refclassid = 'pg_class'::REGCLASS
                AND deps.deptype = 'a'
        GROUP BY
            map.kind,
            schema,
            unqualified_name,
            owner_id
    ), schemas AS (
        SELECT
            'schemas'::TEXT AS kind,
            nsp.nspname AS schema,
            NULL::TEXT AS unqualified_name,
            nsp.nspowner AS owner_id,
            FALSE AS is_dependent
        FROM pg_namespace nsp
    ), combined AS (
        SELECT *
        FROM tables_and_sequences
        UNION ALL
        SELECT *
        FROM schemas
    )
    SELECT
        co.kind,
        co.schema,
        co.unqualified_name,
        t_owner.rolname AS owner,
        co.is_dependent
    FROM combined AS co
    JOIN pg_authid t_owner
        ON co.owner_id = t_owner.OID
    WHERE
        co.schema NOT LIKE 'pg\_t%'
    ;
    """

Q_GET_ALL_PERSONAL_SCHEMAS = """
    SELECT nsp.nspname
    FROM pg_namespace nsp
        JOIN pg_authid auth
            ON  nsp.nspname = auth.rolname
    WHERE auth.rolcanlogin IS TRUE
    ;
    """

Q_GET_VERSIONS = """
    SELECT
        substring(version from 'PostgreSQL ([0-9.]*) ') AS postgres_version,
        substring(version from 'Redshift ([0-9.]*)') AS redshift_version,
        version LIKE '%Redshift%' AS is_redshift
    FROM version()
    ;
"""

# Write access causes read access to be granted as well. As a result, we
# don't add things like SELECT for tables into the write privileges
PRIVILEGE_MAP = {
    'tables':
        {'read':  ('SELECT', ),
         'write': ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER')
         },
    'sequences':
        {'read':  ('SELECT', ),
         'write': ('USAGE', 'UPDATE')
         },
    'schemas':
        {'read':  ('USAGE', ),
         'write': ('CREATE', )
         },
}

ObjectInfo = namedtuple('ObjectInfo', ['kind', 'objname', 'owner', 'is_dependent'])
ObjectAttributes = namedtuple('ObjectAttributes',
                              ['kind', 'schema', 'objname', 'owner', 'is_dependent'])
VersionInfo = namedtuple('VersionInfo', ['postgres_version', 'redshift_version', 'is_redshift'])


class DatabaseContext(object):
    """ Show the current state of the database we are connected to. If the relevant information
    has not already been fetched, fetch it (this is implemented via __getattribute__ below) """

    cacheables = {
        'get_all_raw_object_attributes',
        'get_all_current_defaults',
        'get_all_current_nondefaults',
        'get_all_object_attributes',
        'get_all_role_attributes',
        'get_all_memberships',
        'get_all_nonschema_objects_and_owners',
        'get_all_personal_schemas',
        'get_all_schemas_and_owners',
        'get_version_info',
    }

    def __init__(self, cursor, verbose):
        self.cursor = cursor
        self.verbose = verbose
        self._cache = dict()

    def __getattribute__(self, attr):
        """ If the requested attribute should be cached and hasn't, fetch it and cache it. """
        cache = super(DatabaseContext, self).__getattribute__('_cache')
        cacheables = super(DatabaseContext, self).__getattribute__('cacheables')

        is_cacheable = attr in cacheables
        is_in_cache = attr in cache

        if is_cacheable and is_in_cache:
            return cache[attr]

        if is_cacheable and not is_in_cache:
            logger.debug('Generating database context "{}"'.format(attr))
            result = super(DatabaseContext, self).__getattribute__(attr)()
            # The attribute being cached is the output of a function, so it will
            # be called once this returns; we use a lambda function so that works
            cache[attr] = lambda: result

        return super(DatabaseContext, self).__getattribute__(attr)

    def get_all_current_defaults(self):
        """ Return a dict of the form:
            {roleA: {
                objkindA: {
                    'read': set([
                        (grantor, ObjectName(nspname), privilege),
                        ...
                        ]),
                    'write': set([
                        (grantor, ObjectName(nspname), privilege),
                        ...
                        ])
                    },
                }
             roleB:
                ....
            }

            This will not include privileges granted by this role to itself
        """
        NamedRow = namedtuple('NamedRow',
                              ['grantee', 'objkind', 'grantor', 'schema', 'privilege'])
        common.run_query(self.cursor, self.verbose, Q_GET_ALL_CURRENT_DEFAULTS)

        current_defaults = defaultdict(dict)
        for i in self.cursor.fetchall():
            row = NamedRow(*i)
            is_read_priv = row.privilege in PRIVILEGE_MAP[row.objkind]['read']
            access_key = 'read' if is_read_priv else 'write'

            entry = (row.grantor, common.ObjectName(row.schema), row.privilege)
            role_defaults = current_defaults[row.grantee]

            # Create this role's dict substructure for the first entry we come across
            if row.objkind not in role_defaults:
                role_defaults[row.objkind] = {
                    'read': set(),
                    'write': set(),
                }

            role_defaults[row.objkind][access_key].add(entry)

        return current_defaults

    def get_role_current_defaults(self, rolename, object_kind, access):
        """ Return the current default privileges for a specific
        rolename x object_kind x access type, e.g. for role jdoe x tables x read """
        all_current_defaults = self.get_all_current_defaults()
        try:
            return all_current_defaults[rolename][object_kind][access]
        except KeyError:
            return set()

    def has_default_privilege(self, rolename, schema, object_kind, access):
        write_defaults = self.get_role_current_defaults(rolename, object_kind, access)
        for grantor, objname, priv in write_defaults:
            # So long as at least one default privilege exists in this schema and was not granted
            # by this role we consider the role to have default privileges in that schema
            if objname == schema and grantor != rolename:
                return True

        return False

    def get_role_objects_with_access(self, rolename, schema, object_kind, access):
        """ Return the set of objects in this schema which the given rolename has the
        specified access for

        Returns:
            set: A set of common.ObjectName instances
        """
        objects_with_access = self.get_role_current_nondefaults(rolename, object_kind, access)
        results = set([objname for objname, _ in objects_with_access if objname.only_schema() == schema])
        return results

    def get_all_current_nondefaults(self):
        """ Return a dict of the form:
            {roleA: {
                objkindA: {
                    'read': set([
                        (objname, privilege),
                        ...
                        ]),
                    'write': set([
                        (objname, privilege),
                        ...
                        ]),
                    },
                }
             roleB:
                ....
            }

            This will not include privileges granted by this role to itself
        """
        NamedRow = namedtuple('NamedRow',
                              ['grantee', 'objkind', 'schema', 'unqualified_name', 'privilege'])
        common.run_query(self.cursor, self.verbose, Q_GET_ALL_CURRENT_NONDEFAULTS)
        current_nondefaults = defaultdict(dict)

        for i in self.cursor.fetchall():
            row = NamedRow(*i)
            is_read_priv = row.privilege in PRIVILEGE_MAP[row.objkind]['read']
            access_key = 'read' if is_read_priv else 'write'

            role_nondefaults = current_nondefaults[row.grantee]
            # Create this role's dict substructure for the first entry we come across
            if row.objkind not in role_nondefaults:
                role_nondefaults[row.objkind] = {
                    'read': set(),
                    'write': set(),
                }

            objname = common.ObjectName(schema=row.schema, unqualified_name=row.unqualified_name)
            entry = (objname, row.privilege)
            role_nondefaults[row.objkind][access_key].add(entry)

        return current_nondefaults

    def get_role_current_nondefaults(self, rolename, object_kind, access):
        """ Return the current non-default privileges for a specific
        rolename x object_kind x access type, e.g. for role jdoe x tables x read.

        Returns:
            set: A set of tuples consisting of a database object and a privilege
                with types (common.ObjectName, str)
        """
        all_current_nondefaults = self.get_all_current_nondefaults()
        try:
            return all_current_nondefaults[rolename][object_kind][access]
        except KeyError:
            return set()

    def get_all_role_attributes(self):
        """ Return a dict with key = rolname and values = all fields in pg_authid """
        common.run_query(self.cursor, self.verbose, Q_GET_ALL_ROLE_ATTRIBUTES)
        role_attributes = {row['rolname']: dict(row) for row in self.cursor.fetchall()}
        return role_attributes

    def get_role_attributes(self, rolename):
        all_role_attributes = self.get_all_role_attributes()
        return all_role_attributes.get(rolename, dict())

    def is_superuser(self, rolename):
        role_attributes = self.get_role_attributes(rolename)
        return role_attributes.get('rolsuper', False)

    def get_all_raw_object_attributes(self):
        """
        Fetch results for all object attributes.

        The results are used in several subsequent methods, so having consistent results is
        important. Thus, this helper method is here to ensure that we only run this query once.
        """
        common.run_query(self.cursor, self.verbose, Q_GET_ALL_RAW_OBJECT_ATTRIBUTES)
        results = []
        NamedRow = namedtuple('NamedRow', ['kind', 'schema', 'unqualified_name', 'owner', 'is_dependent'])
        for i in self.cursor.fetchall():
            row = NamedRow(*i)
            objname = common.ObjectName(schema=row.schema, unqualified_name=row.unqualified_name)
            entry = ObjectAttributes(row.kind, row.schema, objname, row.owner, row.is_dependent)
            results.append(entry)
        return results

    def get_all_object_attributes(self):
        """ Return a dict of the form:
            {objkindA: {
                'schemaA': {
                    'objnameA': {
                        'owner': ownerA,
                        'is_dependent': False,
                        },
                    'objnameB': {
                        'owner': ownerB,
                        'is_dependent': True,
                        },
                    },
                'schemaB': ...
                 ...
                },
            objkindB:
                ...
            }
        i.e. we can access an object's owner via output[objkind][schema][objname]['owner']

        This structure is chosen to match as closely as possible the structure of spec files
        as we typically access this structure as we are building out or reading through a spec
        """
        all_object_owners = defaultdict(dict)
        for row in self.get_all_raw_object_attributes():
            objkind_owners = all_object_owners[row.kind]
            if row.schema not in objkind_owners:
                objkind_owners[row.schema] = dict()

            objkind_owners[row.schema][row.objname] = {'owner': row.owner,
                                                       'is_dependent': row.is_dependent}

        return all_object_owners

    def get_all_memberships(self):
        """ Return a list of tuple, where each tuple is (member, group) """
        common.run_query(self.cursor, self.verbose, Q_GET_ALL_MEMBERSHIPS)
        return self.cursor.fetchall()

    def get_all_schemas_and_owners(self):
        """
        Returns:
            dict: a dict of {schema_name: schema_owner}, where schema_name is a common.ObjectName
        """
        all_object_owners = self.get_all_object_attributes()
        schemas_subdict = all_object_owners.get('schemas', {})
        schema_owners = dict()
        for schema, attributes in schemas_subdict.items():
            objname = common.ObjectName(schema)
            schema_owners[objname] = attributes[objname]['owner']
        return schema_owners

    def get_schema_owner(self, schema):
        """
        Args:
            schema (common.ObjectName): The schema to find the owner for

        Returns:
            str
        """
        all_schemas_and_owners = self.get_all_schemas_and_owners()
        return all_schemas_and_owners.get(schema)

    def get_role_memberships(self, rolename):
        all_memberships = self.get_all_memberships()
        role_memberships = set([group for role, group in all_memberships if role == rolename])
        return role_memberships

    def get_all_personal_schemas(self):
        """ Return all personal schemas

        Returns:
            set: A set of common.ObjectName instances
        """
        common.run_query(self.cursor, self.verbose, Q_GET_ALL_PERSONAL_SCHEMAS)
        personal_schemas = set([common.ObjectName(schema=row[0]) for row in self.cursor.fetchall()])
        return personal_schemas

    def get_all_nonschema_objects_and_owners(self):
        """
        For all objkinds other than schemas return a dict of the form
            {common.ObjectName(schema_name): [(objkind, objname, objowner, is_dependent), ...]}

        This is primarily a helper for DatabaseContext.get_schema_objects so we have O(1)
        schema object lookups instead of needing to iterate through all objects every time
        """
        schema_objects = defaultdict(list)
        for row in self.get_all_raw_object_attributes():
            if row.kind != 'schemas':
                objinfo = ObjectInfo(row.kind, row.objname, row.owner, row.is_dependent)
                schema_objects[row.objname.only_schema()].append(objinfo)

        return schema_objects

    def get_schema_objects(self, schema):
        """
        Args:
            schema (common.ObjectName): The schema to get object for

        Returns:
            list
        """
        all_objects_and_owners = self.get_all_nonschema_objects_and_owners()
        return all_objects_and_owners.get(schema, [])

    def is_schema_empty(self, schema, object_kind):
        """ Determine if the schema is empty with regard to the object kind specified

        If there are no objects in the schema of kind object_kind but there are objects in the
        schema of other kinds, this function will return True (i.e. the schema is empty of this
        particular kind of object)

        Args:
            schema (common.ObjectName): The schema to check
            object_kind (str): The object kind to look for

        Returns:
            bool
        """
        all_objects_and_owners = self.get_all_nonschema_objects_and_owners()
        for obj in all_objects_and_owners.get(schema, []):
            if obj.kind == object_kind:
                return False

        return True

    def get_version_info(self):
        """ Return information for this Postgres instance """
        common.run_query(self.cursor, self.verbose, Q_GET_VERSIONS)
        results = self.cursor.fetchone()
        info = VersionInfo(*results)
        return info
