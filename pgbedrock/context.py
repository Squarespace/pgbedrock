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
            c.relname AS objname,
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
             NULL::TEXT AS objname,
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
        combined.objname,
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
            c.relname AS objname,
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
            objname,
            owner_id
    ), schemas AS (
        SELECT
            'schemas'::TEXT AS kind,
            nsp.nspname AS schema,
            NULL::TEXT AS objname,
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
        co.objname,
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

ObjectInfo = namedtuple('ObjectInfo', ['kind', 'dbobject', 'owner', 'is_dependent'])
ObjectAttributes = namedtuple('ObjectAttributes',
                              ['kind', 'schema', 'dbobject', 'owner', 'is_dependent'])
VersionInfo = namedtuple('VersionInfo', ['postgres_version', 'redshift_version', 'is_redshift'])


class DBObject(object):
    """ Hold references to a specifc object, i.e. the schema and object name.

    We do this in order to:
        * Enable us to easily pick out the schema and object name for an object
        * Be sure that when we use a schema or object name we won't have to worry
            about existing double-quoting of these characteristics
        * Be sure that when we get the fully-qualified name it will be double quoted
            properly, i.e.  "myschema"."mytable"
    """
    def __init__(self, schema, object_name=None):
        # Make sure schema and table are both stored without double quotes around
        # them; we add these when DBObject.qualified_name is called
        self._schema = self._unquoted_item(schema)
        self._object_name = self._unquoted_item(object_name)

        if self._object_name and self._object_name == '*':
            self._qualified_name = '{}.{}'.format(self.schema, self.object_name)
        elif self._object_name and self._object_name != '*':
            #TODO: Change these to "schema"."table" after converting pgbedrock to use this class
            self._qualified_name = '{}."{}"'.format(self.schema, self.object_name)
        else:
            self._qualified_name = '{}'.format(self.schema)

    def __eq__(self, other):
        return (self.schema == other.schema) and (self.object_name == other.object_name)

    def __hash__(self):
        return hash(self.qualified_name)

    @classmethod
    def from_str(cls, text):
        """ Convert a text representation of a qualified object name into an DBObject instance

        For example, 'foo.bar', '"foo".bar', '"foo"."bar"', etc. will be converted an object with
        schema 'foo' and object name 'bar'. Double quotes around the schema or object name are
        stripped, but note that we don't do anything with impossible input like 'foo."bar".baz'
        (which is impossible because the object name would include double quotes in it). Instead,
        we let processing proceed and the issue bubble up downstream.

        #TODO: add spec validation to prevent things like the impossible situation above, then
        amend this docstring to note that.

        """
        if '.' not in text:
            return cls(schema=text)

        # If there are multiple periods we assume that the first one delineates the schema from
        # the rest of the object, i.e. foo.bar.baz means schema foo and object "bar.baz"
        schema, object_name = text.split('.', 1)
        # Don't worry about removing double quotes as that happens in __init__
        return cls(schema=schema, object_name=object_name)

    @property
    def schema(self):
        return self._schema

    @property
    def object_name(self):
        return self._object_name

    @property
    def qualified_name(self):
        return self._qualified_name

    @staticmethod
    def _unquoted_item(item):
        if item and item.startswith('"') and item.endswith('"'):
            return item[1:-1]
        return item


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
                        (grantor, nspname, privilege),
                        ...
                        ]),
                    'write': set([
                        (grantor, nspname, privilege),
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

            entry = (row.grantor, row.schema, row.privilege)
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
        for grantor, nspname, priv in write_defaults:
            # So long as at least one default privilege exists in this schema and was not granted
            # by this role we consider the role to have default privileges in that schema
            if nspname == schema and grantor != rolename:
                return True

        return False

    def get_role_objects_with_access(self, rolename, schema, object_kind, access):
        """ Return the set of objects in this schema which the given rolename has the
        specified access for

        Returns:
            set: A set of context.DBObject instances
        """
        objects_with_access = self.get_role_current_nondefaults(rolename, object_kind, access)
        results = set([dbo for dbo, _ in objects_with_access if dbo.schema == schema])
        return results

    def get_all_current_nondefaults(self):
        """ Return a dict of the form:
            {roleA: {
                objkindA: {
                    'read': set([
                        (dbobject, privilege),
                        ...
                        ]),
                    'write': set([
                        (dbobject, privilege),
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
                              ['grantee', 'objkind', 'schema', 'objname', 'privilege'])
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

            dbobject = DBObject(schema=row.schema, object_name=row.objname)
            entry = (dbobject, row.privilege)
            role_nondefaults[row.objkind][access_key].add(entry)

        return current_nondefaults

    def get_role_current_nondefaults(self, rolename, object_kind, access):
        """ Return the current non-default privileges for a specific
        rolename x object_kind x access type, e.g. for role jdoe x tables x read.

        Returns:
            set: A set of tuples consisting of a database object and a privilege
                with types (context.DBObject, str)
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
        NamedRow = namedtuple('NamedRow', ['kind', 'schema', 'objname', 'owner', 'is_dependent'])
        for i in self.cursor.fetchall():
            row = NamedRow(*i)
            dbobject = DBObject(schema=row.schema, object_name=row.objname)
            entry = ObjectAttributes(row.kind, row.schema, dbobject, row.owner, row.is_dependent)
            results.append(entry)
        return results

    def get_all_object_attributes(self):
        """ Return a dict of the form:
            {objkindA: {
                'schemaA': {
                    'dbobjectA': {
                        'owner': ownerA,
                        'is_dependent': False,
                        },
                    'dbobjectB': {
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

            objkind_owners[row.schema][row.dbobject] = {'owner': row.owner,
                                                        'is_dependent': row.is_dependent}

        return all_object_owners

    def get_all_memberships(self):
        """ Return a list of tuple, where each tuple is (member, group) """
        common.run_query(self.cursor, self.verbose, Q_GET_ALL_MEMBERSHIPS)
        return self.cursor.fetchall()

    def get_all_schemas_and_owners(self):
        """
        Returns:
            dict: a dict of {schema_name: schema_owner}, where schema_name is a context.DBObject
        """
        all_object_owners = self.get_all_object_attributes()
        schemas_subdict = all_object_owners.get('schemas', {})
        schema_owners = dict()
        for schema, attributes in schemas_subdict.items():
            dbobject = DBObject(schema)
            schema_owners[dbobject] = attributes[dbobject]['owner']
        return schema_owners

    def get_schema_owner(self, schema):
        """
        Args:
            schema (DBObject): The schema to find the owner for

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
            set: A set of DBObject instances
        """
        common.run_query(self.cursor, self.verbose, Q_GET_ALL_PERSONAL_SCHEMAS)
        personal_schemas = set([DBObject(schema=row[0]) for row in self.cursor.fetchall()])
        return personal_schemas

    def get_all_nonschema_objects_and_owners(self):
        """
        For all objkinds other than schemas return a dict of the form
            {schema_name: [(objkind, dbobject, objowner, is_dependent), ...]}

        This is primarily a helper for DatabaseContext.get_schema_objects so we have O(1)
        schema object lookups instead of needing to iterate through all objects every time
        """
        schema_objects = defaultdict(list)
        for row in self.get_all_raw_object_attributes():
            if row.kind != 'schemas':
                objinfo = ObjectInfo(row.kind, row.dbobject, row.owner, row.is_dependent)
                schema_objects[row.schema].append(objinfo)

        return schema_objects

    def get_schema_objects(self, schema):
        all_objects_and_owners = self.get_all_nonschema_objects_and_owners()
        return all_objects_and_owners.get(schema, [])

    def is_schema_empty(self, schema, object_kind):
        """ Determine if the schema is empty with regard to the object kind specified """
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
