import pytest

from conftest import quoted_object, run_setup_sql
from pgbedrock import privileges as privs, attributes, ownerships, context
from pgbedrock import memberships


Q_CREATE_TABLE = 'SET ROLE {}; CREATE TABLE {}.{} AS (SELECT 1+1); RESET ROLE;'
Q_CREATE_SEQUENCE = 'SET ROLE {}; CREATE SEQUENCE {}.{}; RESET ROLE;'
Q_HAS_PRIVILEGE = "SELECT has_table_privilege('{}', '{}', 'SELECT');"

SCHEMAS = tuple('schema{}'.format(i) for i in range(4))
ROLES = tuple('role{}'.format(i) for i in range(4))
TABLES = tuple('table{}'.format(i) for i in range(6))
SEQUENCES = tuple('seq{}'.format(i) for i in range(6))
DUMMY = 'foo'


def test_dbobject_nonschema():
    myobj = context.DBObject(schema='myschema', object_name='mytable')
    assert myobj.schema == 'myschema'
    assert myobj.object_name == 'mytable'
    assert myobj.qualified_name == 'myschema."mytable"'


def test_dbobject_schema():
    myobj = context.DBObject(schema='myschema')
    assert myobj.schema == 'myschema'
    assert myobj.object_name is None
    assert myobj.qualified_name == 'myschema'


def test_dbobject_unquoted_item():
    assert context.DBObject._unquoted_item('foo') == 'foo'
    assert context.DBObject._unquoted_item('"foo"') == 'foo'


def test_dbobject_equivalence():
    myobj1 = context.DBObject(schema='myschema', object_name='mytable')
    myobj2 = context.DBObject(schema='myschema', object_name='mytable')
    assert myobj1 == myobj2

    myobj1 = context.DBObject(schema='myschema')
    myobj2 = context.DBObject(schema='myschema')
    assert myobj1 == myobj2


@pytest.mark.parametrize('full_name', [('foo'), ('"foo"')])
def test_dbobject_from_str_only_schema(full_name):
    myobj = context.DBObject.from_str(full_name)
    assert isinstance(myobj, context.DBObject)
    assert myobj.schema == 'foo'
    assert myobj.object_name is None
    assert myobj.qualified_name == 'foo'


@pytest.mark.parametrize('full_name, schema_name, object_name, qualified_name', [
    ('foo.bar', 'foo', 'bar', 'foo."bar"'),
    ('foo."bar"', 'foo', 'bar', 'foo."bar"'),
    ('"foo".bar', 'foo', 'bar', 'foo."bar"'),
    ('"foo"."bar"', 'foo', 'bar', 'foo."bar"'),
    ('"foo".bar.baz', 'foo', 'bar.baz', 'foo."bar.baz"'),
    ('"foo"."bar.baz"', 'foo', 'bar.baz', 'foo."bar.baz"'),
    ('foo.*', 'foo', '*', 'foo."*"'),
])
def test_objectname_from_str_schema_and_object(full_name, schema_name, object_name, qualified_name):
    myobj = context.DBObject.from_str(full_name)
    assert isinstance(myobj, context.DBObject)
    assert myobj.schema == schema_name
    assert myobj.object_name == object_name
    assert myobj.qualified_name == qualified_name




@run_setup_sql(
    # Create the roles
    [attributes.Q_CREATE_ROLE.format(r) for r in ROLES] +

    [
        # Create a schema owned by role1
        ownerships.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[1]),

        # Let role2 create tables in the schema and have it create a table there
        # so that default privileges from role2 should occur when we configure
        privs.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', SCHEMAS[0], ROLES[2]),
        Q_CREATE_TABLE.format(ROLES[2], SCHEMAS[0], TABLES[0]),

        # Grant default privileges to role0 from role3 for this schema; these should get
        # revoked in our test
        privs.Q_GRANT_DEFAULT.format(ROLES[3], SCHEMAS[0], 'SELECT', 'TABLES', ROLES[0]),
    ]
)
def test_get_all_current_defaults(cursor):
    dbcontext = context.DatabaseContext(cursor, verbose=True)
    expected = {
        ROLES[0]: {
            'tables': {
                'read': set([
                    (ROLES[3], SCHEMAS[0], 'SELECT'),
                ]),
                'write': set(),
            }
        }
    }
    actual = dbcontext.get_all_current_defaults()
    assert actual == expected

    # Make sure that this data is cached for future use
    cursor.close()
    actual_again = dbcontext.get_all_current_defaults()
    assert actual_again == expected




@pytest.mark.parametrize('rolename, object_kind, access, expected', [
    ('role1', 'object_kind1', 'access1', set([1, 2, 3])),
    ('role1', 'object_kind1', 'missing_access', set()),
    ('role1', 'missing_object_kind1', 'access1', set()),
    ('missing_role1', 'object_kind1', 'access', set()),
])
def test_get_role_current_defaults(rolename, object_kind, access, expected):
    dbcontext = context.DatabaseContext(cursor=DUMMY, verbose=True)
    dbcontext._cache['get_all_current_defaults'] = lambda: {
        'role1': {
            'object_kind1': {
                'access1': set([1, 2, 3])
            }
        }
    }
    assert dbcontext.get_role_current_defaults(rolename, object_kind, access) == expected



@pytest.mark.parametrize('rolename, schema, object_kind, access, expected', [
    # No privilege --> false
    ('role1', 'schema1', 'tables', 'read', False),
    # Privilege exists --> True
    ('role1', 'schema1', 'tables', 'write', True),
    # Grantor is this role --> False
    ('role1', 'schema2', 'tables', 'read', False),
    # No entries exist --> False
    ('role1', DUMMY, 'objkind_does_not_exist', DUMMY, False),
])
def test_has_default_privilege(rolename, schema, object_kind, access, expected):
    dbcontext = context.DatabaseContext(cursor=DUMMY, verbose=True)
    dbcontext._cache['get_all_current_defaults'] = lambda: {
        'role1': {
            'tables': {
                'read': set([
                    ('role1', 'schema2', 'SELECT'),
                ]),
                'write': set([
                    ('not_this_role', 'schema1', 'UPDATE'),
                ]),
            }
        }
    }
    assert dbcontext.has_default_privilege(rolename, schema, object_kind, access) == expected




@run_setup_sql(
    # Create the roles
    [attributes.Q_CREATE_ROLE.format(r) for r in ROLES] +

    # Create two schemas, both owned by Role1 (who will own nothing else)
    [ownerships.Q_CREATE_SCHEMA.format(s, ROLES[1]) for s in SCHEMAS[:2]] +

    [
        # Let role2 and role3 create objects in the schemas
        privs.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', SCHEMAS[0], ROLES[2]),
        privs.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', SCHEMAS[0], ROLES[3]),
        privs.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', SCHEMAS[1], ROLES[2]),
        privs.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', SCHEMAS[1], ROLES[3]),

        # Create a couple tables
        Q_CREATE_TABLE.format(ROLES[3], SCHEMAS[0], TABLES[1]),
        Q_CREATE_TABLE.format(ROLES[3], SCHEMAS[1], TABLES[3]),

        # Grant SELECT to role0 for several tables
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', '{}.{}'.format(SCHEMAS[0], TABLES[1]), ROLES[0]),
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', '{}.{}'.format(SCHEMAS[1], TABLES[3]), ROLES[0]),
    ]
)
def test_get_all_current_nondefaults(cursor):
    dbcontext = context.DatabaseContext(cursor, verbose=True)
    expected = {
        ROLES[0]: {
            'tables': {
                'read': set([
                    (context.DBObject(schema=SCHEMAS[0], object_name=TABLES[1]), 'SELECT'),
                    (context.DBObject(schema=SCHEMAS[1], object_name=TABLES[3]), 'SELECT'),
                ]),
                'write': set(),
            }
        },
        ROLES[2]: {
            'schemas': {
                'read': set(),
                'write': set([
                    (context.DBObject(schema=SCHEMAS[0]), 'CREATE'),
                    (context.DBObject(schema=SCHEMAS[1]), 'CREATE'),
                ]),
            }
        },
        ROLES[3]: {
            'schemas': {
                'read': set(),
                'write': set([
                    (context.DBObject(schema=SCHEMAS[0]), 'CREATE'),
                    (context.DBObject(schema=SCHEMAS[1]), 'CREATE'),
                ]),
            }
        }
    }
    actual = dbcontext.get_all_current_nondefaults()
    assert actual == expected

    # Make sure that this data is cached for future use
    cursor.close()
    actual_again = dbcontext.get_all_current_nondefaults()
    assert actual_again == expected




@pytest.mark.parametrize('rolename, object_kind, access, expected', [
    ('role1', 'object_kind1', 'access1', set([
        (context.DBObject(schema='foo', object_name='bar'), 'SELECT'),
        (context.DBObject(schema='foo', object_name='baz'), 'SELECT'),
        (context.DBObject(schema='foo', object_name='qux'), 'INSERT'),
    ])),
    ('role1', 'object_kind1', 'missing_access', set()),
    ('role1', 'missing_object_kind1', 'access1', set()),
    ('missing_role1', 'object_kind1', 'access', set()),
])
def test_get_role_current_nondefaults(rolename, object_kind, access, expected):
    dbcontext = context.DatabaseContext(cursor=DUMMY, verbose=True)
    dbcontext._cache['get_all_current_nondefaults'] = lambda: {
        'role1': {
            'object_kind1': {
                'access1': set([
                    (context.DBObject(schema='foo', object_name='bar'), 'SELECT'),
                    (context.DBObject(schema='foo', object_name='baz'), 'SELECT'),
                    (context.DBObject(schema='foo', object_name='qux'), 'INSERT'),
                ])
            }
        }
    }
    actual = dbcontext.get_role_current_nondefaults(rolename, object_kind, access)
    assert actual == expected




@pytest.mark.parametrize('access, expected', [
    ('write', set()),
    ('read', set([
        context.DBObject(schema=SCHEMAS[0], object_name=TABLES[0]),
        context.DBObject(schema=SCHEMAS[0], object_name=TABLES[1])
    ])),
])
def test_get_role_objects_with_access(access, expected):
    dbcontext = context.DatabaseContext(cursor=DUMMY, verbose=True)
    dbcontext._cache['get_all_current_nondefaults'] = lambda: {
        ROLES[0]: {
            'tables': {
                'read': set([
                    (context.DBObject(schema=SCHEMAS[0], object_name=TABLES[0]), 'SELECT'),
                    (context.DBObject(schema=SCHEMAS[0], object_name=TABLES[1]), 'SELECT'),
                ])
            }
        }
    }
    actual = dbcontext.get_role_objects_with_access(ROLES[0], SCHEMAS[0], 'tables', access)
    assert actual == expected




@run_setup_sql(
    # Create all the roles
    [attributes.Q_CREATE_ROLE.format(r) for r in ROLES] +
    [
        # Create schema; Role0 owns the schema but no objects
        ownerships.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[0]),
    ] +
    # Let all roles create objects in the schema
    [privs.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', SCHEMAS[0], r) for r in ROLES] +
    [
        # Role1 owns 2 tables (0, 1) and 1 sequence (0)
        Q_CREATE_TABLE.format(ROLES[1], SCHEMAS[0], TABLES[0]),
        Q_CREATE_TABLE.format(ROLES[1], SCHEMAS[0], TABLES[1]),
        Q_CREATE_SEQUENCE.format(ROLES[1], SCHEMAS[0], SEQUENCES[0]),

        # Role2 owns 0 tables and 2 sequences (1, 2)
        Q_CREATE_SEQUENCE.format(ROLES[2], SCHEMAS[0], SEQUENCES[1]),
        Q_CREATE_SEQUENCE.format(ROLES[2], SCHEMAS[0], SEQUENCES[2]),

        # Role3 owns 1 table (2) and 0 sequences
        Q_CREATE_TABLE.format(ROLES[3], SCHEMAS[0], TABLES[2]),
    ])
def test_get_all_object_attributes(cursor):
    dbcontext = context.DatabaseContext(cursor, verbose=True)
    expected = {
        'tables': {
            SCHEMAS[0]: {
                context.DBObject(SCHEMAS[0], TABLES[0]): {'owner': ROLES[1], 'is_dependent': False},
                context.DBObject(SCHEMAS[0], TABLES[1]): {'owner': ROLES[1], 'is_dependent': False},
                context.DBObject(SCHEMAS[0], TABLES[2]): {'owner': ROLES[3], 'is_dependent': False},
            }
        },
        'sequences': {
            SCHEMAS[0]: {
                context.DBObject(SCHEMAS[0], SEQUENCES[0]): {'owner': ROLES[1], 'is_dependent': False},
                context.DBObject(SCHEMAS[0], SEQUENCES[1]): {'owner': ROLES[2], 'is_dependent': False},
                context.DBObject(SCHEMAS[0], SEQUENCES[2]): {'owner': ROLES[2], 'is_dependent': False},
            }
        },
        'schemas': {
            SCHEMAS[0]: {
                context.DBObject(SCHEMAS[0]): {'owner': ROLES[0], 'is_dependent': False},
            },
            'public': {
                'public': {'owner': 'postgres', 'is_dependent': False},
            }
        }
    }

    actual = dbcontext.get_all_object_attributes()

    # We do this to avoid having to look at / filter out entries from
    # information_schema or pg_catalog
    for key in expected.keys():
        expected_entries = expected[key][SCHEMAS[0]]
        actual_entries = actual[key][SCHEMAS[0]]
        assert expected_entries == actual_entries

    # Make sure that this data is cached for future use
    cursor.close()
    actual_again = dbcontext.get_all_object_attributes()
    assert actual_again == actual




@run_setup_sql(
    # Create the roles
    [attributes.Q_CREATE_ROLE.format(r) for r in ROLES[:3]] +

    # Grant login permission to 2 of the roles
    [attributes.Q_ALTER_ROLE.format(r, 'LOGIN') for r in ROLES[1:3]] +

    # Create personal schemas (i.e. schemas named identically to their owner)
    [ownerships.Q_CREATE_SCHEMA.format(r, r) for r in ROLES[:3]]
)
def test_get_all_personal_schemas(cursor):
    dbcontext = context.DatabaseContext(cursor, verbose=True)
    actual = dbcontext.get_all_personal_schemas()
    expected = set([context.DBObject(schema) for schema in ROLES[1:3]])
    assert actual == expected

    # Make sure that this data is cached for future use
    cursor.close()
    actual_again = dbcontext.get_all_personal_schemas()
    assert actual_again == actual




@run_setup_sql([
    attributes.Q_CREATE_ROLE.format(ROLES[0]),
    attributes.Q_CREATE_ROLE.format(ROLES[1]),
    ])
def test_get_all_role_attributes(cursor):
    dbcontext = context.DatabaseContext(cursor, verbose=True)

    expected = set(['test_user', 'postgres', ROLES[0], ROLES[1]])
    pg_version = dbcontext.get_version_info().postgres_version
    # Postgres 10 introduces several new roles that we have to account for
    if pg_version.startswith('10.'):
        expected.update(set([
            'pg_read_all_settings', 'pg_stat_scan_tables', 'pg_read_all_stats', 'pg_monitor']
        ))

    actual = dbcontext.get_all_role_attributes()
    assert set(actual.keys()) == expected

    # Make sure that this data is cached for future use
    cursor.close()
    actual_again = dbcontext.get_all_role_attributes()
    assert actual_again == actual



def test_get_role_attributes():
    expected = {'foo': 'bar'}
    dbcontext = context.DatabaseContext(cursor=DUMMY, verbose=True)
    dbcontext._cache['get_all_role_attributes'] = lambda: {ROLES[0]: expected}
    actual = dbcontext.get_role_attributes(ROLES[0])
    assert actual == expected




def test_get_role_attributes_role_does_not_exist():
    dbcontext = context.DatabaseContext(cursor=DUMMY, verbose=True)
    dbcontext._cache['get_all_role_attributes'] = lambda: {}
    actual = dbcontext.get_role_attributes(ROLES[0])
    assert actual == dict()




@pytest.mark.parametrize('all_role_attributes, expected', [
    ({ROLES[0]: {'rolsuper': False}}, False),
    ({ROLES[0]: {'rolsuper': True}}, True),
    ({}, False),
])
def test_is_superuser(all_role_attributes, expected):
    dbcontext = context.DatabaseContext(cursor=DUMMY, verbose=True)
    dbcontext._cache['get_all_role_attributes'] = lambda: all_role_attributes
    actual = dbcontext.is_superuser(ROLES[0])
    assert actual == expected



@run_setup_sql([
    # Create two roles
    attributes.Q_CREATE_ROLE.format(ROLES[0]),
    attributes.Q_CREATE_ROLE.format(ROLES[1]),

    # Create a few schemas
    ownerships.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[0]),
    ownerships.Q_CREATE_SCHEMA.format(SCHEMAS[1], ROLES[0]),
    ownerships.Q_CREATE_SCHEMA.format(SCHEMAS[2], ROLES[1]),
    ownerships.Q_CREATE_SCHEMA.format(ROLES[1], ROLES[1]),
    ])
def test_get_all_schemas_and_owners(cursor):
    dbcontext = context.DatabaseContext(cursor, verbose=True)
    expected = {
        SCHEMAS[0]: ROLES[0],
        SCHEMAS[1]: ROLES[0],
        SCHEMAS[2]: ROLES[1],
        ROLES[1]: ROLES[1],
        # These already existed
        'public': 'postgres',
        'information_schema': 'postgres',
        'pg_catalog': 'postgres',
    }

    actual = dbcontext.get_all_schemas_and_owners()
    assert actual == expected

    # Make sure that this data is cached for future use
    cursor.close()
    actual_again = dbcontext.get_all_schemas_and_owners()
    assert actual_again == actual



@run_setup_sql([
    # Create 3 roles
    attributes.Q_CREATE_ROLE.format(ROLES[0]),
    attributes.Q_CREATE_ROLE.format(ROLES[1]),
    attributes.Q_CREATE_ROLE.format(ROLES[2]),

    # Assign memberships
    memberships.Q_GRANT_MEMBERSHIP.format(ROLES[0], ROLES[1]),
    memberships.Q_GRANT_MEMBERSHIP.format(ROLES[1], ROLES[2]),
])
def test_get_all_memberships(cursor):
    dbcontext = context.DatabaseContext(cursor, verbose=True)

    expected = set([('role1', 'role0'), ('role2', 'role1')])
    pg_version = dbcontext.get_version_info().postgres_version
    # Postgres 10 introduces several new roles and memberships that we have to account for
    if pg_version.startswith('10.'):
        expected.update(set([
            ('pg_monitor', 'pg_stat_scan_tables'),
            ('pg_monitor', 'pg_read_all_stats'),
            ('pg_monitor', 'pg_read_all_settings'),
        ]))

    actual = dbcontext.get_all_memberships()
    assert isinstance(actual, list)
    assert len(actual) == len(expected)

    # Convert actual to a set of tuples so comparison is easier
    actual_converted = set([tuple(i) for i in actual])
    assert actual_converted == expected



def test_get_schema_owner():
    schema = 'foo'
    expected_owner = 'bar'
    dbcontext = context.DatabaseContext(cursor=DUMMY, verbose=True)
    dbcontext._cache['get_all_schemas_and_owners'] = lambda: {schema: expected_owner}
    actual = dbcontext.get_schema_owner(schema)
    assert actual == expected_owner



@run_setup_sql([
    # Create a few roles
    attributes.Q_CREATE_ROLE.format(ROLES[0]),
    attributes.Q_CREATE_ROLE.format(ROLES[1]),

    # Create a few schemas
    ownerships.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[0]),
    ownerships.Q_CREATE_SCHEMA.format(SCHEMAS[1], ROLES[1]),

    # Create some objects in those schemas
    Q_CREATE_TABLE.format(ROLES[0], SCHEMAS[0], TABLES[0]),
    Q_CREATE_TABLE.format(ROLES[1], SCHEMAS[1], TABLES[0]),
    Q_CREATE_SEQUENCE.format(ROLES[0], SCHEMAS[0], SEQUENCES[1]),
    Q_CREATE_SEQUENCE.format(ROLES[1], SCHEMAS[1], SEQUENCES[2]),
    ])
def test_get_all_nonschema_objects_and_owners(cursor):
    dbcontext = context.DatabaseContext(cursor, verbose=True)
    expected = {
        SCHEMAS[0]:
        [
            context.ObjectInfo('tables', context.DBObject(schema=SCHEMAS[0], object_name=TABLES[0]), ROLES[0], False),
            context.ObjectInfo('sequences', context.DBObject(schema=SCHEMAS[0], object_name=SEQUENCES[1]), ROLES[0], False),
        ],
        SCHEMAS[1]:
        [
            context.ObjectInfo('tables', context.DBObject(schema=SCHEMAS[1], object_name=TABLES[0]), ROLES[1], False),
            context.ObjectInfo('sequences', context.DBObject(schema=SCHEMAS[1], object_name=SEQUENCES[2]), ROLES[1], False),
        ],
    }
    actual = dbcontext.get_all_nonschema_objects_and_owners()

    # We are deliberately not checking pg_catalog or information_schema here since that's a
    # lot of work and those should not be touched
    for k, v in expected.items():
        assert set(v) == set(actual[k])

    # Make sure that this data is cached for future use
    cursor.close()
    actual_again = dbcontext.get_all_nonschema_objects_and_owners()
    assert actual_again == actual


def test_get_schema_objects():
    schema = 'foo'
    expected = 'bar'
    dbcontext = context.DatabaseContext(cursor=DUMMY, verbose=False)
    dbcontext._cache['get_all_nonschema_objects_and_owners'] = lambda: {schema: expected}
    actual = dbcontext.get_schema_objects(schema)
    assert actual == expected


def test_get_schema_objects_no_entry():
    dbcontext = context.DatabaseContext(cursor=DUMMY, verbose=False)
    dbcontext._cache['get_all_nonschema_objects_and_owners'] = lambda: {
        'foo': 'bar',
    }
    actual = dbcontext.get_schema_objects('key_not_in_response')
    assert actual == []


def test_get_all_raw_object_attributes(cursor):
    dbcontext = context.DatabaseContext(cursor, verbose=True)
    raw_results = dbcontext.get_all_raw_object_attributes()
    assert isinstance(raw_results, list)
    assert len(raw_results) > 0
    assert isinstance(raw_results[0], tuple)

    # Make sure that this data is cached for future use
    cursor.close()
    raw_results_again = dbcontext.get_all_raw_object_attributes()
    assert raw_results_again == raw_results


def test_get_version_info(cursor):
    dbcontext = context.DatabaseContext(cursor, verbose=True)
    actual = dbcontext.get_version_info()

    assert isinstance(actual, context.VersionInfo)
    assert not actual.is_redshift
    assert not actual.redshift_version
    # We do not check the Postgres version since we test against multiple Postgres versions

    # Make sure that this data is cached for future use
    cursor.close()
    actual_again = dbcontext.get_version_info()
    assert actual_again == actual
