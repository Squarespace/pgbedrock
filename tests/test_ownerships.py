import pytest

from conftest import quoted_object, run_setup_sql
from pgbedrock import ownerships as own
from pgbedrock import attributes, privileges
from pgbedrock.context import ObjectInfo

Q_CREATE_SEQUENCE = 'SET ROLE {}; CREATE SEQUENCE {}.{}; RESET ROLE;'
Q_SCHEMA_EXISTS = "SELECT schema_name FROM information_schema.schemata WHERE schema_name='{}';"

ROLES = tuple('role{}'.format(i) for i in range(2))
SCHEMAS = tuple('schema{}'.format(i) for i in range(3))
TABLES = tuple('table{}'.format(i) for i in range(4))
SEQUENCES = tuple('seq{}'.format(i) for i in range(4))
DUMMY = 'foo'


@run_setup_sql([
    'DROP SCHEMA public',
    attributes.Q_CREATE_ROLE.format(ROLES[0]),
    attributes.Q_CREATE_ROLE.format(ROLES[1]),
    ])
def test_analyze_schemas_create_schemas(cursor):
    spec = {
        ROLES[0]: {
            'has_personal_schema': True,
            'owns': {
                'schemas': [SCHEMAS[0]]
            },
        },
        ROLES[1]: {
            'owns': {
                'schemas': [SCHEMAS[1]],
            },
        },
        'postgres': {
            'owns': {
                'schemas': [
                    'information_schema',
                    'pg_catalog',
                ]
            },
        },
    }
    actual = own.analyze_schemas(spec, cursor, verbose=False)

    expected = set([
        own.Q_CREATE_SCHEMA.format(ROLES[0], ROLES[0]),
        own.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[0]),
        own.Q_CREATE_SCHEMA.format(SCHEMAS[1], ROLES[1]),
    ])
    assert set(actual) == expected


def test_init(mockdbcontext):
    mockdbcontext.get_schema_owner = lambda x: 'foo'
    mockdbcontext.get_schema_objects = lambda x: 'bar'
    schemaconf = own.SchemaAnalyzer(rolename=ROLES[0], schema=SCHEMAS[0], dbcontext=mockdbcontext)

    assert schemaconf.rolename == ROLES[0]
    assert schemaconf.schema == SCHEMAS[0]
    assert schemaconf.current_owner == 'foo'
    assert schemaconf.exists is True
    assert schemaconf.schema_objects == 'bar'


def test_analyze_create_schema(mockdbcontext):
    schemaconf = own.SchemaAnalyzer(ROLES[0], schema=SCHEMAS[0], dbcontext=mockdbcontext)
    actual = schemaconf.analyze()
    expected = [own.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[0])]
    assert actual == expected


def test_analyze_existing_schema_owner_change(mockdbcontext):
    mockdbcontext.get_schema_owner = lambda x: ROLES[1]
    schemaconf = own.SchemaAnalyzer(ROLES[0], schema=SCHEMAS[0], dbcontext=mockdbcontext)
    changes = schemaconf.analyze()
    assert changes == [own.Q_SET_SCHEMA_OWNER.format(SCHEMAS[0], ROLES[0], ROLES[1])]


def test_analyze_existing_schema_same_owner(mockdbcontext):
    mockdbcontext.get_schema_owner = lambda x: ROLES[0]
    schemaconf = own.SchemaAnalyzer(ROLES[0], schema=SCHEMAS[0], dbcontext=mockdbcontext)
    changes = schemaconf.analyze()
    assert changes == []


def test_analyze_existing_personal_schema_change_object_owners(mockdbcontext):
    mockdbcontext.get_schema_owner = lambda x: ROLES[0]
    mockdbcontext.get_schema_objects = lambda x: [
        ObjectInfo('tables', quoted_object(ROLES[0], TABLES[0]), ROLES[0], False),
        ObjectInfo('sequences', quoted_object(ROLES[0], SEQUENCES[0]), ROLES[0], False),
        ObjectInfo('tables', quoted_object(ROLES[0], TABLES[1]), ROLES[1], False),
        ObjectInfo('sequences', quoted_object(ROLES[0], SEQUENCES[1]), ROLES[1], False),
    ]
    schema = ROLES[0]

    schemaconf = own.SchemaAnalyzer(ROLES[0], schema=schema, dbcontext=mockdbcontext,
                                    is_personal_schema=True)
    actual = schemaconf.analyze()
    expected = [
        own.Q_SET_OBJECT_OWNER.format('TABLE', quoted_object(ROLES[0], TABLES[1]), ROLES[0], ROLES[1]),
        own.Q_SET_OBJECT_OWNER.format('SEQUENCE', quoted_object(ROLES[0], SEQUENCES[1]), ROLES[0], ROLES[1]),
    ]
    assert actual == expected


def test_create_schema(mockdbcontext):
    schemaconf = own.SchemaAnalyzer(ROLES[0], schema=SCHEMAS[0], dbcontext=mockdbcontext)
    schemaconf.create_schema()

    assert schemaconf.sql_to_run == [own.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[0])]


def test_set_owner(mockdbcontext):
    previous_owner = ROLES[1]
    mockdbcontext.get_schema_owner = lambda x: previous_owner

    schemaconf = own.SchemaAnalyzer(ROLES[0], schema=SCHEMAS[0], dbcontext=mockdbcontext)
    schemaconf.set_owner()

    expected = [own.Q_SET_SCHEMA_OWNER.format(SCHEMAS[0], ROLES[0], previous_owner)]
    assert schemaconf.sql_to_run == expected


def test_alter_object_owner(mockdbcontext):
    previous_owner = ROLES[1]
    owner = ROLES[0]
    schema = SCHEMAS[0]
    table_name = quoted_object(schema, TABLES[0])
    mockdbcontext.get_schema_owner = lambda x: owner

    schemaconf = own.SchemaAnalyzer(owner, schema=schema, dbcontext=mockdbcontext)
    schemaconf.alter_object_owner('tables', table_name, previous_owner)
    assert schemaconf.sql_to_run == [own.Q_SET_OBJECT_OWNER.format('TABLE', table_name, owner, previous_owner)]


def test_get_improperly_owned_objects(mockdbcontext):
    mockdbcontext.get_schema_owner = lambda x: ROLES[0]
    mockdbcontext.get_schema_objects = lambda x: [
        # Properly owned
        ObjectInfo('tables', quoted_object(ROLES[0], TABLES[0]), ROLES[0], False),
        ObjectInfo('sequences', quoted_object(ROLES[0], SEQUENCES[0]), ROLES[0], False),

        # Improperly owned
        ObjectInfo('tables', quoted_object(ROLES[0], TABLES[1]), ROLES[1], False),
        ObjectInfo('sequences', quoted_object(ROLES[0], SEQUENCES[1]), ROLES[1], False),

        # Improperly owned but dependent (i.e. should be skipped)
        ObjectInfo('sequences', quoted_object(ROLES[0], SEQUENCES[2]), ROLES[1], True),
    ]
    schema = ROLES[0]

    schemaconf = own.SchemaAnalyzer(rolename=ROLES[0], schema=schema, dbcontext=mockdbcontext,
                                    is_personal_schema=True)

    actual = schemaconf.get_improperly_owned_objects()
    expected = [('tables', quoted_object(schema, TABLES[1]), ROLES[1]),
                ('sequences', quoted_object(schema, SEQUENCES[1]), ROLES[1])]
    assert set(actual) == set(expected)
