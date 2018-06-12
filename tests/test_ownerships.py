from conftest import quoted_object, run_setup_sql
from pgbedrock import ownerships as own
from pgbedrock import attributes, privileges
from pgbedrock.common import ObjectName
from pgbedrock.context import ObjectInfo

Q_CREATE_SEQUENCE = 'SET ROLE {}; CREATE SEQUENCE {}.{}; RESET ROLE;'
Q_CREATE_TABLE = 'SET ROLE {}; CREATE TABLE {}.{} AS (SELECT 1+1); RESET ROLE;'
Q_SCHEMA_EXISTS = "SELECT schema_name FROM information_schema.schemata WHERE schema_name='{}';"

ROLES = tuple('role{}'.format(i) for i in range(3))
SCHEMAS = tuple('schema{}'.format(i) for i in range(3))
TABLES = tuple('table{}'.format(i) for i in range(4))
SEQUENCES = tuple('seq{}'.format(i) for i in range(4))
DUMMY = 'foo'


@run_setup_sql([
    'DROP SCHEMA public',
    attributes.Q_CREATE_ROLE.format(ROLES[0]),
    attributes.Q_CREATE_ROLE.format(ROLES[1]),
    ])
def test_analyze_ownerships_create_schemas(cursor):
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
    }
    actual = own.analyze_ownerships(spec, cursor, verbose=False)

    expected = set([
        own.Q_CREATE_SCHEMA.format(ROLES[0], ROLES[0]),
        own.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[0]),
        own.Q_CREATE_SCHEMA.format(SCHEMAS[1], ROLES[1]),
    ])
    assert set(actual) == expected


@run_setup_sql([
    'DROP SCHEMA public',
    attributes.Q_CREATE_ROLE.format(ROLES[0]),
    attributes.Q_CREATE_ROLE.format(ROLES[1]),
    own.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[0]),
    own.Q_CREATE_SCHEMA.format(SCHEMAS[1], ROLES[0]),
    privileges.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', SCHEMAS[0], ROLES[1]),
    privileges.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', SCHEMAS[1], ROLES[1]),

    # Create tables in SCHEMAS[0], some of which aren't owned by ROLES[0]
    Q_CREATE_TABLE.format(ROLES[0], SCHEMAS[0], TABLES[0]),
    Q_CREATE_TABLE.format(ROLES[1], SCHEMAS[0], TABLES[1]),
    Q_CREATE_TABLE.format(ROLES[1], SCHEMAS[0], TABLES[2]),
    Q_CREATE_TABLE.format(ROLES[0], SCHEMAS[0], TABLES[3]),

    # Create two sequences in SCHEMAS[1], one of which isn't owned by ROLES[1]
    Q_CREATE_SEQUENCE.format(ROLES[1], SCHEMAS[1], SEQUENCES[0]),
    Q_CREATE_SEQUENCE.format(ROLES[0], SCHEMAS[1], SEQUENCES[1]),
    ])
def test_analyze_ownerships_nonschemas(cursor):
    spec = {
        ROLES[0]: {
            'owns': {
                'tables': ['{}.*'.format(SCHEMAS[0])]
            },
        },
        ROLES[1]: {
            'owns': {
                'sequences': [
                    quoted_object(SCHEMAS[1], SEQUENCES[0]),
                    quoted_object(SCHEMAS[1], SEQUENCES[1]),
                ]
            },
        },
    }
    actual = own.analyze_ownerships(spec, cursor, verbose=False)

    expected = set([
        own.Q_SET_OBJECT_OWNER.format('TABLE', quoted_object(SCHEMAS[0], TABLES[1]),
                                      ROLES[0], ROLES[1]),
        own.Q_SET_OBJECT_OWNER.format('TABLE', quoted_object(SCHEMAS[0], TABLES[2]),
                                      ROLES[0], ROLES[1]),
        own.Q_SET_OBJECT_OWNER.format('SEQUENCE', quoted_object(SCHEMAS[1], SEQUENCES[1]),
                                      ROLES[1], ROLES[0]),
    ])
    assert set(actual) == expected


@run_setup_sql([
    'DROP SCHEMA public',
    attributes.Q_CREATE_ROLE.format(ROLES[0]),
    attributes.Q_CREATE_ROLE.format(ROLES[1]),
    own.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[0]),
    own.Q_CREATE_SCHEMA.format(SCHEMAS[1], ROLES[0]),
    privileges.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', SCHEMAS[0], ROLES[1]),
    privileges.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', SCHEMAS[1], ROLES[1]),

    # Create tables in SCHEMAS[0], some of which aren't owned by ROLES[0]
    Q_CREATE_TABLE.format(ROLES[0], SCHEMAS[0], TABLES[0]),
    Q_CREATE_TABLE.format(ROLES[1], SCHEMAS[0], TABLES[1]),
    Q_CREATE_TABLE.format(ROLES[1], SCHEMAS[0], TABLES[2]),
    Q_CREATE_TABLE.format(ROLES[0], SCHEMAS[0], TABLES[3]),

    # Create two sequences in SCHEMAS[1], one of which isn't owned by ROLES[1]
    Q_CREATE_SEQUENCE.format(ROLES[1], SCHEMAS[1], SEQUENCES[0]),
    Q_CREATE_SEQUENCE.format(ROLES[0], SCHEMAS[1], SEQUENCES[1]),
    ])
def test_analyze_ownerships_schemas_and_nonschemas(cursor):
    """
    This is just a combination of the related schema and nonschema tests to make sure the pieces
    fit together.
    """
    spec = {
        ROLES[0]: {
            'has_personal_schema': True,
            'owns': {
                'tables': ['{}.*'.format(SCHEMAS[0])],
                'schemas': [SCHEMAS[2]],
            },
        },
        ROLES[1]: {
            'owns': {
                'sequences': [
                    quoted_object(SCHEMAS[1], SEQUENCES[0]),
                    quoted_object(SCHEMAS[1], SEQUENCES[1]),
                ]
            },
        },
    }
    actual = own.analyze_ownerships(spec, cursor, verbose=False)

    expected = set([
        own.Q_SET_OBJECT_OWNER.format('TABLE', quoted_object(SCHEMAS[0], TABLES[1]),
                                      ROLES[0], ROLES[1]),
        own.Q_SET_OBJECT_OWNER.format('TABLE', quoted_object(SCHEMAS[0], TABLES[2]),
                                      ROLES[0], ROLES[1]),
        own.Q_SET_OBJECT_OWNER.format('SEQUENCE', quoted_object(SCHEMAS[1], SEQUENCES[1]),
                                      ROLES[1], ROLES[0]),
        own.Q_CREATE_SCHEMA.format(ROLES[0], ROLES[0]),
        own.Q_CREATE_SCHEMA.format(SCHEMAS[2], ROLES[0]),
    ])
    assert set(actual) == expected


def test_schemaanalyzer_init(mockdbcontext):
    mockdbcontext.get_schema_owner = lambda x: 'foo'
    mockdbcontext.get_schema_objects = lambda x: 'bar'
    schemaconf = own.SchemaAnalyzer(rolename=ROLES[0], objname=ObjectName(SCHEMAS[0]),
                                    dbcontext=mockdbcontext)

    assert schemaconf.rolename == ROLES[0]
    assert isinstance(schemaconf.objname, ObjectName)
    assert schemaconf.objname.schema == SCHEMAS[0]
    assert schemaconf.current_owner == 'foo'
    assert schemaconf.exists is True
    assert schemaconf.schema_objects == 'bar'


def test_schemaanalyzer_analyzer_creates_schema(mockdbcontext):
    schemaconf = own.SchemaAnalyzer(ROLES[0], objname=ObjectName(SCHEMAS[0]),
                                    dbcontext=mockdbcontext)
    actual = schemaconf.analyze()
    expected = [own.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[0])]
    assert actual == expected


def test_schemaanalyzer_existing_schema_owner_change(mockdbcontext):
    mockdbcontext.get_schema_owner = lambda x: ROLES[1]
    schemaconf = own.SchemaAnalyzer(ROLES[0], objname=ObjectName(SCHEMAS[0]),
                                    dbcontext=mockdbcontext)
    changes = schemaconf.analyze()
    assert changes == [own.Q_SET_SCHEMA_OWNER.format(SCHEMAS[0], ROLES[0], ROLES[1])]


def test_schemaanalyzer_existing_schema_same_owner(mockdbcontext):
    mockdbcontext.get_schema_owner = lambda x: ROLES[0]
    schemaconf = own.SchemaAnalyzer(ROLES[0], objname=ObjectName(SCHEMAS[0]),
                                    dbcontext=mockdbcontext)
    changes = schemaconf.analyze()
    assert changes == []


def test_schemaanalyzer_existing_personal_schema_change_object_owners(mockdbcontext):
    personal_schema = ROLES[0]
    mockdbcontext.get_schema_owner = lambda x: ROLES[0]
    mockdbcontext.get_schema_objects = lambda x: [
        ObjectInfo('tables', ObjectName(personal_schema, TABLES[0]), ROLES[0], False),
        ObjectInfo('sequences', ObjectName(personal_schema, SEQUENCES[0]), ROLES[0], False),
        ObjectInfo('tables', ObjectName(personal_schema, TABLES[1]), ROLES[1], False),
        ObjectInfo('sequences', ObjectName(personal_schema, SEQUENCES[1]), ROLES[1], False),
    ]
    schemaconf = own.SchemaAnalyzer(ROLES[0], objname=ObjectName(personal_schema),
                                    dbcontext=mockdbcontext, is_personal_schema=True)
    actual = schemaconf.analyze()
    expected = [
        own.Q_SET_OBJECT_OWNER.format('TABLE', quoted_object(ROLES[0], TABLES[1]), ROLES[0], ROLES[1]),
        own.Q_SET_OBJECT_OWNER.format('SEQUENCE', quoted_object(ROLES[0], SEQUENCES[1]), ROLES[0], ROLES[1]),
    ]
    assert actual == expected


def test_schemaanalyzer_create_schema(mockdbcontext):
    schemaconf = own.SchemaAnalyzer(ROLES[0], objname=ObjectName(SCHEMAS[0]), dbcontext=mockdbcontext)
    schemaconf.create_schema()
    assert schemaconf.sql_to_run == [own.Q_CREATE_SCHEMA.format(SCHEMAS[0], ROLES[0])]


def test_schemaanalyzer_set_owner(mockdbcontext):
    previous_owner = ROLES[1]
    mockdbcontext.get_schema_owner = lambda x: previous_owner

    schemaconf = own.SchemaAnalyzer(ROLES[0], objname=ObjectName(SCHEMAS[0]), dbcontext=mockdbcontext)
    schemaconf.set_owner()

    expected = [own.Q_SET_SCHEMA_OWNER.format(SCHEMAS[0], ROLES[0], previous_owner)]
    assert schemaconf.sql_to_run == expected


def test_schemaanalyzer_alter_object_owner(mockdbcontext):
    previous_owner = ROLES[1]
    owner = ROLES[0]
    schema = SCHEMAS[0]
    objname = ObjectName(schema, TABLES[0])
    mockdbcontext.get_schema_owner = lambda x: owner

    schemaconf = own.SchemaAnalyzer(owner, objname=ObjectName(schema), dbcontext=mockdbcontext)
    schemaconf.alter_object_owner('tables', objname, previous_owner)
    assert schemaconf.sql_to_run == [
        own.Q_SET_OBJECT_OWNER.format('TABLE', objname.qualified_name, owner, previous_owner)
    ]


def test_schemaanalyzer_get_improperly_owned_objects(mockdbcontext):
    owner = ROLES[0]
    wrong_owner = ROLES[1]
    mockdbcontext.get_schema_owner = lambda x: owner
    mockdbcontext.get_schema_objects = lambda x: [
        # Properly owned
        ObjectInfo('tables', ObjectName(owner, TABLES[0]), owner, False),
        ObjectInfo('sequences', ObjectName(owner, SEQUENCES[0]), owner, False),

        # Improperly owned
        ObjectInfo('tables', ObjectName(owner, TABLES[1]), wrong_owner, False),
        ObjectInfo('sequences', ObjectName(owner, SEQUENCES[1]), wrong_owner, False),

        # Improperly owned but dependent (i.e. should be skipped)
        ObjectInfo('sequences', ObjectName(owner, SEQUENCES[2]), wrong_owner, True),
    ]
    schemaconf = own.SchemaAnalyzer(rolename=owner, objname=ObjectName(owner),
                                    dbcontext=mockdbcontext, is_personal_schema=True)

    actual = schemaconf.get_improperly_owned_objects()
    expected = [('tables', ObjectName(owner, TABLES[1]), wrong_owner),
                ('sequences', ObjectName(owner, SEQUENCES[1]), wrong_owner)]
    assert set(actual) == set(expected)


def test_nonschemaanalyzer_expand_schema_objects(mockdbcontext):
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0], TABLES[0]): {'owner': DUMMY, 'is_dependent': False},
                ObjectName(SCHEMAS[0], TABLES[1]): {'owner': DUMMY, 'is_dependent': False},
                ObjectName(SCHEMAS[0], TABLES[2]): {'owner': DUMMY, 'is_dependent': True},
            },
        },
    }
    nsa = own.NonschemaAnalyzer(rolename=ROLES[0], objname=DUMMY,
                                objkind='tables', dbcontext=mockdbcontext)
    actual = nsa.expand_schema_objects(SCHEMAS[0])
    expected = [ObjectName(SCHEMAS[0], TABLES[0]), ObjectName(SCHEMAS[0], TABLES[1])]
    assert set(actual) == set(expected)


def test_nonschemaanalyzer_analyze_no_changed_needed(mockdbcontext):
    objname = ObjectName(SCHEMAS[0], TABLES[0])
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            SCHEMAS[0]: {
                objname: {'owner': ROLES[0], 'is_dependent': False},
            },
        },
    }
    nsa = own.NonschemaAnalyzer(rolename=ROLES[0], objname=objname,
                                objkind='tables', dbcontext=mockdbcontext)
    actual = nsa.analyze()
    assert actual == []


def test_nonschemaanalyzer_analyze_without_schema_expansion(mockdbcontext):
    objname = ObjectName(SCHEMAS[0], TABLES[0])
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            SCHEMAS[0]: {
                objname: {'owner': ROLES[1], 'is_dependent': False},
            },
        },
    }
    nsa = own.NonschemaAnalyzer(rolename=ROLES[0], objname=objname,
                                objkind='tables', dbcontext=mockdbcontext)
    actual = nsa.analyze()
    expected = [own.Q_SET_OBJECT_OWNER.format('TABLE', objname.qualified_name, ROLES[0], ROLES[1])]
    assert actual == expected


def test_nonschemaanalyzer_analyze_with_schema_expansion(mockdbcontext):
    mockdbcontext.get_all_object_attributes = lambda: {
        'sequences': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0], SEQUENCES[0]): {'owner': ROLES[1], 'is_dependent': False},
                ObjectName(SCHEMAS[0], SEQUENCES[1]): {'owner': ROLES[2], 'is_dependent': False},
                # This will be skipped as the owner is correct
                ObjectName(SCHEMAS[0], SEQUENCES[2]): {'owner': ROLES[0], 'is_dependent': False},
                # This will be skipped as it is dependent
                ObjectName(SCHEMAS[0], SEQUENCES[3]): {'owner': ROLES[1], 'is_dependent': True},
            },
        },
    }
    nsa = own.NonschemaAnalyzer(rolename=ROLES[0], objname=ObjectName(SCHEMAS[0], '*'),
                                objkind='sequences', dbcontext=mockdbcontext)
    actual = nsa.analyze()
    expected = [
        own.Q_SET_OBJECT_OWNER.format('SEQUENCE', ObjectName(SCHEMAS[0], SEQUENCES[0]).qualified_name,
                                      ROLES[0], ROLES[1]),
        own.Q_SET_OBJECT_OWNER.format('SEQUENCE', ObjectName(SCHEMAS[0], SEQUENCES[1]).qualified_name,
                                      ROLES[0], ROLES[2]),
    ]
    assert set(actual) == set(expected)
