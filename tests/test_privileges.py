"""
NOTES:
    * In all tests that have a "grantee" (i.e. the role being analyzed), ROLES[0] is that
      grantee. This convention is maintained across tests because with so much setup a bit of
      consistency is helpful
"""
from collections import defaultdict
import itertools

import pytest
import yaml

from conftest import quoted_object, run_setup_sql
from pgbedrock import privileges as privs, attributes, ownerships, spec_inspector
from pgbedrock.common import ObjectName


Q_CREATE_TABLE = 'SET ROLE {}; CREATE TABLE {}.{} AS (SELECT 1+1); RESET ROLE;'
Q_CREATE_SEQUENCE = 'SET ROLE {}; CREATE SEQUENCE {}.{}; RESET ROLE;'
Q_HAS_PRIVILEGE = "SELECT has_table_privilege('{}', '{}', 'SELECT');"

SCHEMAS = tuple('schema{}'.format(i) for i in range(4))
ROLES = tuple('role{}'.format(i) for i in range(5))
TABLES = tuple('table{}'.format(i) for i in range(6))
SEQUENCES = tuple('seq{}'.format(i) for i in range(6))
DUMMY = 'foo'


@run_setup_sql(
    # Create the roles; role0 and role1 will be in our test, role2 and role3
    # own objects, with role3 owning all schemas
    [attributes.Q_CREATE_ROLE.format(r) for r in ROLES] +

    # Create 3 schemas, all owned by role3
    [ownerships.Q_CREATE_SCHEMA.format(s, ROLES[3]) for s in SCHEMAS[:3]] +

    # Let role2 create objects in the schemas
    [privs.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', s, ROLES[2]) for s in SCHEMAS[:3]] +
    [

        # Create tables. Note that these tables are owned by both role2 and role3 in each schema
        # except schema2, where only role2 owns tables (this is used to make sure that the schema
        # owner is included in default privileges even if it doesn't own an object in the schema)
        Q_CREATE_TABLE.format(ROLES[2], SCHEMAS[0], TABLES[0]),
        Q_CREATE_TABLE.format(ROLES[3], SCHEMAS[0], TABLES[1]),
        Q_CREATE_TABLE.format(ROLES[2], SCHEMAS[1], TABLES[2]),
        Q_CREATE_TABLE.format(ROLES[3], SCHEMAS[1], TABLES[3]),
        Q_CREATE_TABLE.format(ROLES[2], SCHEMAS[2], TABLES[4]),
        Q_CREATE_TABLE.format(ROLES[2], SCHEMAS[2], TABLES[5]),

        # Create sequences, following the same approach asused above for tables
        Q_CREATE_SEQUENCE.format(ROLES[2], SCHEMAS[0], SEQUENCES[0]),
        Q_CREATE_SEQUENCE.format(ROLES[3], SCHEMAS[0], SEQUENCES[1]),
        Q_CREATE_SEQUENCE.format(ROLES[2], SCHEMAS[1], SEQUENCES[2]),
        Q_CREATE_SEQUENCE.format(ROLES[3], SCHEMAS[1], SEQUENCES[3]),
        Q_CREATE_SEQUENCE.format(ROLES[2], SCHEMAS[2], SEQUENCES[4]),
        Q_CREATE_SEQUENCE.format(ROLES[2], SCHEMAS[2], SEQUENCES[5]),

        # Grant a couple unwanted default privileges to assert that they will be revoked
        privs.Q_GRANT_DEFAULT.format(ROLES[3], SCHEMAS[1], 'SELECT', 'TABLES', ROLES[0]),
        privs.Q_GRANT_DEFAULT.format(ROLES[3], SCHEMAS[1], 'TRIGGER', 'TABLES', ROLES[0]),

        # Grant privileges that would come along with the above default privs (i.e. if default
        # SELECT table priv, then grant SELECT to all existing tables)
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', '{}.{}'.format(SCHEMAS[1], TABLES[2]), ROLES[0]),
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', '{}.{}'.format(SCHEMAS[1], TABLES[3]), ROLES[0]),
        privs.Q_GRANT_NONDEFAULT.format('TRIGGER', 'TABLE', '{}.{}'.format(SCHEMAS[1], TABLES[2]), ROLES[0]),
        privs.Q_GRANT_NONDEFAULT.format('TRIGGER', 'TABLE', '{}.{}'.format(SCHEMAS[1], TABLES[3]), ROLES[0]),

        # Grant a non-default privilege that will be subsumed by a default privilege grant
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', '{}.{}'.format(SCHEMAS[0], TABLES[0]), ROLES[0]),

        # Grant a couple unwanted non-default privileges to assert that they will be revoked
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', '{}.{}'.format(SCHEMAS[2], TABLES[5]), ROLES[0]),
        privs.Q_GRANT_NONDEFAULT.format('UPDATE', 'SEQUENCE', '{}.{}'.format(SCHEMAS[1], SEQUENCES[2]), ROLES[1]),
    ]
)
def test_analyze_privileges(cursor):
    """
    End-to-end test to assert a slew of high-level behavior. Note that this test is painful, but if
    it breaks we _should_ have a lower-level unit test that breaks as well. This test is here to
    make sure all the pieces fit together as expected.

    We start with our roles' privileges in one state and then run analyze_roles() to end up in a
    different state, asserting that the changes that were made are what we expect.

    Starting state:
        Role0:
            tables:
                read:
                    - schema0.table0
                    - schema1.*
                    - schema2.table5
                write:
                    - schema1.* (only TRIGGER)
        Role1:
            sequences:
                write:
                    - schema1.sequence2 (only UPDATE)
        Role2:
            privileges:
                schemas:
                    write:
                        - schema0
                        - schema1
                        - schema2
        Role3:
            owns:
                schemas:
                    - schema0
                    - schema1
                    - schema2
        Role4:
            privileges:
                tables:
                    read:
                        - schema0.*
                    except:
                        - schema0.table2 (Role4 can read all tables except for table 2 in schema 0)
    """
    unconverted_desired_spec = yaml.safe_load("""
        {role0}:
            privileges:
                tables:
                    write:
                        - {schema0}.*
                        - {schema1}.{table2}
        {role1}:
            privileges:
                sequences:
                    read:
                        - {schema0}.{sequence1}
                        - {schema2}.*
        {role2}:
            privileges:
                schemas:
                    write:
                        - {schema0}
                        - {schema1}
                        - {schema2}
        {role3}:
            owns:
                schemas:
                    - {schema0}
                    - {schema1}
                    - {schema2}
        {role4}:
            privileges:
                tables:
                    read:
                        - {schema0}.*
                    except:
                        - {schema0}.{table1}
    """.format(role0=ROLES[0], role1=ROLES[1], role2=ROLES[2], role3=ROLES[3], role4=ROLES[4],
               schema0=SCHEMAS[0], schema1=SCHEMAS[1], schema2=SCHEMAS[2], sequence1=SEQUENCES[1],
               table1=TABLES[1], table2=TABLES[2]))
    desired_spec = spec_inspector.convert_spec_to_objectnames(unconverted_desired_spec)

    expected_role0_changes = set([
        # Revoke read schema2.table5 from role0
        privs.Q_REVOKE_NONDEFAULT.format('SELECT', 'TABLE', quoted_object(SCHEMAS[2], TABLES[5]), ROLES[0]),

        # Revoke SELECT and TRIGGER from schema1.table3 from role0
        privs.Q_REVOKE_NONDEFAULT.format('SELECT', 'TABLE', quoted_object(SCHEMAS[1], TABLES[3]), ROLES[0]),
        privs.Q_REVOKE_NONDEFAULT.format('TRIGGER', 'TABLE', quoted_object(SCHEMAS[1], TABLES[3]), ROLES[0]),

        # Revoke default SELECT and TRIGGER privs on tables in schema1 from role0 (granted by role3)
        privs.Q_REVOKE_DEFAULT.format(ROLES[3], SCHEMAS[1], 'SELECT', 'TABLES', ROLES[0]),
        privs.Q_REVOKE_DEFAULT.format(ROLES[3], SCHEMAS[1], 'TRIGGER', 'TABLES', ROLES[0]),

        # Grant default read on tables in schema0 to role0 from role3 and role2 (both own objects)
        privs.Q_GRANT_DEFAULT.format(ROLES[3], SCHEMAS[0], 'SELECT', 'TABLES', ROLES[0]),
        privs.Q_GRANT_DEFAULT.format(ROLES[2], SCHEMAS[0], 'SELECT', 'TABLES', ROLES[0]),

        # Grant read on all tables in schema0 except schema0.table0 (it already has read)
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', quoted_object(SCHEMAS[0], TABLES[1]), ROLES[0]),
    ]

        # Grant write on schema1.table2 to role0 (already has SELECT and TRIGGER)
        + [privs.Q_GRANT_NONDEFAULT.format(priv, 'TABLE', quoted_object(SCHEMAS[1], TABLES[2]), ROLES[0])
           for priv in privs.PRIVILEGE_MAP['tables']['write'] if priv not in ('SELECT', 'TRIGGER')]

        # Grant default write on tables in schema0 to role0 from role3 and role2 (both own objects)
        + [privs.Q_GRANT_DEFAULT.format(r, SCHEMAS[0], priv, 'TABLES', ROLES[0])
           for priv in privs.PRIVILEGE_MAP['tables']['write'] for r in (ROLES[2], ROLES[3])]

        # Grant write on all tables in schema0 to role0
        + [privs.Q_GRANT_NONDEFAULT.format(priv, 'TABLE', quoted_object(SCHEMAS[0], t), ROLES[0])
           for priv in privs.PRIVILEGE_MAP['tables']['write'] for t in (TABLES[0], TABLES[1])]
    )

    expected_role1_changes = set([
        # Revoke UPDATE for schema1.sequence2 from role1
        privs.Q_REVOKE_NONDEFAULT.format('UPDATE', 'SEQUENCE', quoted_object(SCHEMAS[1], SEQUENCES[2]), ROLES[1]),

        # Grant read for schema0.sequence1 to role1
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'SEQUENCE', quoted_object(SCHEMAS[0], SEQUENCES[1]), ROLES[1]),

        # Grant default read for sequences in schema2 to role1 from role3 (schema owner)
        # and role2 (owns all sequences in schema)
        privs.Q_GRANT_DEFAULT.format(ROLES[2], SCHEMAS[2], 'SELECT', 'SEQUENCES', ROLES[1]),
        privs.Q_GRANT_DEFAULT.format(ROLES[3], SCHEMAS[2], 'SELECT', 'SEQUENCES', ROLES[1]),

        # Grant read on all sequences in schema2 since we're granting default read
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'SEQUENCE', quoted_object(SCHEMAS[2], SEQUENCES[4]), ROLES[1]),
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'SEQUENCE', quoted_object(SCHEMAS[2], SEQUENCES[5]), ROLES[1]),
    ])

    expected_role2_changes = set([
        # role2 has write access on schema0 but doesn't have read access; this will be granted
        privs.Q_GRANT_NONDEFAULT.format('USAGE', 'SCHEMA', s, ROLES[2]) for s in SCHEMAS[:3]
    ])

    expected_role4_changes = set([
        # role4 has read access on schema0 except for table1 (which is excepted)
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', quoted_object(SCHEMAS[0], TABLES[0]), ROLES[4]),
        # Grant default read for sequences in schema2 to role4 from role3 (schema owner)
        # and role2 (owns all sequences in schema)
        privs.Q_GRANT_DEFAULT.format(ROLES[2], SCHEMAS[0], 'SELECT', 'TABLES', ROLES[4]),
        privs.Q_GRANT_DEFAULT.format(ROLES[3], SCHEMAS[0], 'SELECT', 'TABLES', ROLES[4]),
    ])

    expected = expected_role0_changes.union(expected_role1_changes).union(expected_role2_changes).union(expected_role4_changes)
    all_sql_to_run = privs.analyze_privileges(desired_spec, cursor, verbose=False)
    actual = set(all_sql_to_run)
    expected_but_not_actual = expected.difference(actual)
    actual_but_not_expected = actual.difference(expected)

    assert expected_but_not_actual == set()
    assert actual_but_not_expected == set()


@run_setup_sql([
    attributes.Q_CREATE_ROLE.format(ROLES[0]),
    attributes.Q_ALTER_ROLE.format(ROLES[0], 'SUPERUSER')
])
def test_analyze_privileges_skips_superuser(cursor):
    desired_spec = yaml.safe_load("""
        {role0}:
            privileges:
                tables:
                    write:
                        - foo.bar
                sequences:
                    write:
                        - baz.bip
    """.format(role0=ROLES[0]))

    actual = privs.analyze_privileges(desired_spec, cursor, verbose=False)
    expected = [privs.SKIP_SUPERUSER_PRIVILEGE_CONFIGURATION_MSG.format(ROLES[0])]
    assert actual == expected


@pytest.mark.parametrize('object_kind', privs.PRIVILEGE_MAP.keys())
def test_init_default_acl_possible(object_kind, mockdbcontext):
    privconf = privs.PrivilegeAnalyzer(rolename=DUMMY, access=DUMMY, object_kind=object_kind,
                                       desired_items=DUMMY, schema_writers=DUMMY,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext,
                                       excepted_items=[])
    expected = object_kind in privs.OBJECTS_WITH_DEFAULTS
    assert privconf.default_acl_possible is expected


def test_get_schema_objects_tables(mockdbcontext):
    objattributes = {'owner': ROLES[0], 'is_dependent': False}
    all_attributes = {ObjectName(SCHEMAS[0], t): objattributes for t in TABLES}
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            SCHEMAS[0]: all_attributes
        }
    }

    privconf = privs.PrivilegeAnalyzer(rolename=DUMMY, access=DUMMY, object_kind='tables',
                                       desired_items=DUMMY, schema_writers=DUMMY,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext, excepted_items=[])

    # Assert that we get back the tables that are in the context object
    actual = privconf.get_schema_objects(SCHEMAS[0])
    expected = set([ObjectName(SCHEMAS[0], t) for t in TABLES])
    assert actual == expected


def test_get_schema_objects_sequences(mockdbcontext):
    """ While this test is almost identical to test_get_schema_objects_tables(), it's here because
    we want to ensure we have coverage over more than just tables """
    objattributes = {'owner': ROLES[0], 'is_dependent': False}
    all_attributes = {ObjectName(SCHEMAS[0], seq): objattributes for seq in SEQUENCES}
    mockdbcontext.get_all_object_attributes = lambda: {
        'sequences': {
            SCHEMAS[0]: all_attributes
        }
    }

    privconf = privs.PrivilegeAnalyzer(rolename=DUMMY, access=DUMMY, object_kind='sequences',
                                       desired_items=DUMMY, schema_writers=DUMMY,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext, excepted_items=[])
    # Assert that we get back the sequences that are in the context object
    actual = privconf.get_schema_objects(SCHEMAS[0])
    expected = set([ObjectName(SCHEMAS[0], seq) for seq in SEQUENCES])
    assert actual == expected


@pytest.mark.parametrize('object_kind, objname, expected', [
    ('schemas', ObjectName(SCHEMAS[0]), ROLES[0]),
    ('sequences', ObjectName(SCHEMAS[0], SEQUENCES[0]), ROLES[1]),
    ('tables', ObjectName(SCHEMAS[0], TABLES[1]), ROLES[2]),
])
def test_get_object_owner(mockdbcontext, object_kind, objname, expected):
    mockdbcontext.get_all_object_attributes = lambda: {
        'schemas': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0]): {'owner': ROLES[0], 'is_dependent': False},
            },
        }, 'sequences': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0], SEQUENCES[0]): {'owner': ROLES[1], 'is_dependent': False},
            },
        }, 'tables': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0], TABLES[1]): {'owner': ROLES[2], 'is_dependent': False},
            },
        },
    }

    privconf = privs.PrivilegeAnalyzer(rolename=DUMMY, access=DUMMY, object_kind=object_kind,
                                       desired_items=DUMMY, schema_writers=DUMMY,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext, excepted_items=[])
    actual = privconf.get_object_owner(objname)
    assert actual == expected


def test_get_object_owner_nonexistent_object(capsys, mockdbcontext):
    object_kind = 'tables'
    objname = ObjectName('foo', 'bar')
    mockdbcontext.get_all_object_attributes = lambda: {}
    privconf = privs.PrivilegeAnalyzer(rolename=ROLES[0], access=DUMMY, object_kind=object_kind,
                                       desired_items=DUMMY, schema_writers=DUMMY,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext, excepted_items=[])

    with pytest.raises(SystemExit):
        privconf.get_object_owner(objname)

    out, _ = capsys.readouterr()
    assert out == privs.OBJECT_DOES_NOT_EXIST_ERROR_MSG.format('table', objname.qualified_name,
                                                               ROLES[0]) + '\n'


def test_determine_desired_defaults(mockdbcontext):
    """ Make sure that desired default privileges include:
            (all object owners in the schema + schema owner)
            crossed with (all privileges associated with this object and access type)
    """
    # Using sequence-write because it has 2 types of privileges (i.e. >1 but not a ton)
    object_kind = 'sequences'
    access = 'write'
    schema_writers = {ObjectName(SCHEMAS[0]): set(ROLES[1:])}
    privconf = privs.PrivilegeAnalyzer(rolename=ROLES[0], access=access, object_kind=object_kind,
                                       desired_items=DUMMY, schema_writers=schema_writers,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext, excepted_items=[])

    schemas = [ObjectName(SCHEMAS[0])]
    roles = ROLES[1:]
    possible_privs = privs.PRIVILEGE_MAP[object_kind][access]
    expected = set(itertools.product(roles, schemas, possible_privs))

    privconf.determine_desired_defaults(schemas)
    actual = privconf.desired_defaults

    assert actual == expected


@pytest.mark.parametrize('rolename', [ROLES[0], ROLES[1], ROLES[2]])
def test_identify_desired_objects(rolename, mockdbcontext):
    """
    Verify a variety of aspects of the PrivilegeAnalyzer.identify_desired_objects()
    method, including:
        * We properly deal with schema.*
        * When a schema owner doesn't have any objects it shows up in our default privileges set
        * When a schema owner doesn't have any objects it does not show up in our non default
          privileges set
        * It doesn't matter to this method whether the role in question owns the schema, tables, or
          anything else (that's the mark.parametrize part)
    """
    # Using sequence-write because it has 2 types of privileges (i.e. >1 but not a ton)
    object_kind = 'sequences'
    access = 'write'
    mockdbcontext.get_all_object_attributes = lambda: {
        'sequences': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0], SEQUENCES[0]): {'owner': ROLES[1], 'is_dependent': False},
                ObjectName(SCHEMAS[0], SEQUENCES[1]): {'owner': ROLES[2], 'is_dependent': False},
                ObjectName(SCHEMAS[0], SEQUENCES[2]): {'owner': ROLES[2], 'is_dependent': False},
            }, SCHEMAS[1]: {
                ObjectName(SCHEMAS[1], SEQUENCES[0]): {'owner': ROLES[2], 'is_dependent': False},
                ObjectName(SCHEMAS[1], SEQUENCES[1]): {'owner': ROLES[1], 'is_dependent': False},
            },
        },
        'schemas': {
            SCHEMAS[0]: {ObjectName(SCHEMAS[0]): {'owner': ROLES[0]}, 'is_dependent': False},
            SCHEMAS[1]: {ObjectName(SCHEMAS[1]): {'owner': ROLES[0]}, 'is_dependent': False},
        },
    }

    desired_items = [
        ObjectName(SCHEMAS[0], '*'),
        ObjectName(SCHEMAS[1], SEQUENCES[0]),
        ObjectName(SCHEMAS[1], SEQUENCES[1])
    ]

    schema_writers = {ObjectName(SCHEMAS[0]): set(ROLES[:3])}

    privconf = privs.PrivilegeAnalyzer(rolename, access=access, object_kind=object_kind,
                                       desired_items=desired_items, schema_writers=schema_writers,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext, excepted_items=[])
    privconf.identify_desired_objects()

    # We don't grant default privileges when the grantor is the role itself because in that case
    # the role already can access the objects (since it owns them). As a result, we need to remove
    # the grantee role from this list. We need this `if` check because there is one role (role3)
    # that doesn't own anything and shouldn't show up in our list
    possible_privs = privs.PRIVILEGE_MAP[object_kind][access]
    roles = list(ROLES[:3])
    # We have to remove this role since we don't grant default privileges to ourselves
    roles.remove(rolename)
    expected_defaults = set(itertools.product(roles, [ObjectName(SCHEMAS[0])], possible_privs))

    actual_defaults = privconf.desired_defaults
    assert actual_defaults == expected_defaults

    nondefault_items = [ObjectName(SCHEMAS[0], t) for t in SEQUENCES[0:3]] \
                     + [ObjectName(SCHEMAS[1], t) for t in SEQUENCES[:2]]

    # Remove things owned by the given role
    if rolename == ROLES[1]:
        nondefault_items.remove(ObjectName(SCHEMAS[0], SEQUENCES[0]))
        nondefault_items.remove(ObjectName(SCHEMAS[1], SEQUENCES[1]))
    elif rolename == ROLES[2]:
        nondefault_items.remove(ObjectName(SCHEMAS[0], SEQUENCES[1]))
        nondefault_items.remove(ObjectName(SCHEMAS[0], SEQUENCES[2]))
        nondefault_items.remove(ObjectName(SCHEMAS[1], SEQUENCES[0]))

    expected_nondefaults = set(itertools.product(nondefault_items, possible_privs))
    actual_nondefaults = privconf.desired_nondefaults
    assert actual_nondefaults == expected_nondefaults


def test_identify_desired_objects_personal_schemas_object_kind_is_schema(mockdbcontext):
    """ Make sure that if we desire 'personal_schemas' and the object_kind is a schema
    that the personal schemas do show up """
    mockdbcontext.get_all_object_attributes = lambda: {
        'schemas': {
            SCHEMAS[0]: {ObjectName(SCHEMAS[0]): {'owner': ROLES[0]}, 'is_dependent': False},
            SCHEMAS[1]: {ObjectName(SCHEMAS[1]): {'owner': ROLES[0]}, 'is_dependent': False},
        },
    }
    personal_schemas = set([
        ObjectName(ROLES[1]),
        ObjectName(ROLES[2]),
        ObjectName(ROLES[3]),
    ])
    access = 'read'
    object_kind = 'schemas'
    desired_items = [ObjectName(SCHEMAS[0]), ObjectName(SCHEMAS[1]), ObjectName('personal_schemas')]
    privconf = privs.PrivilegeAnalyzer(rolename=DUMMY, access=access, object_kind=object_kind,
                                       desired_items=desired_items, schema_writers=DUMMY,
                                       personal_schemas=personal_schemas, dbcontext=mockdbcontext,
                                       excepted_items=[])
    privconf.identify_desired_objects()

    nonpersonal_expected_schemas = set([ObjectName(SCHEMAS[0]), ObjectName(SCHEMAS[1])])
    expected_schemas = nonpersonal_expected_schemas.union(personal_schemas)
    possible_privs = privs.PRIVILEGE_MAP[object_kind][access]
    expected = set(itertools.product(expected_schemas, possible_privs))
    actual = set(privconf.desired_nondefaults)
    assert actual == expected


def test_identify_desired_objects_personal_schemas_object_kind_is_not_schema(mockdbcontext):
    """ Make sure that if we desire 'personal_schemas.*' and the object_kind is something
    other than 'schema' that items in personal schemas show up in the the desired_nondefaults and
    the personal schemas show up in the desired_defaults """
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0], TABLES[0]): {'owner': ROLES[1], 'is_dependent': False},
            },
            ROLES[2]: {
                ObjectName(ROLES[2], TABLES[2]): {'owner': ROLES[2], 'is_dependent': False},
                ObjectName(ROLES[2], TABLES[3]): {'owner': ROLES[2], 'is_dependent': False},
            },
            ROLES[3]: {
                ObjectName(ROLES[3], TABLES[4]): {'owner': ROLES[3], 'is_dependent': False},
                ObjectName(ROLES[3], TABLES[5]): {'owner': ROLES[3], 'is_dependent': False},
            },
        }, 'schemas': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0]): {'owner': ROLES[1]}, 'is_dependent': False
            },
            ROLES[2]: {
                ObjectName(ROLES[2]): {'owner': ROLES[2]}, 'is_dependent': False
            },
            ROLES[3]: {
                ObjectName(ROLES[3]): {'owner': ROLES[3]}, 'is_dependent': False
            },
        },
    }
    personal_schemas = set([ObjectName(ROLES[2]), ObjectName(ROLES[3])])
    access = 'read'
    object_kind = 'tables'
    desired_items = [
        ObjectName(SCHEMAS[0], TABLES[0]),
        ObjectName('personal_schemas', '*')
    ]
    schema_writers = {
        ObjectName(ROLES[2]): set([ROLES[2], ROLES[1]]),
        ObjectName(ROLES[3]): set([ROLES[3]]),
    }
    privconf = privs.PrivilegeAnalyzer(ROLES[0], access=access, object_kind=object_kind,
                                       desired_items=desired_items, schema_writers=schema_writers,
                                       personal_schemas=personal_schemas, dbcontext=mockdbcontext,
                                       excepted_items=[])
    privconf.identify_desired_objects()

    # Check default privileges
    possible_privs = privs.PRIVILEGE_MAP[object_kind][access]
    expected_defaults = set([
        (ROLES[2], ObjectName(ROLES[2]), possible_privs[0]),
        (ROLES[1], ObjectName(ROLES[2]), possible_privs[0]),
        (ROLES[3], ObjectName(ROLES[3]), possible_privs[0])
    ])
    actual_defaults = privconf.desired_defaults
    assert actual_defaults == expected_defaults

    # Check non-default privileges
    expected_nondefault_items = [
        ObjectName(SCHEMAS[0], TABLES[0]),
        ObjectName(ROLES[2], TABLES[2]),
        ObjectName(ROLES[2], TABLES[3]),
        ObjectName(ROLES[3], TABLES[4]),
        ObjectName(ROLES[3], TABLES[5]),
    ]
    expected_nondefaults = set(itertools.product(expected_nondefault_items, possible_privs))
    actual_nondefaults = privconf.desired_nondefaults
    assert actual_nondefaults == expected_nondefaults


def test_identify_desired_objects_personal_schemas_error_expected(capsys, mockdbcontext):
    """ Verify that an error is raised if 'personal_schemas' is requested
    and the object_kind is not 'schema' """
    access = 'read'
    object_kind = 'tables'
    privconf = privs.PrivilegeAnalyzer(rolename=DUMMY, access=access, object_kind=object_kind,
                                       desired_items=[ObjectName('personal_schemas')],
                                       schema_writers=DUMMY, personal_schemas=DUMMY,
                                       dbcontext=mockdbcontext, excepted_items=[])
    with pytest.raises(SystemExit):
        privconf.identify_desired_objects()
    expected_err_msg = privs.PERSONAL_SCHEMAS_ERROR_MSG.format(DUMMY, object_kind, access) + '\n'
    assert capsys.readouterr()[0] == expected_err_msg


def test_grant_default(mockdbcontext):
    rolename = ROLES[0]
    privconf = privs.PrivilegeAnalyzer(rolename=rolename, access='read', object_kind='tables',
                                       desired_items=DUMMY, schema_writers=DUMMY,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext,
                                       excepted_items=[])

    # Grant default privileges to role0 from role1 for this schema
    privconf.grant_default(grantor=ROLES[1], schema=ObjectName(SCHEMAS[0]), privilege='SELECT')

    expected = [privs.Q_GRANT_DEFAULT.format(ROLES[1], SCHEMAS[0], 'SELECT', 'TABLES', rolename)]
    assert privconf.sql_to_run == expected


def test_revoke_default(mockdbcontext):
    rolename = ROLES[0]

    # Revoke default privileges from role0 for this schema granted by role1
    privconf = privs.PrivilegeAnalyzer(rolename=rolename, access='read', object_kind='tables',
                                       desired_items=DUMMY, schema_writers=DUMMY,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext,
                                       excepted_items=[])

    privconf.revoke_default(grantor=ROLES[1], schema=ObjectName(SCHEMAS[0]), privilege='SELECT')

    expected = [privs.Q_REVOKE_DEFAULT.format(ROLES[1], SCHEMAS[0], 'SELECT', 'TABLES', rolename)]
    assert privconf.sql_to_run == expected


def test_grant_nondefault(mockdbcontext):
    table = ObjectName(SCHEMAS[0], TABLES[0])
    rolename = ROLES[0]

    # Grant the privilege
    privconf = privs.PrivilegeAnalyzer(rolename=rolename, access=DUMMY, object_kind='tables',
                                       desired_items=DUMMY, schema_writers=DUMMY,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext,
                                       excepted_items=[])

    privconf.grant_nondefault(table, 'SELECT')
    expected = [privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', table.qualified_name, rolename)]
    assert privconf.sql_to_run == expected


def test_revoke_nondefault(mockdbcontext):
    table = ObjectName(SCHEMAS[0], TABLES[0])
    rolename = ROLES[0]

    # Revoke the privilege
    privconf = privs.PrivilegeAnalyzer(rolename=rolename, access=DUMMY, object_kind='tables',
                                       desired_items=DUMMY, schema_writers=DUMMY,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext, excepted_items=[])

    privconf.revoke_nondefault(table, 'SELECT')
    expected = [privs.Q_REVOKE_NONDEFAULT.format('SELECT', 'TABLE', table.qualified_name, rolename)]
    assert privconf.sql_to_run == expected


def test_analyze_defaults(mockdbcontext):
    mockdbcontext.get_role_current_defaults = lambda x, y, z: set([
        (ROLES[3], ObjectName(SCHEMAS[0]), 'SELECT'),
    ])
    mockdbcontext.get_role_current_nondefaults = lambda x, y, z: set()
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0], TABLES[0]): {'owner': ROLES[2], 'is_dependent': False},
            },
        },
        'schemas': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0]): {'owner': ROLES[1], 'is_dependent': False},
            },
        },
    }

    desired_items = [ObjectName(SCHEMAS[0], '*')]
    schema_writers = {
        ObjectName(SCHEMAS[0]): set([ROLES[1], ROLES[2]]),
    }
    privconf = privs.PrivilegeAnalyzer(rolename=ROLES[0], access='read', object_kind='tables',
                                       desired_items=desired_items, schema_writers=schema_writers,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext, excepted_items=[])

    # Run analyze_defaults(); note that we have to do identify_desired_objects()
    # first to set things up
    privconf.identify_desired_objects()
    privconf.analyze_defaults()

    expected = [
        privs.Q_REVOKE_DEFAULT.format(ROLES[3], SCHEMAS[0], 'SELECT', 'TABLES', ROLES[0]),
        privs.Q_GRANT_DEFAULT.format(ROLES[1], SCHEMAS[0], 'SELECT', 'TABLES', ROLES[0]),
        privs.Q_GRANT_DEFAULT.format(ROLES[2], SCHEMAS[0], 'SELECT', 'TABLES', ROLES[0]),
    ]
    assert set(expected) == set(privconf.sql_to_run)


def test_analyze_nondefaults(mockdbcontext):
    """
    Test that:
        - schema0.* is expanded out and all are granted
        - an existing and desired grant is skipped (schema0.table1)
        - a desired but non-existent grant is made (schema0.table0 and schema1.table2)
        - an existing but undesired grant is revoked (schema1.table3)

    Setup:
        - schema0.table0 (owned by role2) -          DESIRED  --> GRANT
        - schema0.table1 (owned by role3) - GRANTED  DESIRED
        - schema1.table2 (owned by role2) -          DESIRED  --> GRANT
        - schema1.table3 (owned by role3) - GRANTED           --> REVOKE
    """
    mockdbcontext.get_role_current_nondefaults = lambda x, y, z: set([
        (ObjectName(SCHEMAS[0], TABLES[1]), 'SELECT'),
        (ObjectName(SCHEMAS[1], TABLES[3]), 'SELECT'),
    ])
    mockdbcontext.get_all_object_attributes = lambda: {
        'schemas': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0]): {'owner': ROLES[1], 'is_dependent': False}
            },
            SCHEMAS[1]: {
                ObjectName(SCHEMAS[1]): {'owner': ROLES[1], 'is_dependent': False}
            },
        },
        'tables': {
            SCHEMAS[0]: {
                ObjectName(SCHEMAS[0], TABLES[0]): {'owner': ROLES[2], 'is_dependent': False},
                ObjectName(SCHEMAS[0], TABLES[1]): {'owner': ROLES[3], 'is_dependent': False},
            },
            SCHEMAS[1]: {
                ObjectName(SCHEMAS[1], TABLES[2]): {'owner': ROLES[2], 'is_dependent': False},
                ObjectName(SCHEMAS[1], TABLES[3]): {'owner': ROLES[3], 'is_dependent': False},
            },
        }
    }
    desired_items = [
        ObjectName(SCHEMAS[0], '*'),
        ObjectName(SCHEMAS[1], TABLES[2]),
    ]
    dummy_schema_writers = defaultdict(set)

    privconf = privs.PrivilegeAnalyzer(rolename=ROLES[0], access='read', object_kind='tables',
                                       desired_items=desired_items, schema_writers=dummy_schema_writers,
                                       personal_schemas=DUMMY, dbcontext=mockdbcontext, excepted_items=[])

    expected = set([
        # Grant for schema0.table0
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', quoted_object(SCHEMAS[0], TABLES[0]), ROLES[0]),

        # Grant for schema1.table2
        privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', quoted_object(SCHEMAS[1], TABLES[2]), ROLES[0]),

        # Revoke for schema1.table3
        privs.Q_REVOKE_NONDEFAULT.format('SELECT', 'TABLE', quoted_object(SCHEMAS[1], TABLES[3]), ROLES[0]),
    ])

    # Run analyze_nondefaults(); note that we have to do identify_desired_objects()
    # first to set things up
    privconf.identify_desired_objects()
    privconf.analyze_nondefaults()

    actual = privconf.sql_to_run
    assert expected.difference(actual) == set()


@pytest.mark.parametrize('group, expected', [
    ('roleD', set(['roleB', 'roleA'])),
    ('roleC', set(['roleA'])),
    ('roleB', set(['roleA'])),
    ('roleA', set()),
])
def test_get_members(group, expected):
    spec = {
        'roleA': {
            'member_of': ['roleB', 'roleC'],
        },
        'roleB': {
            'member_of': ['roleD'],
        },
        'roleC': {},
        'roleD': {},
    }
    actual = privs.get_members(group, spec)
    assert actual == expected


def test_determine_personal_schemas():
    spec = {
        'roleA': {'has_personal_schema': True},
        'roleB': {'has_personal_schema': 'yes'},
        'roleC': {'has_personal_schema': 'false'},
        'roleD': {'has_personal_schema': False},
        'roleE': {},
        'roleF': None,
    }
    expected = set([ObjectName('roleA'), ObjectName('roleB')])
    actual = privs.determine_personal_schemas(spec)
    assert actual == expected


def test_determine_schema_owners():
    spec = {
        'roleA': {
            'has_personal_schema': True,
            'owns': {
                'schemas': [ObjectName('schema1'), ObjectName('schema2')],
            },
        },
        'roleB': {'has_personal_schema': 'yes'},
        'roleC': {
            'has_personal_schema': 'false',
            'owns': {
                'schemas': [ObjectName('schema3')],
            },
        },
        'roleD': {'has_personal_schema': False},
        'roleE': {},
        'roleF': None,
    }
    expected = {
        ObjectName('roleA'): 'roleA',
        ObjectName('roleB'): 'roleB',
        ObjectName('schema1'): 'roleA',
        ObjectName('schema2'): 'roleA',
        ObjectName('schema3'): 'roleC',
    }
    actual = privs.determine_schema_owners(spec)
    assert actual == expected


def test_determine_superusers():
    spec = {
        'roleA': {'is_superuser': True},
        'roleB': {'is_superuser': 'yes'},
        'roleC': {'is_superuser': 'false'},
        'roleD': {'is_superuser': False},
        'roleE': {},
        'roleF': None,
    }
    expected = set(['roleA', 'roleB'])
    actual = privs.determine_superusers(spec)
    assert actual == expected


def test_determine_schema_writers():
    spec = {
        'roleA': {
            'has_personal_schema': True,
            'is_superuser': 'false',
            'owns': {
                'schemas': [ObjectName('schema1'), ObjectName('schema2')],
            },
        },
        'roleB': {
            'has_personal_schema': 'yes',
            'privileges': {
                'schemas': {
                    'write': [ObjectName('personal_schemas'), ObjectName('schema3')],
                },
            },
        },
        'roleC': {
            'has_personal_schema': 'false',
            'owns': {
                'schemas': [ObjectName('schema3')],
            },
        },
        'roleD': {'has_personal_schema': False},
        'roleE': {},
        'roleF': None,
        'roleG': {'is_superuser': True},
        'roleH': {'is_superuser': 'true'},
    }
    expected = {
        ObjectName('roleA'): set(['roleA', 'roleG', 'roleH', 'roleB']),
        ObjectName('roleB'): set(['roleB', 'roleG', 'roleH']),
        ObjectName('schema1'): set(['roleA', 'roleG', 'roleH']),
        ObjectName('schema2'): set(['roleA', 'roleG', 'roleH']),
        ObjectName('schema3'): set(['roleC', 'roleG', 'roleH', 'roleB']),
    }
    actual = privs.determine_schema_writers(spec)
    assert actual == expected
