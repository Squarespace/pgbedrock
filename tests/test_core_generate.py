import copy
import datetime as dt
import textwrap

import psycopg2
import pytest

from conftest import quoted_object, run_setup_sql
from pgbedrock import attributes as attr
from pgbedrock.context import DatabaseContext
from pgbedrock import core_generate
from pgbedrock import ownerships as own
from pgbedrock import privileges as privs


Q_CREATE_TABLE = 'SET ROLE {}; CREATE TABLE {}.{} AS (SELECT 1+1); RESET ROLE;'
Q_CREATE_SEQUENCE = 'SET ROLE {}; CREATE SEQUENCE {}.{}; RESET ROLE;'

VALID_FOREVER_VALUES = (
    None,
    'infinity',
    dt.datetime.max,
    dt.datetime.max.replace(tzinfo=psycopg2.tz.FixedOffsetTimezone(offset=0, name=None)))


def test_add_attributes(mockdbcontext):
    mockdbcontext.get_all_role_attributes = lambda: {
        'foo': {
            'rolcanlogin': True,
            'rolconnlimit': 2,
            'rolinherit': False,
            'rolsuper': False,
        },
        'bar': {
            'rolcanlogin': False,
            'rolpassword': 'supersecret',
            'rolsuper': True,
            'rolvaliduntil': dt.datetime(2018, 6, 5),
        },
    }
    expected = {
        'foo': {
            'can_login': True,
            'attributes': [
                'CONNECTION LIMIT 2',
                'NOINHERIT',
            ],
        },
        'bar': {
            'is_superuser': True,
            'attributes': [
                'PASSWORD "{{ env[\'BAR_PASSWORD\'] }}"',
                "VALID UNTIL '2018-06-05'",
            ],
        },
    }
    spec = {'foo': {}, 'bar': {}}
    actual = core_generate.add_attributes(spec, mockdbcontext)

    # There's no guarantee in what order the list of attributes will be returned,
    # so we have to convert the entries to a set to check equivalence
    assert actual['foo']['can_login'] == expected['foo']['can_login']
    assert set(actual['foo']['attributes']) == set(expected['foo']['attributes'])

    assert actual['bar']['is_superuser'] == expected['bar']['is_superuser']
    assert set(actual['bar']['attributes']) == set(expected['bar']['attributes'])


def test_add_attributes_password_for_rolename_with_dash(mockdbcontext):
    mockdbcontext.get_all_role_attributes = lambda: {
        'foo-bar-baz': {
            'rolpassword': 'supersecret',
            # These are expected to exist for core_generate.add_attributes
            'rolcanlogin': False,
            'rolsuper': False,
        },
    }
    expected = {
        'foo-bar-baz': {
            'attributes': [
                'PASSWORD "{{ env[\'FOO_BAR_BAZ_PASSWORD\'] }}"',
            ],
        },
    }
    spec = {'foo-bar-baz': {}}
    actual = core_generate.add_attributes(spec, mockdbcontext)

    assert actual == expected


def test_add_memberships(mockdbcontext):
    mockdbcontext.get_all_memberships = lambda: [
        ('foo', 'bar'),
        ('foo', 'baz'),
        ('bar', 'baz'),
    ]
    expected = {
        'foo': {
            'member_of': [
                'bar',
                'baz',
            ],
        },
        'bar': {
            'member_of': [
                'baz',
            ],
        },
        'baz': {},
    }
    spec = {'foo': {}, 'bar': {}, 'baz': {}}
    actual = core_generate.add_memberships(spec, mockdbcontext)
    assert actual == expected


def test_add_schema_ownerships(mockdbcontext):
    mockdbcontext.get_all_schemas_and_owners = lambda: {
        # Non-personal schemas
        'schema1': 'owner1',
        'schema2': 'owner1',
        'schema3': 'owner2',

        # Personal schema
        'owner1': 'owner1',

        # Would not show up in get_all_personal_schemas as can_login is False
        'owner2': 'owner2',
    }
    mockdbcontext.get_all_personal_schemas = lambda: set(['owner1'])

    spec = {
        'owner1': {'can_login': True},
        'owner2': {},
    }

    actual = core_generate.add_schema_ownerships(spec, mockdbcontext)

    # There's no guarantee in what order the list of schemas will be returned,
    # so we have to convert the entries to a set to check equivalence
    assert actual['owner1']['can_login'] is True
    assert actual['owner1']['has_personal_schema'] is True
    assert set(actual['owner1']['owns']['schemas']) == set(['schema1', 'schema2'])
    assert 'has_personal_schema' not in actual['owner2']
    assert set(actual['owner2']['owns']['schemas']) == set(['owner2', 'schema3'])


def test_add_nonschema_ownerships(mockdbcontext):
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            'schema1': {
                quoted_object('schema1', 'mytable1'): {'owner': 'owner1', 'is_dependent': False},
                # This entry should be skipped because it is dependent
                quoted_object('schema1', 'mytable2'): {'owner': 'owner2', 'is_dependent': True},
                quoted_object('schema1', 'mytable3'): {'owner': 'owner2', 'is_dependent': False},
            },
            'schema2': {
                # These all have the same owner, so it will become schema2.*
                quoted_object('schema2', 'mytable4'): {'owner': 'owner1', 'is_dependent': False},
                quoted_object('schema2', 'mytable5'): {'owner': 'owner1', 'is_dependent': False},
                quoted_object('schema2', 'mytable6'): {'owner': 'owner1', 'is_dependent': False},
            },
            'owner3': {
                # This entry should be skipped because it is in a personal schema
                quoted_object('owner3', 'mytable7'): {'owner': 'owner2', 'is_dependent': False},
            },
        },
        'sequences': {},
    }
    mockdbcontext.get_all_personal_schemas = lambda: set(['owner3', 'owner5'])

    spec = {
        'owner1': {
            'owns': {
                'schemas': ['schema1']
            }
        },
        'owner2': {},
        'owner3': {},
        'owner4': {},
    }

    actual = core_generate.add_nonschema_ownerships(spec, mockdbcontext, 'tables')
    assert actual['owner1']['owns']['schemas'] == ['schema1']
    assert set(actual['owner1']['owns']['tables']) == set([
        quoted_object('schema1', 'mytable1'),
        'schema2.*',
    ])
    assert actual['owner2']['owns']['tables'] == [quoted_object('schema1', 'mytable3')]
    assert actual['owner3'] == {}
    assert actual['owner4'] == {}


@pytest.mark.parametrize('objkind', [('tables'), ('sequences')])
def test_add_nonschema_ownerships_empty_objkinds(mockdbcontext, objkind):
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            'schema1': {},
        },
        'sequences': {},
    }
    mockdbcontext.get_all_personal_schemas = lambda: set(['owner4', 'owner5'])

    spec = {
        'owner1': {
            'owns': {
                'schemas': ['schema1']
            }
        },
        'owner2': {},
        'owner3': {},
    }

    actual = core_generate.add_nonschema_ownerships(spec, mockdbcontext, objkind)
    # Make sure nothing changed
    assert actual == spec


def test_add_ownerships(mockdbcontext):
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            'schema1': {
                quoted_object('schema1', 'mytable1'): {'owner': 'owner1', 'is_dependent': False},
                # This entry should be skipped because it is dependent
                quoted_object('schema1', 'mytable2'): {'owner': 'owner2', 'is_dependent': True},
                quoted_object('schema1', 'mytable3'): {'owner': 'owner2', 'is_dependent': False},
            },
            'schema2': {
                # These all have the same owner, so it will become schema2.*
                quoted_object('schema2', 'mytable4'): {'owner': 'owner1', 'is_dependent': False},
                quoted_object('schema2', 'mytable5'): {'owner': 'owner1', 'is_dependent': False},
                quoted_object('schema2', 'mytable6'): {'owner': 'owner1', 'is_dependent': False},
            },
            'owner3': {
                # This entry should be skipped because it is in a personal schema
                quoted_object('owner3', 'mytable7'): {'owner': 'owner2', 'is_dependent': False},
            },
        },
        'sequences': {
            'schema1': {
                quoted_object('schema1', 'myseq1'): {'owner': 'owner2', 'is_dependent': False},
                quoted_object('schema1', 'myseq2'): {'owner': 'owner3', 'is_dependent': True},
            },
            'schema2': {
                quoted_object('schema2', 'myseq3'): {'owner': 'owner1', 'is_dependent': False},
                quoted_object('schema2', 'myseq4'): {'owner': 'owner2', 'is_dependent': False},
            },
        },
    }
    mockdbcontext.get_all_schemas_and_owners = lambda: {
        # Non-personal schemas
        'schema1': 'owner1',
        'schema2': 'owner1',

        # Personal schema
        'owner3': 'owner3',
    }
    mockdbcontext.get_all_personal_schemas = lambda: set(['owner3'])

    spec = {
        'owner1': {},
        'owner2': {},
        'owner3': {},
    }

    actual = core_generate.add_ownerships(spec, mockdbcontext)
    # Schema ownership assertions
    assert set(actual['owner1']['owns']['schemas']) == set(['schema1', 'schema2'])
    assert actual['owner3'] == {'has_personal_schema': True}

    # Table ownership assertions
    assert set(actual['owner1']['owns']['tables']) == set([
        quoted_object('schema1', 'mytable1'),
        'schema2.*',
    ])
    assert actual['owner2']['owns']['tables'] == [quoted_object('schema1', 'mytable3')]

    # Sequence ownership assertions
    assert actual['owner1']['owns']['sequences'] == [quoted_object('schema2', 'myseq3')]
    assert set(actual['owner2']['owns']['sequences']) == set([
        'schema1.*',
        quoted_object('schema2', 'myseq4')
    ])


@run_setup_sql([
    attr.Q_CREATE_ROLE.format('role0'),

    # role1's personal schema has an object in it
    attr.Q_CREATE_ROLE.format('role1'),
    attr.Q_ALTER_ROLE.format('role1', 'LOGIN'),
    own.Q_CREATE_SCHEMA.format('role1', 'role1'),
    Q_CREATE_TABLE.format('role1', 'role1', 'table0'),

    # role2's personal schema has no objects
    attr.Q_CREATE_ROLE.format('role2'),
    attr.Q_ALTER_ROLE.format('role2', 'LOGIN'),
    own.Q_CREATE_SCHEMA.format('role2', 'role2'),

    # role3's personal schema has several objects in it
    attr.Q_CREATE_ROLE.format('role3'),
    attr.Q_ALTER_ROLE.format('role3', 'LOGIN'),
    own.Q_CREATE_SCHEMA.format('role3', 'role3'),
    Q_CREATE_TABLE.format('role3', 'role3', 'table1'),
    Q_CREATE_TABLE.format('role3', 'role3', 'table2'),
])
@pytest.mark.parametrize('objects, expected', [
    (set(['role1.*', 'role3.*']), set(['personal_schemas.*'])),
    (set(['role1.*', 'role3.table1']), set(['role1.*', 'role3.table1'])),
])
def test_collapse_personal_schemas(cursor, objects, expected):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actual = core_generate.collapse_personal_schemas(role='role0', objects=objects,
                                                     objkind='tables', dbcontext=dbcontext)
    assert actual == expected


@run_setup_sql([
    attr.Q_CREATE_ROLE.format('role0'),

    # role1's personal schema has an object in it
    attr.Q_CREATE_ROLE.format('role1'),
    attr.Q_ALTER_ROLE.format('role1', 'LOGIN'),
    own.Q_CREATE_SCHEMA.format('role1', 'role1'),
    Q_CREATE_TABLE.format('role1', 'role1', 'table0'),

    # role2's schema is also called role2 and it does have objects, but role2
    # can't log in so this should not count as a personal schema
    attr.Q_CREATE_ROLE.format('role2'),
    own.Q_CREATE_SCHEMA.format('role2', 'role2'),

    # role3's personal schema has several objects in it
    attr.Q_CREATE_ROLE.format('role3'),
    attr.Q_ALTER_ROLE.format('role3', 'LOGIN'),
    own.Q_CREATE_SCHEMA.format('role3', 'role3'),
    Q_CREATE_TABLE.format('role3', 'role3', 'table1'),
    Q_CREATE_TABLE.format('role3', 'role3', 'table2'),
])
@pytest.mark.parametrize('objects, expected', [
    (set(['role1.*', 'role3.*']), set(['personal_schemas.*'])),
    (set(['role1.*', 'role2.*', 'role3.*']), set(['personal_schemas.*', 'role2.*'])),
])
def test_collapse_personal_schemas_only_logginable_roles(cursor, objects, expected):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actual = core_generate.collapse_personal_schemas(role='role0', objects=objects,
                                                     objkind='tables', dbcontext=dbcontext)
    assert actual == expected


def test_collapse_personal_schemas_no_personal_schemas_exist(cursor):
    objects = set(['role1.*', 'role2.foo', 'role3.bar'])
    dbcontext = DatabaseContext(cursor, verbose=True)
    actual = core_generate.collapse_personal_schemas(role='role0', objects=objects,
                                                     objkind='tables', dbcontext=dbcontext)
    assert actual == objects


@run_setup_sql([
    attr.Q_CREATE_ROLE.format('role0'),

    # role1's personal schema has an object in it
    attr.Q_CREATE_ROLE.format('role1'),
    attr.Q_ALTER_ROLE.format('role1', 'LOGIN'),
    own.Q_CREATE_SCHEMA.format('role1', 'role1'),
    Q_CREATE_TABLE.format('role1', 'role1', 'table0'),

    # role2's personal schema has no objects. We could grant a default privilege here but all
    # that matters is that our input to the collapse_personal_schemas() function includes 'role2.*'
    attr.Q_CREATE_ROLE.format('role2'),
    attr.Q_ALTER_ROLE.format('role2', 'LOGIN'),
    own.Q_CREATE_SCHEMA.format('role2', 'role2'),
])
def test_collapse_personal_schemas_empty_schema_with_default_priv(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    objects = set(['role1.*', 'role2.*'])
    actual = core_generate.collapse_personal_schemas(role='role0', objects=objects,
                                                     objkind='tables', dbcontext=dbcontext)
    expected = set(['personal_schemas.*'])
    assert actual == expected


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create schemas owned by the other role (role1)
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),
    own.Q_CREATE_SCHEMA.format('schema1', 'role1'),
    own.Q_CREATE_SCHEMA.format('schema2', 'role1'),

    # Create one schema owned by role0
    own.Q_CREATE_SCHEMA.format('schema3', 'role0'),

    # Grant various read access to role0 (including to the schema it owns)
    privs.Q_GRANT_NONDEFAULT.format('USAGE', 'SCHEMA', 'schema0', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('USAGE', 'SCHEMA', 'schema1', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('USAGE', 'SCHEMA', 'schema2', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('USAGE', 'SCHEMA', 'schema3', 'role0'),

    # Grant various read access to role0 (including to the schema it owns)
    privs.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', 'schema2', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', 'schema3', 'role0'),
])
def test_determine_schema_privileges_both_read_and_write_no_personal_schemas(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actual = core_generate.determine_schema_privileges('role0', dbcontext)
    expected = {
        'write': ['schema2', 'schema3'],
        'read': ['schema0', 'schema1'],
    }
    assert actual == expected


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
])
def test_determine_schema_privileges_nothing_returns(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actual = core_generate.determine_schema_privileges('role0', dbcontext)
    assert actual == {}


# verify personal schemas works, verify only read
@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema owned by the other role (role1) and grant USAGE on it to role0
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),
    privs.Q_GRANT_NONDEFAULT.format('USAGE', 'SCHEMA', 'schema0', 'role0'),

])
def test_determine_schema_privileges_only_read_exists(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actual = core_generate.determine_schema_privileges('role0', dbcontext)
    expected = {
        'read': ['schema0'],
    }
    assert actual == expected


# verify personal schemas works, verify only read
@run_setup_sql([
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),
    attr.Q_CREATE_ROLE.format('role2'),
    attr.Q_ALTER_ROLE.format('role0', 'LOGIN'),
    attr.Q_ALTER_ROLE.format('role1', 'LOGIN'),
    attr.Q_ALTER_ROLE.format('role2', 'LOGIN'),

    # Create three personal schemas
    own.Q_CREATE_SCHEMA.format('role0', 'role0'),
    own.Q_CREATE_SCHEMA.format('role1', 'role1'),
    own.Q_CREATE_SCHEMA.format('role2', 'role2'),
    privs.Q_GRANT_NONDEFAULT.format('USAGE', 'SCHEMA', 'role1', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('USAGE', 'SCHEMA', 'role2', 'role0'),

    # Create two non-personal schemas
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),
    own.Q_CREATE_SCHEMA.format('schema1', 'role2'),

    privs.Q_GRANT_NONDEFAULT.format('USAGE', 'SCHEMA', 'schema0', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', 'schema1', 'role0'),
])
def test_determine_schema_privileges_personal_schemas(cursor):
    """
    Setup: (schema - privilege - expected state)
        role0 - owns - does not need granting as this is a personal schema owned by this user
        role1 - read - should be converted to 'personal_schemas'
        role2 - read - should be converted to 'personal_schemas'
        schema0 - read - should be in 'read'
        schema1 - write - should be in 'write'
    """
    dbcontext = DatabaseContext(cursor, verbose=True)
    actual = core_generate.determine_schema_privileges('role0', dbcontext)
    expected = {
        'write': ['schema1'],
        'read': ['personal_schemas', 'schema0'],
    }
    assert actual == expected


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema owned by the other role (role1) and grant CREATE on it to role0
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),
    privs.Q_GRANT_NONDEFAULT.format('CREATE', 'SCHEMA', 'schema0', 'role0'),

    # Create one schema owned by role0
    own.Q_CREATE_SCHEMA.format('schema1', 'role0'),

])
def test_determine_schema_privileges_only_write_exists(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actual = core_generate.determine_schema_privileges('role0', dbcontext)
    expected = {
        'write': ['schema0', 'schema1'],
    }
    assert actual == expected


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a personal schema for role0
    own.Q_CREATE_SCHEMA.format('role0', 'role0'),
])
def test_determine_schema_privileges_has_personal_schema(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actual = core_generate.determine_schema_privileges('role0', dbcontext)
    assert actual == {}


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Grant a default privilege
    privs.Q_GRANT_DEFAULT.format('role1', 'schema0', 'SELECT', 'TABLES', 'role0'),
])
def test_determine_nonschema_privileges_for_schema_no_objects_with_default_priv(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set()
    assert actr == set(['schema0.*'])


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),
])
def test_determine_nonschema_privileges_for_schema_no_objects(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set()
    assert actr == set()


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Create a table so there is at least one object in the schema
    Q_CREATE_TABLE.format('role1', 'schema0', 'table0'),

    # Grant a write default privilege
    privs.Q_GRANT_DEFAULT.format('role1', 'schema0', 'UPDATE', 'TABLES', 'role0'),
])
def test_determine_nonschema_privileges_for_schema_default_write(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set(['schema0.*'])
    assert actr == set()


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Create two tables and grant a different write-level privilege to each
    Q_CREATE_TABLE.format('role1', 'schema0', 'table0'),
    Q_CREATE_TABLE.format('role1', 'schema0', 'table1'),
    privs.Q_GRANT_NONDEFAULT.format('INSERT', 'TABLE', 'schema0.table0', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('DELETE', 'TABLE', 'schema0.table1', 'role0'),
])
def test_determine_nonschema_privileges_for_schema_has_all_writes(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set(['schema0.*'])
    assert actr == set()


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Create two tables and grant a write-level privilege to one of them (but not both)
    Q_CREATE_TABLE.format('role1', 'schema0', 'table0'),
    Q_CREATE_TABLE.format('role1', 'schema0', 'table1'),
    privs.Q_GRANT_NONDEFAULT.format('INSERT', 'TABLE', 'schema0.table0', 'role0'),

    # Grant a default read privilege
    privs.Q_GRANT_DEFAULT.format('role1', 'schema0', 'SELECT', 'TABLES', 'role0'),
])
def test_determine_nonschema_privileges_for_schema_some_write_default_read(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set(['schema0."table0"'])
    assert actr == set(['schema0.*'])


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Create two tables and grant read-level privileges to both of them
    Q_CREATE_TABLE.format('role1', 'schema0', 'table0'),
    Q_CREATE_TABLE.format('role1', 'schema0', 'table1'),
    privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', 'schema0.table0', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', 'schema0.table1', 'role0'),
])
def test_determine_nonschema_privileges_for_schema_no_writes_all_reads(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set()
    assert actr == set(['schema0.*'])


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Create 2 tables and grant a read to one and a write to the other
    Q_CREATE_TABLE.format('role1', 'schema0', 'table0'),
    Q_CREATE_TABLE.format('role1', 'schema0', 'table1'),
    privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', 'schema0.table0', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('INSERT', 'TABLE', 'schema0.table1', 'role0'),

    # Create a table and grant it both a read and a write to verify it only shows up as a write
    Q_CREATE_TABLE.format('role1', 'schema0', 'table2'),
    privs.Q_GRANT_NONDEFAULT.format('UPDATE', 'TABLE', 'schema0.table2', 'role0'),
])
def test_determine_nonschema_privileges_for_schema_some_writes_some_reads(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set(['schema0."table1"', 'schema0."table2"'])
    assert actr == set(['schema0."table0"'])


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Create 3 tables and grant a write on all of them
    Q_CREATE_TABLE.format('role1', 'schema0', 'table0'),
    Q_CREATE_TABLE.format('role1', 'schema0', 'table1'),
    Q_CREATE_TABLE.format('role1', 'schema0', 'table2'),
    privs.Q_GRANT_NONDEFAULT.format('DELETE', 'TABLE', 'schema0.table0', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('INSERT', 'TABLE', 'schema0.table1', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('UPDATE', 'TABLE', 'schema0.table2', 'role0'),
])
def test_determine_nonschema_privileges_for_schema_all_writes(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set(['schema0.*'])
    assert actr == set()


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Grant a default write
    privs.Q_GRANT_DEFAULT.format('role1', 'schema0', 'INSERT', 'TABLES', 'role0'),

    # Create 2 tables and grant a read on one of them
    Q_CREATE_TABLE.format('role1', 'schema0', 'table0'),
    Q_CREATE_TABLE.format('role1', 'schema0', 'table1'),
    privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', 'schema0.table0', 'role0'),
])
def test_determine_nonschema_privileges_for_schema_default_write_some_reads(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set(['schema0.*'])
    assert actr == set()


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Grant a default write and a default read
    privs.Q_GRANT_DEFAULT.format('role1', 'schema0', 'INSERT', 'TABLES', 'role0'),
    privs.Q_GRANT_DEFAULT.format('role1', 'schema0', 'SELECT', 'TABLES', 'role0'),
])
def test_determine_nonschema_privileges_for_schema_default_write_and_default_read(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set(['schema0.*'])
    assert actr == set()


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Create 2 tables and grant a read on both of them
    Q_CREATE_TABLE.format('role1', 'schema0', 'table0'),
    Q_CREATE_TABLE.format('role1', 'schema0', 'table1'),
    privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', 'schema0.table0', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', 'schema0.table1', 'role0'),
])
def test_determine_nonschema_privileges_for_schema_no_write_all_reads(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set()
    assert actr == set(['schema0.*'])


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Create 2 tables and grant a read on both of them
    Q_CREATE_TABLE.format('role1', 'schema0', 'table0'),
    Q_CREATE_TABLE.format('role1', 'schema0', 'table1'),
    privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', 'schema0.table0', 'role0'),
])
def test_determine_nonschema_privileges_for_schema_no_writes_some_reads(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set()
    assert actr == set(['schema0."table0"'])


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),

    # Create 1 object of a different objkind
    Q_CREATE_TABLE.format('role1', 'schema0', 'table0'),
    Q_CREATE_SEQUENCE.format('role1', 'schema0', 'sequence0')
])
def test_determine_nonschema_privileges_for_schema_no_objects_of_objkind(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_nonschema_privileges_for_schema('role0', 'tables',
                                                                         'schema0', dbcontext)
    assert actw == set()
    assert actr == set()


@run_setup_sql([
    # role0 is who we care about; role1 is just another user to own things
    attr.Q_CREATE_ROLE.format('role0'),
    attr.Q_CREATE_ROLE.format('role1'),

    # Create a schema
    own.Q_CREATE_SCHEMA.format('schema0', 'role1'),
    own.Q_CREATE_SCHEMA.format('schema1', 'role1'),

    # Create a role0's personal schema
    own.Q_CREATE_SCHEMA.format('role0', 'role0'),

    # role0 will have write access to all objects in schema0
    Q_CREATE_TABLE.format('role1', 'schema0', 'table1'),
    Q_CREATE_TABLE.format('role1', 'schema0', 'table2'),
    privs.Q_GRANT_NONDEFAULT.format('TRIGGER', 'TABLE', 'schema0.table1', 'role0'),
    privs.Q_GRANT_NONDEFAULT.format('DELETE', 'TABLE', 'schema0.table2', 'role0'),

    # role0 will have read access to a some things in schema1
    Q_CREATE_TABLE.format('role1', 'schema1', 'table3'),
    Q_CREATE_TABLE.format('role1', 'schema1', 'table4'),
    privs.Q_GRANT_NONDEFAULT.format('SELECT', 'TABLE', 'schema1.table3', 'role0'),

    # An object exists in role0's personal schema
    Q_CREATE_TABLE.format('role0', 'role0', 'table0'),
])
def test_determine_all_nonschema_privileges(cursor):
    dbcontext = DatabaseContext(cursor, verbose=True)
    actw, actr = core_generate.determine_all_nonschema_privileges('role0', 'tables', dbcontext)
    assert actw == set(['schema0.*'])
    assert actr == set(['schema1."table3"'])


def test_initialize_spec(mockdbcontext):
    all_role_attributes = {
        'foo': {'whatever': 'can_be_here'},
        'bar': {'or': 'nothing'},
        'baz': {},
    }
    mockdbcontext.get_all_role_attributes = lambda: all_role_attributes
    expected = {role: {} for role in all_role_attributes.keys()}

    spec = core_generate.initialize_spec(mockdbcontext)
    assert spec == expected


def test_nondefault_attributes_as_list():
    nondefaults = {
        'rolbypassrls': True,
        'rolconnlimit': 7,
        'rolinherit': False,
        'rolpassword': 'supersecret',
        'rolvaliduntil': dt.datetime(2018, 6, 5),
    }
    expected = [
        'BYPASSRLS',
        'CONNECTION LIMIT 7',
        'NOINHERIT',
        'PASSWORD "{{ env[\'ROLE1_PASSWORD\'] }}"',
        "VALID UNTIL '2018-06-05'",
    ]
    actual = core_generate.nondefault_attributes_as_list('role1', nondefaults)
    assert set(actual) == set(expected)


@pytest.mark.parametrize('value', VALID_FOREVER_VALUES)
def test_remove_default_attributes_valid_until(value):
    attributes_input = {
        'rolvaliduntil': value,
    }
    actual = core_generate.remove_default_attributes(attributes_input)
    assert actual == {}


def test_remove_default_attributes():
    attributes_input = copy.deepcopy(attr.DEFAULT_ATTRIBUTES)
    nondefaults = {
        'rolcanlogin': True,
        'rolreplication': True,
        'rolconnlimit': 5,
    }
    attributes_input.update(nondefaults)
    actual = core_generate.remove_default_attributes(attributes_input)
    assert actual == nondefaults


def test_output_spec(capsys):
    spec = {
        'roleA': {
            'attributes': [
                'CONNECTION LIMIT 3'
            ]
        },
        'roleB': {},
    }
    expected = textwrap.dedent("""
    roleA:
        attributes:
            - CONNECTION LIMIT 3

    roleB:

    """)

    core_generate.output_spec(spec)
    out, err = capsys.readouterr()
    assert out == expected


@pytest.mark.parametrize("input_, expected", [
    ([3, 1, 5, 2], [1, 2, 3, 5]),
    (8, 8),
    ('some text', 'some text'),
    ({'a': 3, 'b': 'foo', 'c': []}, {'a': 3, 'b': 'foo', 'c': []}),
    ({'a': [0, 6, 1], 'b': {'c': [8, 3, 1]}}, {'a': [0, 1, 6], 'b': {'c': [1, 3, 8]}}),
])
def test_sort_sublists(input_, expected):
    assert core_generate.sort_sublists(input_) == expected
