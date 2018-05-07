import os

import pytest
import yaml

from pgbedrock import spec_inspector
from pgbedrock.context import ObjectAttributes


@pytest.fixture
def set_envvar(request):
    """ Set an environment variable. We use a fixture to ensure cleanup if the test fails """
    k, v = request.param
    os.environ[k] = v
    yield
    del os.environ[k]


def test_ensure_no_schema_owned_twice():
    spec_yaml = """
    jfinance:
        owns:
            schemas:
                - finance_documents
    jfauxnance:
        owns:
            schemas:
                - finance_documents
    """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.ensure_no_schema_owned_twice(spec)
    expected = spec_inspector.MULTIPLE_SCHEMA_OWNER_ERR_MSG.format('finance_documents',
                                                                   'jfauxnance, jfinance')
    assert [expected] == errors


def test_ensure_no_schema_owned_twice_with_personal_schemas():
    spec_yaml = """
    jfinance:
        has_personal_schema: yes
        owns:
            schemas:
                - finance_documents
    jfauxnance:
        owns:
            schemas:
                - jfinance
    """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.ensure_no_schema_owned_twice(spec)
    expected = spec_inspector.MULTIPLE_SCHEMA_OWNER_ERR_MSG.format('jfinance',
                                                                   'jfauxnance, jfinance')
    assert [expected] == errors


def test_ensure_no_object_owned_twice(mockdbcontext):
    mockdbcontext.get_all_object_attributes = lambda: {}

    spec_yaml = """
    # No config
    foo:

    # Config but no 'owns'
    bar:
        has_personal_schema: True

    # Has 'owns' but not for objkind
    baz:
        owns:
            schemas:
                - schema0

    role0:
        owns:
            tables:
                - schema0.table0
                - schema1.table1

    role1:
        owns:
            tables:
                - schema1.table1
                - schema1.table2
    """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.ensure_no_object_owned_twice(spec, mockdbcontext, 'tables')
    expected = spec_inspector.MULTIPLE_OBJKIND_OWNER_ERR_MSG.format('Table', 'schema1.table1',
                                                                    'role0, role1')
    assert [expected] == errors


def test_ensure_no_object_owned_twice_schema_expansion_works(mockdbcontext):
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            'schema1': {
                'schema1.table1': {'owner': 'owner1', 'is_dependent': False},
                'schema1.table2': {'owner': 'owner2', 'is_dependent': False},
                'schema1.table3': {'owner': 'owner3', 'is_dependent': False},
            },
        },
    }
    spec_yaml = """
    role0:
        owns:
            tables:
                - schema0.table0
                - schema1.*

    role1:
        owns:
            tables:
                - schema1.table1
                - schema1.table3
    """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.ensure_no_object_owned_twice(spec, mockdbcontext, 'tables')
    expected = set([
        spec_inspector.MULTIPLE_OBJKIND_OWNER_ERR_MSG.format('Table', 'schema1.table1', 'role0, role1'),
        spec_inspector.MULTIPLE_OBJKIND_OWNER_ERR_MSG.format('Table', 'schema1.table3', 'role0, role1')
    ])
    assert set(errors) == expected


def test_ensure_no_missing_objects_missing_in_db(mockdbcontext):
    mockdbcontext.get_all_raw_object_attributes = lambda: {
        ObjectAttributes('tables', 'schema0', 'schema0.table1', 'owner1', False),
        ObjectAttributes('tables', 'schema0', 'schema0.table3', 'owner3', False),
    }
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            'schema0': {
                'schema0.table1': {'owner': 'owner1', 'is_dependent': False},
                'schema0.table3': {'owner': 'owner3', 'is_dependent': False},
            },
        },
    }
    spec_yaml = """
    role0:
        owns:
            tables:
                - schema0.table1
                - schema0.table2
                - schema0.table3
                - schema0.table4
    """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.ensure_no_missing_objects(spec, mockdbcontext, 'tables')
    expected = spec_inspector.UNKNOWN_OBJECTS_MSG.format(objkind='tables',
                                                         unknown_objects='schema0.table2, schema0.table4')
    assert errors == [expected]


def test_ensure_no_missing_objects_missing_in_spec(mockdbcontext):
    mockdbcontext.get_all_raw_object_attributes = lambda: {
        ObjectAttributes('tables', 'schema0', 'schema0.table1', 'owner1', False),
        ObjectAttributes('tables', 'schema0', 'schema0.table2', 'owner1', False),
        ObjectAttributes('tables', 'schema0', 'schema0.table3', 'owner3', False),
        ObjectAttributes('tables', 'schema0', 'schema0.table4', 'owner3', False),
        # This should be skipped as it is dependent
        ObjectAttributes('tables', 'schema0', 'schema0.table5', 'owner3', True),
    }
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            'schema0': {
                'schema0.table1': {'owner': 'owner1', 'is_dependent': False},
                'schema0.table2': {'owner': 'owner1', 'is_dependent': False},
                'schema0.table3': {'owner': 'owner3', 'is_dependent': False},
                'schema0.table4': {'owner': 'owner3', 'is_dependent': False},
                'schema0.table5': {'owner': 'owner3', 'is_dependent': True},
            },
        },
    }
    spec_yaml = """
    role0:
        owns:
            tables:
                - schema0.table1
                - schema0.table3
    """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.ensure_no_missing_objects(spec, mockdbcontext, 'tables')
    expected = spec_inspector.UNOWNED_OBJECTS_MSG.format(objkind='tables',
                                                         unowned_objects='schema0.table2, schema0.table4')
    assert errors == [expected]


def test_ensure_no_missing_objects_schema_expansion_works(mockdbcontext):
    mockdbcontext.get_all_raw_object_attributes = lambda: {
        ObjectAttributes('tables', 'schema0', 'schema0.table1', 'owner1', False),
        ObjectAttributes('tables', 'schema0', 'schema0.table2', 'owner3', False),
    }
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            'schema0': {
                'schema0.table1': {'owner': 'owner1', 'is_dependent': False},
                'schema0.table2': {'owner': 'owner2', 'is_dependent': False},
            },
        },
    }
    spec_yaml = """
    role0:
        owns:
            tables:
                - schema0.*
    """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.ensure_no_missing_objects(spec, mockdbcontext, 'tables')
    assert errors == []


def test_ensure_no_dependent_object_is_owned(mockdbcontext):
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            'schema0': {
                'schema0.table1': {'owner': 'owner1', 'is_dependent': False},
                'schema0.table2': {'owner': 'owner2', 'is_dependent': True},
                'schema0.table3': {'owner': 'owner2', 'is_dependent': True},
            },
        },
    }
    spec_yaml = """
    role0:
        owns:
            tables:
                - schema0.table1
                - schema0.table2
                - schema0.table3
    """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.ensure_no_dependent_object_is_owned(spec, mockdbcontext, 'tables')
    expected = spec_inspector.DEPENDENT_OBJECTS_MSG.format(objkind='tables',
                                                           dep_objs='schema0.table2, schema0.table3')
    assert errors == [expected]


def test_ensure_no_dependent_object_is_owned_schema_expansion_skips_deps(mockdbcontext):
    mockdbcontext.get_all_object_attributes = lambda: {
        'tables': {
            'schema0': {
                'schema0.table1': {'owner': 'owner1', 'is_dependent': False},
                'schema0.table2': {'owner': 'owner2', 'is_dependent': True},
                'schema0.table3': {'owner': 'owner2', 'is_dependent': True},
            },
        },
    }
    spec_yaml = """
    role0:
        owns:
            tables:
                - schema0.*
    """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.ensure_no_dependent_object_is_owned(spec, mockdbcontext, 'tables')
    assert errors == []


def test_verify_spec_fails_object_referenced_read_write():
    spec_yaml = """
    margerie:
        can_login: true
        privileges:
            {}:
                read:
                    - big_bad
                write:
                    - big_bad
    danil:
        can_login: true
        privileges:
            sequences:
                read:
                    - hoop
                write:
                    - grok
    """

    privilege_types = ('schemas', 'sequences', 'tables')
    for t in privilege_types:
        spec = yaml.load(spec_yaml.format(t))
        errors = spec_inspector.ensure_no_redundant_privileges(spec)
        err_string = "margerie: {'%s': ['big_bad']}" % t
        expected = spec_inspector.OBJECT_REF_READ_WRITE_ERR.format(err_string)
        assert [expected] == errors


def test_verify_spec_fails_role_defined_multiple_times(tmpdir):
    spec_path = tmpdir.join('spec.yml')
    spec_path.write("""
    jfinance:
        owns:
            schemas:
                - finance_documents
    jfinance:
        owns:
            schemas:
                - even_more_finance_documents
    patty:
        owns:
            schemas:
                - tupperwear
    """)
    rendered_template = spec_inspector.render_template(spec_path.strpath)
    errors = spec_inspector.ensure_no_duplicate_roles(rendered_template)
    expected = spec_inspector.DUPLICATE_ROLE_DEFINITIONS_ERR_MSG.format('jfinance')
    assert [expected] == errors


def test_verify_spec_fails():
    """ We could check more functionality, but at that point we'd just be testing cerberus. This
    test is just to verify that a failure will happen and will be presented as we'd expect """
    spec_yaml = """
        fred:
            attribute:
                - flub
        """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.ensure_valid_schema(spec)
    expected = spec_inspector.VALIDATION_ERR_MSG.format('fred', 'attribute', 'unknown field')
    assert expected == errors[0]


def test_verify_spec_succeeds():
    spec_yaml = """
        fred:
            attributes:
                - flub

        mark:
        """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.ensure_valid_schema(spec)
    assert len(errors) == 0


def test_render_template(tmpdir):
    spec_path = tmpdir.join('spec.yml')
    spec_path.write("""
        fred:
          can_login: yes

        my_group:
          can_login: no

        admin:
          can_login: yes
          is_superuser: yes
          options:
              - CREATEDB
              - CREATEROLE
              - REPLICATION

        service1:
          can_login: yes
          schemas:
              - service1_schema
    """)
    spec = spec_inspector.render_template(spec_path.strpath)
    spec = yaml.load(spec)

    assert len(spec) == 4
    assert set(spec.keys()) == {'admin', 'my_group', 'service1', 'fred'}


@pytest.mark.parametrize('set_envvar', [('FRED_PASSWORD', 'a_password')], indirect=True)
def test_load_spec_with_templated_variables(tmpdir, set_envvar):
    spec_path = tmpdir.join('spec.yml')
    spec_path.write("""
        fred:
          can_login: yes
          options:
            - PASSWORD: "{{ env['FRED_PASSWORD'] }}"
    """)
    spec = spec_inspector.render_template(spec_path.strpath)
    spec = yaml.load(spec)

    password_option = spec['fred']['options'][0]
    assert password_option['PASSWORD'] == 'a_password'


def test_load_spec_fails_missing_templated_envvars(capsys, tmpdir):
    envvar_name = 'MISSING_ENVVAR'
    assert envvar_name not in os.environ

    spec = """
        fred:
          can_login: yes
          options:
            - PASSWORD: "{{ env['%s'] }}"
    """ % envvar_name
    spec_path = tmpdir.join('spec.yml')
    spec_path.write(spec)

    with pytest.raises(SystemExit):
        spec_inspector.render_template(spec_path.strpath)

    out, err = capsys.readouterr()
    expected = spec_inspector.MISSING_ENVVAR_MSG.format('')
    assert expected in out
    assert envvar_name in out


def test_load_spec_fails_file_not_found(capsys):
    filename = 'non_existent.yml'
    dirname = os.path.dirname(__file__)
    path = os.path.join(dirname, filename)

    with pytest.raises(SystemExit):
        spec_inspector.render_template(path)

    out, _ = capsys.readouterr()
    assert spec_inspector.FILE_OPEN_ERROR_MSG.format(path, '') in out


def test_ensure_no_undocumented_roles(mockdbcontext):
    mockdbcontext.get_all_role_attributes = lambda: {'foo': {}, 'bar': {}, 'baz': {}}
    spec = {'baz': {}}
    error_messages = spec_inspector.ensure_no_undocumented_roles(spec, mockdbcontext)
    expected = spec_inspector.UNDOCUMENTED_ROLES_MSG.format('"bar", "foo"')
    assert error_messages == [expected]


def test_ensure_no_unowned_schemas(mockdbcontext):
    mockdbcontext.get_all_schemas_and_owners = lambda: {'foo': {}, 'bar': {}, 'baz': {}}
    spec = {
        'qux': {
            'owns': {
                'schemas': ['baz'],
            },
        },
    }
    error_messages = spec_inspector.ensure_no_unowned_schemas(spec, mockdbcontext)
    expected = spec_inspector.UNOWNED_SCHEMAS_MSG.format('"bar", "foo"')
    assert error_messages == [expected]


def test_get_spec_schemas():
    spec = {
        'role0': {
             'has_personal_schema': True,
             'owns': {
                 'schemas': ['schemas0']
             },
        },
        'role1': {
             'owns': {
                 'schemas': ['schemas1']
             },
        }
    }

    assert spec_inspector.get_spec_schemas(spec) == set(['role0', 'schemas0', 'schemas1'])
