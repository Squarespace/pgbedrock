import os

import pytest
import yaml

from pgbedrock import spec_inspector


@pytest.fixture
def set_envvar(request):
    """ Set an environment variable. We use a fixture to ensure cleanup if the test fails """
    k, v = request.param
    os.environ[k] = v
    yield
    del os.environ[k]


def test_verify_spec_fails_multiple_roles_own_schema(capsys):
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
    errors = spec_inspector.check_for_multi_schema_owners(spec)
    expected = spec_inspector.MULTIPLE_SCHEMA_OWNER_ERR_MSG.format('finance_documents', 'jfinance, jfauxnance')
    assert [expected] == errors


def test_verify_spec_fails_multiple_roles_own_schema_personal_schema(capsys):
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
    errors = spec_inspector.check_for_multi_schema_owners(spec)
    expected = spec_inspector.MULTIPLE_SCHEMA_OWNER_ERR_MSG.format('jfinance', 'jfinance, jfauxnance')
    assert [expected] == errors


def test_verify_spec_fails_object_referenced_read_write(capsys):
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
        errors = spec_inspector.check_read_write_obj_references(spec)
        err_string = "margerie: {'%s': ['big_bad']}" % t
        expected = spec_inspector.OBJECT_REF_READ_WRITE_ERR.format(err_string)
        assert [expected] == errors


def test_verify_spec_fails_role_defined_multiple_times(tmpdir, capsys):
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
    errors = spec_inspector.detect_multiple_role_definitions(rendered_template)
    expected = spec_inspector.DUPLICATE_ROLE_DEFINITIONS_ERR_MSG.format('jfinance')
    assert [expected] == errors


def test_verify_spec_fails(capsys):
    """ We could check more functionality, but at that point we'd just be testing cerberus. This
    test is just to verify that a failure will happen and will be presented as we'd expect """
    spec_yaml = """
        fred:
            attribute:
                - flub
        """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.verify_schema(spec)
    expected = spec_inspector.VALIDATION_ERR_MSG.format('fred', 'attribute', 'unknown field')
    assert expected == errors[0]


def test_verify_spec_succeeds(capsys):
    spec_yaml = """
        fred:
            attributes:
                - flub

        mark:
        """
    spec = yaml.load(spec_yaml)
    errors = spec_inspector.verify_schema(spec)
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
