import copy
import datetime as dt

import pytest

from conftest import run_setup_sql
from pgbedrock import attributes as attr


ROLE1 = 'charlie'
ROLE2 = 'barney'
ROLE3 = 'wacko'
NON_DEFAULTS_GIVEN = ['CREATEDB', 'CREATEROLE', 'REPLICATION', 'CONNECTION LIMIT 30',
                      'VALID UNTIL 2016-08-04']
NON_DEFAULTS_EXPECTED = {'rolcreatedb': True,
                         'rolcreaterole': True,
                         'rolreplication': True,
                         'rolconnlimit': 30,
                         'rolvaliduntil': dt.date(2016, 8, 4)}
DUMMY = 'foo'


def nondefault_attributes(opts):
    return pytest.mark.parametrize('roleconf', [opts], indirect=True)


@pytest.fixture(scope='function')
def roleconf(request, mockdbcontext):
    # We need this ternary expression in case we were indirectly passwed non-default attributes
    nondefault_attributes = request.param if hasattr(request, 'param') else {}

    # Apply any non-default attributes to what mockdbcontext will return
    role_attributes = copy.deepcopy(attr.DEFAULT_ATTRIBUTES)
    role_attributes.update(nondefault_attributes)
    mockdbcontext.get_role_attributes = lambda x: role_attributes

    roleconf = attr.AttributeAnalyzer(rolename=ROLE1, spec_attributes={}, spec_configs={}, dbcontext=mockdbcontext)
    return roleconf


@run_setup_sql([
    attr.Q_CREATE_ROLE.format(ROLE1),
    ])
def test_analyze_attributes_modifying_objects(capsys, cursor):
    """
    End-to-end test.
    ROLE1 exists and has some non-defaults
    ROLE2 does not exist yet and is a superuser
    ROLE3 does not exist and has the defaults
    """
    attributes = ['BYPASSRLS', 'CREATEDB', 'CREATEROLE', 'INHERIT', 'REPLICATION']
    spec = {
        # Add the existing users so we don't get an UNDOCUMENTED_ROLES failure
        'postgres': {'is_superuser': True, 'attributes': attributes},
        'test_user': {'is_superuser': True, 'attributes': attributes},

        ROLE1: {'can_login': False, 'attributes': NON_DEFAULTS_GIVEN},
        ROLE2: {'is_superuser': True, 'attributes': NON_DEFAULTS_GIVEN},
        ROLE3: {},
    }

    # Generate all of the ALTER ROLE statements for NON_DEFAULTS_GIVEN
    expected = set([])
    for role in (ROLE1, ROLE2):
        for k, v in NON_DEFAULTS_EXPECTED.items():

            if isinstance(v, bool):
                base_keyword = attr.COLUMN_NAME_TO_KEYWORD[k]
                # prepend 'NO' if desired_value is False
                keyword = base_keyword if v is True else ('NO' + base_keyword)
                # prefix = 'NO' if v is False else ''
                # desired = prefix + k
                stmt = attr.Q_ALTER_ROLE_WITH.format(role, keyword)
            elif k == 'rolconnlimit':
                stmt = attr.Q_ALTER_CONN_LIMIT.format(role, v, attr.DEFAULT_ATTRIBUTES[k])
            elif k == 'rolvaliduntil':
                stmt = attr.Q_ALTER_VALID_UNTIL.format(role, v, attr.DEFAULT_ATTRIBUTES[k])

            expected.add(stmt)

    expected.add(attr.Q_CREATE_ROLE.format(ROLE2))
    expected.add(attr.Q_ALTER_ROLE_WITH.format(ROLE2, 'SUPERUSER'))
    expected.add(attr.Q_CREATE_ROLE.format(ROLE3))

    actual, password_changed = attr.analyze_attributes(spec, cursor, verbose=False)
    # Filter out changes for roles that existed before this test
    actual = set([s for s in actual if ('postgres' not in s and 'test_user' not in s)])

    assert actual == expected


def test_analyze_nonexistent_role_with_default_attributes(mockdbcontext):
    mockdbcontext.get_role_attributes = lambda x: dict()
    # Analyze the role with default attributes
    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes={}, spec_configs={}, dbcontext=mockdbcontext)
    roleconf.analyze()

    assert roleconf.sql_to_run == [
        attr.Q_CREATE_ROLE.format(ROLE1)
    ]


def test_analyze_nonexistent_role_with_non_default_attributes(mockdbcontext):
    mockdbcontext.get_role_attributes = lambda x: dict()

    spec_attributes = copy.deepcopy(NON_DEFAULTS_GIVEN)
    spec_attributes.extend(['LOGIN', 'SUPERUSER'])

    # Analyze the role with non-default attributes
    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=spec_attributes,
                                      spec_configs={}, dbcontext=mockdbcontext)
    roleconf.analyze()

    expected = set([
        attr.Q_CREATE_ROLE.format(ROLE1),
        attr.Q_ALTER_ROLE_WITH.format(ROLE1, 'LOGIN'),
        attr.Q_ALTER_ROLE_WITH.format(ROLE1, 'SUPERUSER'),
        attr.Q_ALTER_ROLE_WITH.format(ROLE1, 'CREATEDB'),
        attr.Q_ALTER_ROLE_WITH.format(ROLE1, 'CREATEROLE'),
        attr.Q_ALTER_ROLE_WITH.format(ROLE1, 'REPLICATION'),
        attr.Q_ALTER_CONN_LIMIT.format(ROLE1, '30', '-1'),
        attr.Q_ALTER_VALID_UNTIL.format(ROLE1, '2016-08-04', 'None'),
    ])
    actual = set(roleconf.sql_to_run)
    assert actual == expected


def test_analyze_existing_role_non_default_attributes(mockdbcontext):
    role_attributes = copy.deepcopy(attr.DEFAULT_ATTRIBUTES)
    role_attributes.update(
        dict(
            rolcanlogin=True,
            rolconnlimit=27,
            rolreplication=True
        )
    )
    mockdbcontext.get_role_attributes = lambda x: role_attributes

    spec_attributes = copy.deepcopy(NON_DEFAULTS_GIVEN)
    spec_attributes.extend(['LOGIN', 'SUPERUSER'])

    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=spec_attributes,
                                      spec_configs={}, dbcontext=mockdbcontext)

    roleconf.analyze()

    expected = set([
        attr.Q_ALTER_ROLE_WITH.format(ROLE1, 'SUPERUSER'),
        attr.Q_ALTER_ROLE_WITH.format(ROLE1, 'CREATEDB'),
        attr.Q_ALTER_ROLE_WITH.format(ROLE1, 'CREATEROLE'),
        attr.Q_ALTER_CONN_LIMIT.format(ROLE1, '30', '27'),
        attr.Q_ALTER_VALID_UNTIL.format(ROLE1, '2016-08-04', 'None'),
    ])
    actual = set(roleconf.sql_to_run)
    assert actual == expected


@nondefault_attributes(dict(
    # role_exists() checks if dbcontext got attributes from the db for this rolename, meaning so
    # long as we have something here role_exists() will think the role exists
    anything='can_be_here'
))
def test_role_exists_true(roleconf):
    assert roleconf.role_exists()


def test_role_exists_false(mockdbcontext, roleconf):
    mockdbcontext.get_role_attributes = lambda x: dict()
    roleconf = attr.AttributeAnalyzer(DUMMY, spec_attributes=DUMMY, spec_configs={}, dbcontext=mockdbcontext)
    assert not roleconf.role_exists()


def test_create_role(roleconf):
    roleconf.create_role()
    assert roleconf.sql_to_run == [
        attr.Q_CREATE_ROLE.format(ROLE1)
    ]


def test_converted_attributes_defaults(roleconf):
    assert roleconf.converted_attributes() == {}


@pytest.mark.parametrize('bogus_attribute', [('INVALID'), ('NOINVALID')])
def test_converted_attributes_invalid_attribute(capsys, mockdbcontext, bogus_attribute):
    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=[bogus_attribute],
                                      spec_configs={}, dbcontext=mockdbcontext)

    with pytest.raises(SystemExit):
        roleconf.converted_attributes()
    assert capsys.readouterr()[0] == attr.UNKNOWN_ATTRIBUTE_MSG.format(bogus_attribute) + '\n'


def test_converted_attributes_connection_limit(mockdbcontext):
    """ Make sure converted_attributes parses a connection limit attribute successfully, i.e.
    that it splits the string and converts the second part to an int """
    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=['CONNECTION LIMIT 11'],
                                      spec_configs={}, dbcontext=mockdbcontext)
    attributes = roleconf.converted_attributes()
    assert attributes['rolconnlimit'] == 11


def test_converted_attributes_valid_until(mockdbcontext):
    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=["VALID UNTIL '2018-08-08'"],
                                      spec_configs={}, dbcontext=mockdbcontext)
    attributes = roleconf.converted_attributes()
    assert attributes['rolvaliduntil'] == "'2018-08-08'"


def test_converted_attributes_password(mockdbcontext):
    password_val = 'supeRSecret'
    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=["PASSWORD '{}'".format(password_val)],
                                      spec_configs={}, dbcontext=mockdbcontext)
    attributes = roleconf.converted_attributes()
    assert attributes['rolpassword'] == password_val


@pytest.mark.parametrize("password", [('super"secret'), ("super'secret")])
def test_converted_attributes_password_error_on_quotes(capsys, mockdbcontext, password):
    with pytest.raises(SystemExit):
        roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=["PASSWORD {}".format(password)],
                                          spec_configs={}, dbcontext=mockdbcontext)
        roleconf.converted_attributes()

    expected_err_msg = attr.UNSUPPORTED_CHAR_MSG.format(ROLE1) + '\n'
    assert capsys.readouterr()[0] == expected_err_msg


def test_converted_attributes_boolean_attribute(mockdbcontext):
    set_attributes = ['LOGIN', 'NOINHERIT', 'CREATEROLE', 'BYPASSRLS']
    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=set_attributes,
                                      spec_configs={}, dbcontext=mockdbcontext)
    converted_attributes = roleconf.converted_attributes()

    for opt in set_attributes:
        if opt.startswith('NO'):
            colname = attr.PG_COLUMN_NAME[opt[2:]]
            assert converted_attributes[colname] is False
        else:
            colname = attr.PG_COLUMN_NAME[opt]
            assert converted_attributes[colname] is True


def test_coalesce_attributes(mockdbcontext):
    mockdbcontext.get_role_attributes = lambda x: copy.deepcopy(attr.DEFAULT_ATTRIBUTES)
    set_attributes = ['BYPASSRLS', 'CREATEDB', 'NOINHERIT', 'REPLICATION']
    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=set_attributes,
                                      spec_configs={}, dbcontext=mockdbcontext)

    actual = roleconf.coalesce_attributes()
    expected = copy.deepcopy(attr.DEFAULT_ATTRIBUTES)
    expected.update(dict(
        rolbypassrls=True,
        rolcreatedb=True,
        rolinherit=False,
        rolreplication=True,
    ))
    assert actual == expected


def test_set_all_attributes(mockdbcontext):
    """
    This test name is a bit of a misnomer because it's mirroring the method's name
    (set_all_attributes). We aren't setting _all_ attributes, but rather testing that this method
    will set and update multiple attributes at once.

    Unlike the tests that check that coalesce_attributes works as expected, this test verifies
    that the changes are actually reflected in our change log.
    """
    mockdbcontext.get_role_attributes = lambda x: copy.deepcopy(attr.DEFAULT_ATTRIBUTES)
    set_attributes = ['BYPASSRLS', 'CREATEDB', 'CREATEROLE', 'REPLICATION']
    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=set_attributes,
                                      spec_configs={}, dbcontext=mockdbcontext)
    attributes = roleconf.coalesce_attributes()
    roleconf.set_all_attributes(attributes)

    actual = set(roleconf.sql_to_run)
    expected = {attr.Q_ALTER_ROLE_WITH.format(ROLE1, opt) for opt in set_attributes}
    assert actual == expected


@pytest.mark.parametrize("password", ["'supersecret'", '"supersecret"'])
def test_set_all_attributes_change_skips_same_password(mockdbcontext, password):
    role_attributes = copy.deepcopy(attr.DEFAULT_ATTRIBUTES)
    role_attributes.update(
        dict(
            rolpassword=attr.create_md5_hash(ROLE1, 'supersecret')
        )
    )
    mockdbcontext.get_role_attributes = lambda x: role_attributes

    attributes = ['PASSWORD {}'.format(password)]
    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=attributes, spec_configs={}, dbcontext=mockdbcontext)
    attributes = roleconf.coalesce_attributes()
    roleconf.set_all_attributes(attributes)
    assert roleconf.sql_to_run == []


@pytest.mark.parametrize("optname, optval", [
    ('rolbypassrls', False),
    ('rolcreatedb', False),
    ('rolcreaterole', False),
    ('rolinherit', False),
    ('rolcanlogin', True),
    ('rolreplication', False),
    ('rolsuper', True),
    ('rolconnlimit', 8)])
def test_get_attribute_value(mockdbcontext, optname, optval):
    role_attributes = copy.deepcopy(attr.DEFAULT_ATTRIBUTES)
    role_attributes.update(
        dict(
            rolcanlogin=True,
            rolsuper=True,
            rolinherit=False,
            rolconnlimit=8
        )
    )
    mockdbcontext.get_role_attributes = lambda x: role_attributes

    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=[], spec_configs={}, dbcontext=mockdbcontext)
    assert roleconf.get_attribute_value(optname) == optval


@nondefault_attributes(dict(
    rolvaliduntil=dt.datetime(2020, 1, 4),
))
def test_get_attribute_value_valid_until(roleconf):
    assert str(roleconf.get_attribute_value('rolvaliduntil').date()) == '2020-01-04'


@pytest.mark.parametrize("optname, optval", [
    ('rolbypassrls', True),
    ('rolcreatedb', True),
    ('rolcreaterole', True),
    ('rolinherit', False),
    ('rolcanlogin', True),
    ('rolreplication', True),
    ('rolsuper', True),
    ('rolconnlimit', 8)])
def test_set_attribute_value(roleconf, optname, optval):
    # Get value before we've changed anything
    assert roleconf.get_attribute_value(optname) != optval

    current_value = 'foo'
    roleconf.set_attribute_value(attribute=optname, desired_value=optval,
                                 current_value=current_value)

    if optname == 'rolconnlimit':
        expected = [attr.Q_ALTER_CONN_LIMIT.format(ROLE1, str(optval), current_value)]
    else:
        base_keyword = attr.COLUMN_NAME_TO_KEYWORD[optname]
        # prepend 'NO' if desired_value is False
        keyword = base_keyword if optval is True else ('NO' + base_keyword)
        expected = [attr.Q_ALTER_ROLE_WITH.format(ROLE1, keyword)]

    actual = roleconf.sql_to_run
    assert actual == expected


def test_set_attribute_value_sql_to_run(roleconf):
    assert len(roleconf.sql_to_run) == 0
    roleconf.set_attribute_value(attribute='rolcanlogin', desired_value=True, current_value='_')
    roleconf.set_attribute_value(attribute='rolsuper', desired_value=True, current_value='_')
    assert roleconf.sql_to_run == [attr.Q_ALTER_ROLE_WITH.format(ROLE1, 'LOGIN'),
                                   attr.Q_ALTER_ROLE_WITH.format(ROLE1, 'SUPERUSER')]


def test_set_attribute_value_valid_until(roleconf):
    opt = 'rolvaliduntil'
    val = '2019-09-09'
    curr_val = 'infinity'

    assert roleconf.get_attribute_value(opt) != val

    roleconf.set_attribute_value(attribute=opt, desired_value=val, current_value=curr_val)

    expected = [attr.Q_ALTER_VALID_UNTIL.format(ROLE1, val, curr_val)]
    assert roleconf.sql_to_run == expected


@nondefault_attributes(dict(
    rolpassword=attr.create_md5_hash(ROLE1, 'supersecret'),
))
@pytest.mark.parametrize('desired_value, expected', [
    ('supersecret', True),
    ('incorrect_password', False)])
def test_is_same_password(roleconf, desired_value, expected):
    assert roleconf.is_same_password(desired_value) == expected


def test_is_same_password_if_empty(roleconf):
    assert roleconf.is_same_password(None) is True


@nondefault_attributes(dict(
    rolpassword=attr.create_md5_hash(ROLE1, 'supersecret'),
))
def test_set_password_statements_generated(roleconf):
    desired_value = 'evenmoresecret'
    roleconf.set_password(desired_value)
    assert roleconf.password_sql_to_run == [attr.Q_ALTER_PASSWORD.format(ROLE1, desired_value)]

    # Verify that the output is sanitized
    expected = ['--' + attr.Q_ALTER_PASSWORD.format(roleconf.rolename, '******')]
    assert roleconf.sql_to_run == expected


@run_setup_sql([
    attr.Q_CREATE_ROLE.format(ROLE1),
])
def test_set_password_log_message_is_masked(capsys, cursor):
    new_password = 'mysecretpassword'
    spec = {
        # Add the existing users so we don't get an UNDOCUMENTED_ROLES failure
        'postgres': {'is_superuser': True},
        'test_user': {
            'is_superuser': True,
            'attributes': ['PASSWORD test_password'],
        },

        ROLE1: {'attributes': ['PASSWORD {}'.format(new_password)]},
    }

    _, password_all_sql_to_run = attr.analyze_attributes(spec, cursor, verbose=False)

    assert password_all_sql_to_run == [attr.Q_ALTER_PASSWORD.format(ROLE1, new_password)]


def test_get_config_value(mockdbcontext):
    role_configs = {
        'statement_timeout': 42
    }
    mockdbcontext.get_role_configs = lambda x: role_configs

    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=[], spec_configs={}, dbcontext=mockdbcontext)
    for k, v in role_configs.items():
        assert roleconf.get_config_value(k) == v


def test_set_all_configs(mockdbcontext):
    mockdbcontext.get_role_configs = lambda x: {
        'existing_extra': 'test',
    }

    spec_configs = {
        'statement_timeout': 42,
        'idle_in_transaction_session_timeout': 180,
    }

    roleconf = attr.AttributeAnalyzer(ROLE1, spec_attributes=[], spec_configs=spec_configs, dbcontext=mockdbcontext)
    roleconf.set_all_configs(spec_configs)

    actual = set(roleconf.sql_to_run)
    expected = set(attr.Q_ALTER_ROLE_SET.format(ROLE1, k, v, '') for k, v in spec_configs.items())
    expected.add(attr.Q_ALTER_ROLE_RESET.format(ROLE1, 'existing_extra', 'test'))
    assert actual == expected
