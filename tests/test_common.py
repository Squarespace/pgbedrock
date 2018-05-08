import pytest

from pgbedrock import common


@pytest.mark.parametrize('rolename', [
    ("bad'_name"),
    ('bad"_name'),
])
def test_check_name_fails_on_quotes(capsys, rolename):
    with pytest.raises(SystemExit):
        common.check_name(rolename)
    assert capsys.readouterr()[0] == common.UNSUPPORTED_CHAR_MSG.format(rolename) + '\n'


def test_check_name_succeeds():
    rolename = 'foobar'
    assert rolename == common.check_name(rolename)


@pytest.mark.parametrize('input, expected', [
    ('myschema.myschema.mytable', 'myschema."myschema.mytable"'),
    ('myschema."myschema.mytable"', 'myschema."myschema.mytable"'),
    ('myschema.mytable', 'myschema."mytable"'),
    ('unqualified', 'unqualified'),
])
def test_ensure_quoted_identifier(input, expected):
    assert common.ensure_quoted_identifier(input) == expected


def test_get_db_connection_fails(capsys):
    with pytest.raises(SystemExit) as err:
        common.get_db_connection('foo', 'foo', 'foo', 'foo', 'foo')

    out, err = capsys.readouterr()
    assert common.DATABASE_CONNECTION_ERROR_MSG.format('') in out


def test_get_db_connection_autocommit(db_config):
        db_connection = common.get_db_connection(**db_config)
        assert db_connection.autocommit is False


@pytest.mark.parametrize("value,expected", [
    ('yes', True),
    ('Yes', True),
    ('YES', True),
    ('true', True),
    ('True', True),
    ('on', True),
    ('1', True),
    (1, True),
    ('no', False),
    ('No', False),
    ('NO', False),
    ('false', False),
    ('False', False),
    ('off', False),
    ('0', False),
    (0, False),
])
def test_parse_bool(value, expected):
    assert common.parse_bool(value) == expected


def test_run_query(cursor):
    common.run_query(cursor, verbose=True, query='SELECT 1+1')
    assert cursor.fetchone() == [2]


def test_run_query_fails_in_verbose_mode(capsys, cursor):
    cursor.close()
    with pytest.raises(SystemExit):
        common.run_query(cursor, verbose=True, query='SELECT 1+1')
    expected_msg = common.FAILED_QUERY_MSG.format('SELECT 1+1', '')
    error = capsys.readouterr()[0]
    assert error.startswith(expected_msg)
    assert 'pgbedrock/common.py", line' in error


def test_run_query_fails_not_verbose_mode(capsys, cursor):
    cursor.close()
    with pytest.raises(SystemExit):
        common.run_query(cursor, verbose=False, query='SELECT 1+1')
    expected_msg = common.FAILED_QUERY_MSG.format('SELECT 1+1', 'cursor already closed\n')
    assert expected_msg == capsys.readouterr()[0]
