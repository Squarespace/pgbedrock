import copy
from textwrap import dedent

import pytest

from conftest import Q_GET_ROLE_ATTRIBUTE, NEW_USER, run_setup_sql
from pgbedrock import core_configure, context
from pgbedrock import ownerships as own
from pgbedrock import attributes as attr
from test_ownerships import Q_SCHEMA_EXISTS
from test_memberships import Q_HAS_ROLE
from test_privileges import Q_HAS_PRIVILEGE


@pytest.mark.parametrize('statements, expected', [
    (['--foo', '--bar'], False),
    (['--foo', 'bar'], True),
    ([], False),
])
def test_has_changes(statements, expected):
    assert core_configure.has_changes(statements) is expected


@pytest.mark.usefixtures('drop_users_and_objects')
def test_configure_no_changes_needed(tmpdir, capsys, db_config, base_spec):
    spec_path = tmpdir.join('spec.yml')
    spec_path.write(base_spec)

    params = copy.deepcopy(db_config)
    params.update(
        dict(spec_path=spec_path.strpath,
             prompt=False,
             attributes=True,
             memberships=True,
             ownerships=True,
             privileges=True,
             live=False,
             verbose=False
             )
    )
    core_configure.configure(**params)
    out, err = capsys.readouterr()
    assert core_configure.SUCCESS_MSG in out


@pytest.mark.usefixtures('drop_users_and_objects')
@pytest.mark.parametrize('live_mode, expected', [(True, 1), (False, 0)])
def test_configure_live_mode_works(capsys, cursor, spec_with_new_user, db_config, live_mode, expected):
    """
    We add a new user (NEW_USER) through pgbedrock and make sure that 1) this change isn't
    committed if we pass --check and 2) this change _is_ committed if we pass --live
    """
    # Assert that we start without the role we are trying to add
    cursor.execute(Q_GET_ROLE_ATTRIBUTE.format('rolname', NEW_USER))
    assert cursor.rowcount == 0

    params = copy.deepcopy(db_config)
    params.update(
        dict(spec_path=spec_with_new_user,
             prompt=False,
             attributes=True,
             memberships=True,
             ownerships=True,
             privileges=True,
             live=live_mode,
             verbose=False
             )
    )
    core_configure.configure(**params)
    out, err = capsys.readouterr()

    # We want to make sure that in live mode changes from each module have been
    # made (and additionally that in check mode these changes were _not_ made)
    cursor.execute(Q_GET_ROLE_ATTRIBUTE.format('rolname', NEW_USER))
    assert cursor.rowcount == expected

    cursor.execute(Q_SCHEMA_EXISTS.format(NEW_USER))
    assert cursor.rowcount == expected

    if live_mode:
        cursor.execute(Q_HAS_ROLE.format(NEW_USER, 'postgres'))
        assert cursor.rowcount == expected

        cursor.execute(Q_HAS_PRIVILEGE.format(NEW_USER, 'pg_catalog.pg_class'))
        assert cursor.fetchone()[0] is True


@pytest.mark.usefixtures('drop_users_and_objects')
def test_configure_live_does_not_leak_passwords(tmpdir, capsys, cursor, db_config, base_spec):
    """
    We add a new user (NEW_USER) through pgbedrock and make sure that 1) this change isn't
    committed if we pass --check and 2) this change _is_ committed if we pass --live
    """
    # Assert that we start without the role we are trying to add
    cursor.execute(Q_GET_ROLE_ATTRIBUTE.format('rolname', NEW_USER))
    assert cursor.rowcount == 0

    new_password = 'supersecret'
    spec = copy.copy(base_spec)
    spec += dedent("""
        {new_user}:
            attributes:
                - PASSWORD "{new_password}"
        """.format(new_user=NEW_USER, new_password=new_password))

    spec_path = tmpdir.join('spec.yml')
    spec_path.write(spec)
    params = copy.deepcopy(db_config)
    params.update(
        dict(spec_path=spec_path.strpath,
             prompt=False,
             attributes=True,
             memberships=True,
             ownerships=True,
             privileges=True,
             live=True,
             verbose=True,
             )
    )
    core_configure.configure(**params)

    # Verify that the password was changed
    new_md5_hash = attr.create_md5_hash(NEW_USER, new_password)
    cursor.execute("SELECT rolpassword FROM pg_authid WHERE rolname = '{}';".format(NEW_USER))
    assert cursor.fetchone()[0] == new_md5_hash

    # Verify that the password isn't exposed in our output
    out, err = capsys.readouterr()
    assert 'supersecret' not in out
    assert 'supersecret' not in err

    # Verify that the sanitized record of the password change is in our output
    assert 'ALTER ROLE "foobar" WITH ENCRYPTED PASSWORD \'******\';' in out


@run_setup_sql([
    attr.Q_CREATE_ROLE.format(NEW_USER),
    attr.Q_ALTER_PASSWORD.format(NEW_USER, 'some_password'),
])
@pytest.mark.usefixtures('drop_users_and_objects')
def test_no_password_attribute_makes_password_none(capsys, cursor, spec_with_new_user, db_config):

    # We have to commit the changes from @run_setup_sql so they will be seen by
    # the transaction generated within pgbedrock configure
    cursor.connection.commit()

    # Assert that we start with the role whose password we are trying to modify
    cursor.execute(Q_GET_ROLE_ATTRIBUTE.format('rolname', NEW_USER))
    assert cursor.rowcount == 1

    # Assert that the password is not NULL
    cursor.execute("SELECT rolpassword IS NOT NULL FROM pg_authid WHERE rolname = '{}'".format(NEW_USER))
    assert cursor.fetchone()[0] is True

    params = copy.deepcopy(db_config)
    params.update(
        dict(spec_path=spec_with_new_user,
             prompt=False,
             attributes=True,
             memberships=True,
             ownerships=True,
             privileges=True,
             live=True,
             verbose=False
             )
    )
    core_configure.configure(**params)
    out, err = capsys.readouterr()

    # Assert that the password is NULL now
    cursor.execute("SELECT rolpassword IS NULL FROM pg_authid WHERE rolname = '{}'".format(NEW_USER))
    assert cursor.fetchone()[0] is True


def test_configure_schema_role_has_dash(tmpdir, capsys, db_config, cursor, base_spec):
    """
    We add a new user ('role-with-dash') through pgbedrock and make sure that that user can create
    a personal schema
    """
    role = 'role-with-dash'

    spec = copy.copy(base_spec)
    spec += dedent("""
        {}:
            has_personal_schema: yes
        """.format(role))

    spec_path = tmpdir.join('spec.yml')
    spec_path.write(spec)

    params = copy.deepcopy(db_config)
    params.update(
        dict(spec_path=spec_path.strpath,
             prompt=False,
             attributes=True,
             memberships=True,
             ownerships=True,
             privileges=True,
             live=False,
             verbose=False
             )
    )
    core_configure.configure(**params)
    out, err = capsys.readouterr()
    assert own.Q_CREATE_SCHEMA.format(role, role) in out
