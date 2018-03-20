from click.testing import CliRunner
import pytest

from pgbedrock import cli
from conftest import Q_GET_ROLE_ATTRIBUTE, NEW_USER


@pytest.mark.usefixtures('drop_users_and_objects')
def test_configure_defaults_to_check_mode(cursor, tiny_spec, db_config):
    # Assert that we start without the role we are trying to add
    cursor.execute(Q_GET_ROLE_ATTRIBUTE.format('rolname', NEW_USER))
    assert cursor.rowcount == 0

    runner = CliRunner()
    result = runner.invoke(cli.entrypoint, ['configure',
                                            tiny_spec,
                                            '-h', db_config['host'],
                                            '-p', str(db_config['port']),
                                            '-U', db_config['user'],
                                            '-w', db_config['password'],
                                            '-d', db_config['dbname'],
                                            ])
    assert result.exit_code == 0

    cursor.execute(Q_GET_ROLE_ATTRIBUTE.format('rolname', NEW_USER))
    assert cursor.rowcount == 0


@pytest.mark.usefixtures('drop_users_and_objects')
@pytest.mark.parametrize('live_mode, expected', [('--live', 1), ('--check', 0)])
def test_configure_live_mode_works(cursor, tiny_spec, db_config, live_mode, expected):
    """
    We add a new user (NEW_USER) through pgbedrock and make sure that 1) this change isn't
    committed if we pass --check and 2) this change _is_ committed if we pass --live
    """
    runner = CliRunner()
    result = runner.invoke(cli.entrypoint, ['configure',
                                            tiny_spec,
                                            '-h', db_config['host'],
                                            '-p', str(db_config['port']),
                                            '-U', db_config['user'],
                                            '-w', db_config['password'],
                                            '-d', db_config['dbname'],
                                            live_mode
                                            ])
    assert result.exit_code == 0

    cursor.execute(Q_GET_ROLE_ATTRIBUTE.format('rolname', NEW_USER))
    assert cursor.rowcount == expected
