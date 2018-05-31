import copy
import logging
import os
import sys
from textwrap import dedent

import psycopg2
from psycopg2 import extras  # access via psycopg2.extras doesn't work so this import is needed
import pytest

# Add the package to the Python path so just running `pytest` from the top-level dir works
# This is also necessary in order to import pgbedrock
HERE = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(HERE))

# Set log level to DEBUG because pgbedrock by default only logs at INFO level and above
from pgbedrock import LOG_FORMAT
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


Q_GET_ROLE_ATTRIBUTE = "SELECT {} FROM pg_authid WHERE rolname='{}';"
NEW_USER = 'foobar'


@pytest.fixture(scope='session')
def db_config():
    """
    db config assumes you are using the postgres db provided by the docker
    container either connecting to it through localhost if you're running the
    test suite outside of docker, or through docker's network if you are running
    the test suite from within docker
    """
    in_docker = os.environ.get('WITHIN_DOCKER_FLAG', False)
    host = 'pgbedrock_postgres' if in_docker else 'localhost'
    port = int(os.environ.get('POSTGRES_PORT', '54321'))
    yield {'host': host,
           'port': port,
           'user': 'test_user',
           'password': 'test_password',
           'dbname': 'test_db'}


@pytest.fixture(scope='function')
def cursor(request, db_config):
    db_connection = psycopg2.connect(**db_config)
    cursor = db_connection.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if hasattr(request, 'param'):
        for query in request.param:
            logger.debug('Executing query: {}'.format(query))
            cursor.execute(query)

    yield cursor
    db_connection.rollback()
    db_connection.close()


@pytest.fixture(scope='function')
def drop_users_and_objects(cursor):
    """ Remove committed users and objects after a test run. To do just a teardown we have to
    yield the empty fixture first """
    yield
    cursor.execute("""
        SELECT rolname
        FROM pg_authid
        WHERE rolname NOT IN (
            'test_user', 'postgres', 'pg_signal_backend',
            -- Roles introduced in Postgres 10:
            'pg_monitor', 'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables'
        );
        """)
    users = [u[0] for u in cursor.fetchall()]
    for user in users:
        cursor.execute('DROP OWNED BY "{0}" CASCADE; DROP ROLE "{0}"'.format(user))
        cursor.connection.commit()


@pytest.fixture
def base_spec(cursor):
    """ A spec with the existing state of the test database before anything has been done """
    spec = dedent("""
        postgres:
            attributes:
                - BYPASSRLS
                - CREATEDB
                - CREATEROLE
                - REPLICATION
            can_login: true
            is_superuser: true
            owns:
                schemas:
                    - information_schema
                    - pg_catalog
                    - public
                tables:
                    - information_schema.*
                    - pg_catalog.*
            privileges:
                schemas:
                    write:
                        - information_schema
                        - pg_catalog
                        - public

        test_user:
            attributes:
                - PASSWORD "test_password"
            can_login: yes
            is_superuser: yes
        """)

    # Postgres 10 introduces several new roles that we have to account for
    cursor.execute("SELECT substring(version from 'PostgreSQL ([0-9.]*) ') FROM version()")
    pg_version = cursor.fetchone()[0]
    if pg_version.startswith('10.'):
        spec += dedent("""

            pg_read_all_settings:

            pg_stat_scan_tables:

            pg_read_all_stats:

            pg_monitor:
                member_of:
                    - pg_read_all_settings
                    - pg_stat_scan_tables
                    - pg_read_all_stats
            """)

    return spec


@pytest.fixture
def tiny_spec(tmpdir, base_spec):
    # NOTE: if the test_password isn't provided here we end up changing our
    # test_user's password for real in the test_configure_live_mode_works
    spec = copy.copy(base_spec)
    spec += dedent("""
        {new_user}:
            has_personal_schema: yes
            member_of:
                - postgres
            privileges:
                tables:
                    read:
                        - pg_catalog.pg_class
         """.format(new_user=NEW_USER))

    spec_path = tmpdir.join('spec.yml')
    spec_path.write(spec)
    return spec_path.strpath


@pytest.fixture()
def mockdbcontext():
    """ Create a mock DatabaseContext that returns None for any method call that
    has not been overwritten """
    class MockDatabaseContext(object):
        def __getattr__(self, val):
            def empty_func(*args, **kwargs):
                return None

            return empty_func

    return MockDatabaseContext()


def quoted_object(schema, rest):
    """ All objects that pgbedrock works with will be double-quoted after the schema. Anything we
    work with in our test suite needs to behave similarly. """
    return '{}."{}"'.format(schema, rest)


def run_setup_sql(statement):
    """
    Take a SQL statement and have cursor execute it before the test begins. This is intended to
    separate highly bespoke test setup more fully from test execution
    """
    return pytest.mark.parametrize('cursor', [statement], indirect=True)
