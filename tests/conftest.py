import logging
import os
import sys

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
    host = 'pgbedrock_postgres' if os.environ.get('WITHIN_DOCKER_FLAG') else 'localhost'
    yield {'host': host,
           'port': 5432,
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
        WHERE rolname NOT IN ('test_user', 'postgres', 'pg_signal_backend')
        ;
        """)
    users = [u[0] for u in cursor.fetchall()]
    for user in users:
        cursor.execute('DROP OWNED BY "{0}" CASCADE; DROP ROLE "{0}"'.format(user))
        cursor.connection.commit()


@pytest.fixture
def tiny_spec(tmpdir):
    # NOTE: if the test_password isn't provided here we end up changing our test_user's password
    # for real in our test_main_run_mode_works test below
    spec_path = tmpdir.join('spec.yml')
    spec_path.write("""
    postgres:
        is_superuser: yes
        owns:
            schemas:
                - information_schema
                - pg_catalog
                - public

    test_user:
        can_login: yes
        is_superuser: yes
        attributes:
            - PASSWORD "test_password"

    {new_user}:
        has_personal_schema: yes
        member_of:
            - postgres
        privileges:
            tables:
                read:
                    - pg_catalog.pg_class
    """.format(new_user=NEW_USER))
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
