try:
    # Python 2
    from distutils import strtobool
except:
    # Python 3
    from distutils.util import strtobool
import logging
import sys
import traceback

import click
import psycopg2


logger = logging.getLogger(__name__)

DATABASE_CONNECTION_ERROR_MSG = 'Unable to connect to database. Postgres traceback:\n{}'

FAILED_QUERY_MSG = 'Failed to execute query "{}": {}'
UNSUPPORTED_CHAR_MSG = 'Role "{}" contains an unsupported character: \' or "'
PROGRESS_TEMPLATE = '%(label)s  [%(bar)s]  %(info)s'


def check_name(name):
    if "'" in name or '"' in name:
        fail(msg=UNSUPPORTED_CHAR_MSG.format(name))
    else:
        return name


def fail(msg):
    click.secho(msg, fg='red')
    sys.exit(1)


def get_db_connection(host, port, dbname, user, password):
    try:
        db_conn = psycopg2.connect(host=host, port=port, dbname=dbname, user=user, password=password)
        db_conn.set_session(autocommit=False)
        return db_conn
    except Exception as e:
        fail(DATABASE_CONNECTION_ERROR_MSG.format(e))


def item_show_func(x):
    return x[0] if x else ''


def parse_bool(value):
    return bool(strtobool(str(value).lower()))


def run_query(cursor, verbose, query):
    logger.debug('Executing query: {}'.format(query))
    try:
        cursor.execute(query)
    except Exception as e:
        if verbose:
            click.secho(FAILED_QUERY_MSG.format(query, ''), fg='red')
            # The following is needed to output the traceback as well
            exc_type, exc_value, exc_tb = sys.exc_info()
            formatted_tb = '\n'.join(traceback.format_tb(exc_tb))
            click.secho(formatted_tb)
        else:
            click.secho(FAILED_QUERY_MSG.format(query, e), fg='red')
        sys.exit(1)


class ObjectName(object):
    """ Hold references to a specifc object, i.e. the schema and object name.

    We do this in order to:
        * Enable us to easily pick out the schema and object name for an object
        * Be sure that when we use a schema or object name we won't have to worry
            about existing double-quoting of these characteristics
        * Be sure that when we get the fully-qualified name it will be double quoted
            properly, i.e.  "myschema"."mytable"
    """
    def __init__(self, schema, unqualified_name=None):
        # Make sure schema and table are both stored without double quotes around
        # them; we add these when ObjectName.qualified_name is called
        self._schema = self._unquoted_item(schema)
        self._unqualified_name = self._unquoted_item(unqualified_name)

        if self._unqualified_name and self._unqualified_name == '*':
            self._qualified_name = '{}.{}'.format(self.schema, self.unqualified_name)
        elif self._unqualified_name and self._unqualified_name != '*':
            # Note that if we decide to support "schema"."table" within YAML that we'll need to
            # add a custom constructor since otherwise YAML gets confused unless you do
            # '"schema"."table"'
            self._qualified_name = '{}."{}"'.format(self.schema, self.unqualified_name)
        else:
            self._qualified_name = '{}'.format(self.schema)

    def __eq__(self, other):
        return (self.schema == other.schema) and (self.unqualified_name == other.unqualified_name)

    def __hash__(self):
        return hash(self.qualified_name)

    def __lt__(self, other):
        return self.qualified_name < other.qualified_name

    def __repr__(self):
        if self.unqualified_name:
            return "ObjectName('{}', '{}')".format(self.schema, self.unqualified_name)

        return "ObjectName('{}')".format(self.schema)

    @classmethod
    def from_str(cls, text):
        """ Convert a text representation of a qualified object name into an ObjectName instance

        For example, 'foo.bar', '"foo".bar', '"foo"."bar"', etc. will be converted an object with
        schema 'foo' and object name 'bar'. Double quotes around the schema or object name are
        stripped, but note that we don't do anything with impossible input like 'foo."bar".baz'
        (which is impossible because the object name would include double quotes in it). Instead,
        we let processing proceed and the issue bubble up downstream.
        """
        if '.' not in text:
            return cls(schema=text)

        # If there are multiple periods we assume that the first one delineates the schema from
        # the rest of the object, i.e. foo.bar.baz means schema foo and object "bar.baz"
        schema, unqualified_name = text.split('.', 1)
        # Don't worry about removing double quotes as that happens in __init__
        return cls(schema=schema, unqualified_name=unqualified_name)

    def only_schema(self):
        """ Return an ObjectName instance for the schema associated with the current object """
        return ObjectName(self.schema)

    @property
    def schema(self):
        return self._schema

    @property
    def unqualified_name(self):
        return self._unqualified_name

    @property
    def qualified_name(self):
        return self._qualified_name

    @staticmethod
    def _unquoted_item(item):
        if item and item.startswith('"') and item.endswith('"'):
            return item[1:-1]
        return item
