import copy
import datetime as dt
import hashlib
import logging

import click
import psycopg2

from pgbedrock import common
from pgbedrock.context import DatabaseContext

logger = logging.getLogger(__name__)


UNKNOWN_ATTRIBUTE_MSG = "Unknown attribute '{}' provided to ALTER ROLE"
UNSUPPORTED_CHAR_MSG = 'Password for role "{}" contains an unsupported character: \' or "'

Q_ALTER_CONN_LIMIT = 'ALTER ROLE "{}" WITH CONNECTION LIMIT {}; -- Previous value: {}'
Q_ALTER_PASSWORD = "ALTER ROLE \"{}\" WITH ENCRYPTED PASSWORD '{}';"
Q_REMOVE_PASSWORD = "ALTER ROLE \"{}\" WITH PASSWORD NULL;"
Q_ALTER_ROLE = 'ALTER ROLE "{}" WITH {};'
Q_ALTER_VALID_UNTIL = "ALTER ROLE \"{}\" WITH VALID UNTIL '{}'; -- Previous value: {}"
Q_CREATE_ROLE = 'CREATE ROLE "{}";'


DEFAULT_ATTRIBUTES = {
    'rolbypassrls': False,
    'rolcanlogin': False,
    'rolconnlimit': -1,
    'rolcreatedb': False,
    'rolcreaterole': False,
    'rolinherit': True,
    'rolpassword': None,
    'rolreplication': False,
    'rolsuper': False,
    'rolvaliduntil': None,
}

# Map to how the attribute is referred to within pg_authid
PG_COLUMN_NAME = {
    'BYPASSRLS': 'rolbypassrls',
    'CONNECTION LIMIT': 'rolconnlimit',
    'CREATEDB': 'rolcreatedb',
    'CREATEROLE': 'rolcreaterole',
    'INHERIT': 'rolinherit',
    'LOGIN': 'rolcanlogin',
    'PASSWORD': 'rolpassword',
    'REPLICATION': 'rolreplication',
    'SUPERUSER': 'rolsuper',
    'VALID UNTIL': 'rolvaliduntil'
}

# We also need a reverse lookup of PG_COLUMN_NAME
COLUMN_NAME_TO_KEYWORD = {v: k for k, v in PG_COLUMN_NAME.items()}


def analyze_attributes(spec, cursor, verbose):
    logger.debug('Starting analyze_attributes()')
    dbcontext = DatabaseContext(cursor, verbose)

    # We disable the progress bar when showing verbose output (using '' as our bar_template)
    # or # the bar will get lost in the # output
    bar_template = '' if verbose else common.PROGRESS_TEMPLATE
    with click.progressbar(spec.items(), label='Analyzing roles:      ', bar_template=bar_template,
                           show_eta=False, item_show_func=common.item_show_func) as all_roles:
        all_sql_to_run = []
        password_all_sql_to_run = []
        for rolename, spec_config in all_roles:
            logger.debug('Starting to analyze role {}'.format(rolename))

            spec_config = spec_config or {}
            spec_attributes = spec_config.get('attributes', [])

            for keyword, attribute in (('can_login', 'LOGIN'), ('is_superuser', 'SUPERUSER')):
                is_desired = spec_config.get(keyword, False)
                spec_attributes.append(attribute if is_desired else 'NO' + attribute)

            roleconf = AttributeAnalyzer(rolename, spec_attributes, dbcontext)
            roleconf.analyze()
            all_sql_to_run += roleconf.sql_to_run
            password_all_sql_to_run += roleconf.password_sql_to_run

    return all_sql_to_run, password_all_sql_to_run


def create_md5_hash(rolename, value):
    salted_input = (value + rolename).encode('utf-8')
    return 'md5' + hashlib.md5(salted_input).hexdigest()


def is_valid_forever(val):
    if val is None or val == 'infinity':
        return True
    elif isinstance(val, dt.datetime) and val.tzinfo is not None:
        return val == dt.datetime.max.replace(tzinfo=psycopg2.tz.FixedOffsetTimezone(offset=0, name=None))
    else:
        return val == dt.datetime.max


class AttributeAnalyzer(object):
    """ Analyze one role and determine (via .analyze()) any SQL statements that are necessary to
    make it match the provided spec attributes. Note that spec_attributes is a list whereas
    current_attributes is a dict. """

    def __init__(self, rolename, spec_attributes, dbcontext):
        self.sql_to_run = []
        self.rolename = common.check_name(rolename)
        logger.debug('self.rolename set to {}'.format(self.rolename))
        self.spec_attributes = spec_attributes

        self.current_attributes = dbcontext.get_role_attributes(rolename)

        # We keep track of password-related SQL separately as we don't want running this to
        # go into the main SQL stream since that could leak password
        self.password_sql_to_run = []

    def analyze(self):
        if not self.role_exists():
            self.create_role()

        desired_attributes = self.coalesce_attributes()
        self.set_all_attributes(desired_attributes)
        return self.sql_to_run

    def create_role(self):
        query = Q_CREATE_ROLE.format(self.rolename)
        self.sql_to_run.append(query)

    def coalesce_attributes(self):
        """ Override default attributes with user-provided ones and verify attributes are
        acceptable. Returns a dict with keys and structure similar to DEFAULT_ATTRIBUTES """
        attributes = copy.deepcopy(DEFAULT_ATTRIBUTES)
        spec_attributes = self.converted_attributes()
        attributes.update(spec_attributes)
        return attributes

    def converted_attributes(self):
        """ Convert the list of attributes provided in the spec to postgres-compatible
        keywords and values.
        """
        converted_attributes = {}
        for spec_attribute in self.spec_attributes:

            # We do spec_attribute.upper() in each spot in order to leave the original
            # spec_attribute unchanged in case it is a password, in which case we don't want to
            # change the case
            if spec_attribute.upper().startswith('CONNECTION LIMIT'):
                val = spec_attribute[17:].strip()
                converted_attributes['rolconnlimit'] = int(val)

            elif spec_attribute.upper().startswith('VALID UNTIL'):
                val = spec_attribute[12:].strip()
                converted_attributes['rolvaliduntil'] = val

            elif 'PASSWORD' in spec_attribute.upper():
                # Regardless whether the spec specified ENCRYPTED or UNENCRYPTED for the password,
                # we throw this away as we will be storing the password in encrypted form
                val = spec_attribute.split('PASSWORD ', 1)[-1]

                # Trim leading and ending quotes, if there are any
                if val[0] == '"' or val[0] == "'":
                    val = val[1:]
                if val[-1] == '"' or val[-1] == "'":
                    val = val[:-1]

                if "'" in val or '"' in val:
                    common.fail(msg=UNSUPPORTED_CHAR_MSG.format(self.rolename))

                converted_attributes['rolpassword'] = val

            elif spec_attribute.upper().startswith('NO'):
                keyword = spec_attribute.upper()[2:]
                colname = PG_COLUMN_NAME.get(keyword)
                if not colname:
                    common.fail(UNKNOWN_ATTRIBUTE_MSG.format(spec_attribute))

                converted_attributes[colname] = False

            else:
                keyword = spec_attribute.upper()
                colname = PG_COLUMN_NAME.get(keyword)
                if not colname:
                    common.fail(UNKNOWN_ATTRIBUTE_MSG.format(spec_attribute))

                converted_attributes[colname] = True

        return converted_attributes

    def get_attribute_value(self, attribute):
        """ Take an attribute named like a postgres column (e.g. rolsuper) and look up that value
        in our dbcontext """
        value = self.current_attributes.get(attribute, DEFAULT_ATTRIBUTES[attribute])
        logger.debug('Returning attribute "{}": "{}"'.format(attribute, value))
        return value

    def is_same_password(self, value):
        """ Convert the input value into a postgres rolname-salted md5 hash and compare
        it with the currently stored hash """
        if value is None:
            return self.current_attributes.get('rolpassword') is None

        md5_hash = create_md5_hash(self.rolename, value)
        return self.current_attributes.get('rolpassword') == md5_hash

    def role_exists(self):
        # If current_attributes is empty then the rolname wasn't in pg_authid, i.e. it doesn't exist
        return self.current_attributes != {}

    def set_all_attributes(self, attributes):
        """ Verify that the role's attributes match the spec's, updating as necessary """
        for attribute, desired_value in attributes.items():
            current_value = self.get_attribute_value(attribute)
            if attribute == 'rolpassword' and not self.is_same_password(desired_value):
                logger.debug('Altering password for role "{}"'.format(self.rolename))
                self.set_password(desired_value)

            if attribute == 'rolvaliduntil' \
               and is_valid_forever(desired_value) \
               and is_valid_forever(current_value):
                continue

            elif current_value != desired_value and attribute != 'rolpassword':
                self.set_attribute_value(attribute, desired_value, current_value)

    def set_attribute_value(self, attribute, desired_value, current_value):
        if attribute == 'rolconnlimit':
            query = Q_ALTER_CONN_LIMIT.format(self.rolename, desired_value, current_value)
        elif attribute == 'rolvaliduntil':
            query = Q_ALTER_VALID_UNTIL.format(self.rolename, desired_value, current_value)
        else:
            base_keyword = COLUMN_NAME_TO_KEYWORD[attribute]
            # prepend 'NO' if desired_value is False
            keyword = base_keyword if desired_value else 'NO' + base_keyword
            query = Q_ALTER_ROLE.format(self.rolename, keyword)

        self.sql_to_run.append(query)

    def set_password(self, desired_value):
        if desired_value is None:
            actual_query = Q_REMOVE_PASSWORD.format(self.rolename)
        else:
            actual_query = Q_ALTER_PASSWORD.format(self.rolename, desired_value)
        self.password_sql_to_run.append(actual_query)

        sanitized_query = Q_ALTER_PASSWORD.format(self.rolename, '******')
        self.sql_to_run.append('--' + sanitized_query)
