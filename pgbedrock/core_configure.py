import getpass
import logging

import click
import psycopg2.extras

from pgbedrock import LOG_FORMAT
from pgbedrock import common
from pgbedrock.attributes import analyze_attributes
from pgbedrock.memberships import analyze_memberships
from pgbedrock.ownerships import analyze_ownerships
from pgbedrock.privileges import analyze_privileges
from pgbedrock.spec_inspector import load_spec


logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

HEADER = '-- SQL EXECUTED ({} MODE)'
SUCCESS_MSG = "\nNo changes needed. Congratulations! :)"


def create_divider(section):
    """ Within our output, we prepend all SQL statements for a given submodule (e.g. memberships,
    privileges, etc.) with a divider that names the section that we're on """
    edge_line = '--------------------------------'
    center_line = '--- Configuring {} '.format(section)
    padding = 32 - len(center_line)
    divider = '\n'.join(['', '', edge_line, center_line + '-' * padding, edge_line, ''])
    return divider


def has_changes(statements):
    """ See if a list of SQL statements has any lines that are not just comments """
    for stmt in statements:
        if not stmt.startswith('--') and not stmt.startswith('\n\n--'):
            return True
    return False


def run_module_sql(module_sql, cursor, verbose):
    if module_sql and has_changes(module_sql):
        # Put all SQL into 1 string to reduce network IO of sending many small calls to Postgres
        combined_sql = '\n'.join(module_sql)
        common.run_query(cursor, verbose, combined_sql)


def run_password_sql(cursor, all_password_sql_to_run):
    """
    Run one or more SQL statements that contains a password. We do this outside of the
    common.run_query() framework for two reasons:
        1) If verbose mode is requested then common.run_query() will show the password in its
        reporting of the queries that are executed
        2) The input to common.run_query() is the module output. This output is faithfully rendered
        as-is to STDOUT upon pgbedrock's completion, so we would leak the password there as well.

    By running password-containing queries outside of the common.run_query() approach we can avoid
    these issues
    """
    query = '\n'.join(all_password_sql_to_run)

    try:
        cursor.execute(query)
    except Exception as e:
        common.fail(msg=common.FAILED_QUERY_MSG.format(query, e))


def configure(spec_path, host, port, user, password, dbname, prompt, attributes, memberships,
              ownerships, privileges, live, verbose):
    """
    Configure the role attributes, memberships, object ownerships, and/or privileges of a
    database cluster to match a desired spec.

    Note that attributes and memberships are database cluster-wide settings, i.e. they are the
    same across multiple databases within a given Postgres instance. Ownerships and privileges
    are specific to each individual database within a Postgres instance.

    Inputs:

        spec_path - str; the path for the configuration file

        host - str; the database server host

        port - str; the database server port

        user - str; the database user name

        password - str; the database user's password

        dbname - str; the database to connect to and configure

        prompt - bool; whether to prompt for a password

        attributes - bool; whether to configure the role attributes for the specified
            database cluster

        memberships - bool; whether to configure the role memberships for the specified
            database cluster

        ownerships - bool; whether to configure the ownerships for the specified database

        privileges - bool; whether to configure the privileges for the specified database

        live - bool; whether to apply the changes (True) or just show what changes
            would be made without actually appyling them (False)

        verbose - bool; whether to show all queries that are executed and all debug log
            messages during execution
    """
    if verbose:
        root_logger = logging.getLogger('')
        root_logger.setLevel(logging.DEBUG)

    if prompt:
        password = getpass.getpass()

    db_connection = common.get_db_connection(host, port, dbname, user, password)
    cursor = db_connection.cursor(cursor_factory=psycopg2.extras.DictCursor)

    spec = load_spec(spec_path, cursor, verbose, attributes, memberships, ownerships, privileges)

    sql_to_run = []
    password_changed = False  # Initialize this in case the attributes module isn't run

    if attributes:
        sql_to_run.append(create_divider('attributes'))
        # Password changes happen within the attributes.py module itself so we don't leak
        # passwords; as a result we need to see if password changes occurred
        module_sql, all_password_sql_to_run = analyze_attributes(spec, cursor, verbose)
        run_module_sql(module_sql, cursor, verbose)
        if all_password_sql_to_run:
            password_changed = True
            run_password_sql(cursor, all_password_sql_to_run)

        sql_to_run.extend(module_sql)

    if memberships:
        sql_to_run.append(create_divider('memberships'))
        module_sql = analyze_memberships(spec, cursor, verbose)
        run_module_sql(module_sql, cursor, verbose)
        sql_to_run.extend(module_sql)

    if ownerships:
        sql_to_run.append(create_divider('ownerships'))
        module_sql = analyze_ownerships(spec, cursor, verbose)
        run_module_sql(module_sql, cursor, verbose)
        sql_to_run.extend(module_sql)

    if privileges:
        sql_to_run.append(create_divider('privileges'))
        module_sql = analyze_privileges(spec, cursor, verbose)
        run_module_sql(module_sql, cursor, verbose)
        sql_to_run.extend(module_sql)

    changed = password_changed or has_changes(sql_to_run)
    if changed and live:
        logger.debug('Committing changes')
        db_connection.commit()
    else:
        db_connection.rollback()

    # Make sure there is at least 1 line with a real change (vs. all headers)
    if changed:
        click.secho(HEADER.format('LIVE' if live else 'CHECK'), fg='green')
        for statement in sql_to_run:
            click.secho(statement, fg='green')
    else:
        click.secho(SUCCESS_MSG, fg='green')
