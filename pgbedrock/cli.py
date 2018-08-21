import getpass

import click

from pgbedrock import core_configure, core_generate


USER = getpass.getuser()


@click.group()
def entrypoint():
    pass


@entrypoint.command(short_help='Configure a database to match a YAML spec')
@click.argument('spec', required=True)
@click.option('-h', '--host', default='localhost', help='database server host (default: localhost)')
@click.option('-p', '--port', default=5432, type=int, help='database server port (default: 5432)')
@click.option('-U', '--user', default=USER, help='database user name (default: "{}")'.format(USER))
@click.option('-w', '--password', default="", help='database user password; (default: "")')
@click.option('-d', '--dbname', default=USER, help='database to connect to (default: "{}")'.format(USER))
@click.option('--prompt/--no-prompt', default=False, help='prompt the user to input a password (default: --no-prompt)')
@click.option('--attributes/--no-attributes', default=True, help='whether to configure role attributes (default: --attributes)')
@click.option('--memberships/--no-memberships', default=True, help='whether to configure memberships (default: --membership)')
@click.option('--ownerships/--no-ownerships', default=True, help='whether to configure object ownerships (default: --ownerships)')
@click.option('--privileges/--no-privileges', default=True, help='whether to configure privileges (default: --privileges)')
@click.option('--live/--check', default=False, help='whether to actually make changes ("live") or only show what would be changed ("check") (default: --check)')
@click.option('--verbose/--no-verbose', default=False, help='whether to show debug-level logging messages while running (default: --no-verbose)')
@click.option('--alternate-attributes-table/--no-alternate-attributes-table', default=False, help='whether to use pg_roles instead of pg_authid (default: --no-alternate-attributes-table)')
def configure(spec, host, port, user, password, dbname, prompt, attributes, memberships, ownerships,
              privileges, live, verbose, alternate_attributes_table):
    """
    Configure the role attributes, memberships, object ownerships, and/or privileges of a
    database cluster to match a desired spec.

    By default pgbedrock will not make the changes it proposes, i.e. it runs with --check by
    default (though you can explicitly pass --check as well if you want to be really safe). In this
    mode, when pgbedrock is finished it will abort the transaction that it is in. To make changes
    real, instead pass --live.

    In addition, using --verbose will print to STDOUT all debug statements and all SQL queries
    issued by pgbedrock.
    """

    attributes_source_table = 'pg_roles' if alternate_attributes_table else 'pg_authid'

    core_configure.configure(spec, host, port, user, password, dbname, prompt, attributes,
                             memberships, ownerships, privileges, live, verbose, attributes_source_table)


@entrypoint.command(short_help='Generate a YAML spec for a database')
@click.option('-h', '--host', default='localhost', help='database server host (default: localhost)')
@click.option('-p', '--port', default=5432, type=int, help='database server port (default: 5432)')
@click.option('-U', '--user', default=USER, help='database user name (default: "{}")'.format(USER))
@click.option('-w', '--password', default="", help='database user password; (default: "")')
@click.option('-d', '--dbname', default=USER, help='database to connect to (default: "{}")'.format(USER))
@click.option('--prompt/--no-prompt', default=False, help='prompt the user to input a password (default: --no-prompt)')
@click.option('--verbose/--no-verbose', default=False, help='whether to show debug-level logging messages while running (default: --no-verbose)')
@click.option('--alternate-attributes-table/--no-alternate-attributes-table', default=False, help='whether to use pg_roles instead of pg_authid (default: --no-alternate-attributes-table)')
def generate(host, port, user, password, dbname, prompt, verbose, alternate_attributes_table):
    """
    Generate a YAML spec that represents the roles, memberships, ownerships, and/or privileges of a
    database.
    """

    attributes_source_table = 'pg_roles' if alternate_attributes_table else 'pg_authid'
    core_generate.generate(host, port, user, password, dbname, prompt, verbose, attributes_source_table)


if __name__ == '__main__':
    entrypoint()
