from collections import defaultdict
import getpass
import logging
import os

import click
import cerberus
import jinja2
import psycopg2.extras
import yaml

from pgbedrock import LOG_FORMAT
from pgbedrock import common
from pgbedrock.attributes import analyze_attributes
from pgbedrock.memberships import analyze_memberships
from pgbedrock.ownerships import analyze_schemas
from pgbedrock.privileges import analyze_privileges


logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

HEADER = '-- SQL EXECUTED ({} MODE)'
FILE_OPEN_ERROR_MSG = "Unable to open file '{}':\n{}"
MISSING_ENVVAR_MSG = "Required environment variable not found:\n{}"
VALIDATION_ERR_MSG = 'Spec error: role "{}", field "{}": {}'
MULTIPLE_SCHEMA_OWNER_ERR_MSG = 'Spec error: schema "{}" owned by more than one role: {}'
DUPLICATE_ROLE_DEFINITIONS_ERR_MSG = 'Spec error: role(s) defined more than once: {}'
OBJECT_REF_READ_WRITE_ERR = ('Spec error: objects have been unnecessarily given both read and write privileges.'
                             'pgbedrock automatically grants read access when write access is requested.\n\t{}'
                             )
SUCCESS_MSG = "\nNo changes needed. Congratulations! :)"

SPEC_SCHEMA_YAML = """
    can_login:
        type: boolean
    has_personal_schema:
        type: boolean
    is_superuser:
        type: boolean
    attributes:
        type: list
        schema:
            type: string
            forbidden:
                - LOGIN
                - NOLOGIN
                - SUPERUSER
                - NOSUPERUSER
    member_of:
        type: list
        schema:
            type: string
    privileges:
        type: dict
        allowed:
            - schemas
            - sequences
            - tables
        valueschema:
            type: dict
            allowed:
                - read
                - write
            valueschema:
                type: list
                schema:
                    type: string
    owns:
        type: dict
        allowed:
            - schemas
        valueschema:
            type: list
            schema:
                type: string
    """


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


def render_template(path):
    """ Load a spec. There may be templated password variables, which we render using Jinja. """
    try:
        dir_path, filename = os.path.split(path)
        environment = jinja2.Environment(loader=jinja2.FileSystemLoader(dir_path),
                                         undefined=jinja2.StrictUndefined)
        loaded = environment.get_template(filename)
        rendered = loaded.render(env=os.environ)
    except jinja2.exceptions.TemplateNotFound as err:
        common.fail(FILE_OPEN_ERROR_MSG.format(path, err))
    except jinja2.exceptions.UndefinedError as err:
        common.fail(MISSING_ENVVAR_MSG.format(err))
    else:
        return rendered


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


def verify_schema(spec):
    """Checks spec for schema errors."""
    error_messages = []

    schema = yaml.load(SPEC_SCHEMA_YAML)
    v = cerberus.Validator(schema)
    for rolename, config in spec.items():
        if not config:
            continue
        v.validate(config)
        for field, err_msg in v.errors.items():
            error_messages.append(VALIDATION_ERR_MSG.format(rolename, field, err_msg[0]))

    return error_messages


def check_for_multi_schema_owners(spec):
    """Checks spec for schema with multiple owners."""
    error_messages = []

    globally_owned_schemas = defaultdict(list)
    for role, config in spec.items():
        if not config:
            continue
        if config.get('has_personal_schema'):
            # indicates a role has a personal schema with its same name
            globally_owned_schemas[role].append(role)
        if config.get('owns') and config['owns'].get('schemas'):
            role_owned_schemas = config['owns']['schemas']
            for schema in role_owned_schemas:
                globally_owned_schemas[schema].append(role)
    for schema, owners in globally_owned_schemas.items():
        if len(owners) > 1:
            owners_formatted = ", ".join(owners)
            error_messages.append(MULTIPLE_SCHEMA_OWNER_ERR_MSG.format(schema, owners_formatted))

    return error_messages


def check_read_write_obj_references(spec):
    """Verifies objects aren't defined in both read and write privileges sections."""
    error_messages = []

    multi_refs = defaultdict(dict)
    for role, config in spec.items():
        if config and config.get('privileges'):
            for obj in config['privileges']:
                try:
                    reads = set(config['privileges'][obj]['read'])
                    writes = set(config['privileges'][obj]['write'])
                    duplicates = reads.intersection(writes)
                    if duplicates:
                        multi_refs[role][obj] = list(duplicates)
                except KeyError:
                    continue
    if multi_refs:
        multi_ref_strings = ["%s: %s" % (k, v) for k, v in multi_refs.items()]
        multi_ref_err_string = "\n\t".join(multi_ref_strings)
        error_messages.append(OBJECT_REF_READ_WRITE_ERR.format(multi_ref_err_string))

    return error_messages


def detect_multiple_role_definitions(rendered_spec_template):
    """Checks spec for roles declared multiple times.

    In a spec template, if a role is declared more than once there exists a risk that the re-declaration will
    override the desired configuration. pgbedrock considers a config containing this risk to be invalid and
    will throw an error.

    To accomplish this, the yaml.loader.Loader object is used to convert spec template
    into a document tree.  Then, the root object's child nodes (which are the roles) are checked for duplicates.

    Outputs:
        []string    The decision to return a list of strings was deliberate, despite
                    the fact that the length of the list can at most be one. The reason for this
                    is that the other spec verification functions
                    (check_for_multi_schema_owners and check_read_write_obj_references, verify_schema)
                    also return a list of strings.  This return signature consistency makes the code
                    in the verify_spec function cleaner.
    """
    error_messages = []
    loader = yaml.loader.Loader(rendered_spec_template)
    document_tree = loader.get_single_node()
    if document_tree is None:
        return None

    role_definitions = defaultdict(int)
    for node in document_tree.value:
        role_definitions[node[0].value] += 1
    multi_defined_roles = [k for k, v in role_definitions.items() if v > 1]
    if multi_defined_roles:
        error_message = " ,".join(multi_defined_roles)
        error_messages = [DUPLICATE_ROLE_DEFINITIONS_ERR_MSG.format(error_message)]

    return error_messages


def verify_spec(rendered_template, spec):
    assert isinstance(spec, dict)

    error_messages = []
    error_messages += detect_multiple_role_definitions(rendered_template)
    verification_functions = (verify_schema,
                              check_for_multi_schema_owners,
                              check_read_write_obj_references)
    for fn in verification_functions:
        error_messages += fn(spec)
    if error_messages:
        common.fail('\n'.join(error_messages))


def configure(spec, host, port, user, password, dbname, prompt, attributes, memberships,
              ownerships, privileges, live, verbose):
    """
    Configure the role attributes, memberships, object ownerships, and/or privileges of a
    database cluster to match a desired spec.

    Note that attributes and memberships are database cluster-wide settings, i.e. they are the
    same across multiple databases within a given Postgres instance. Ownerships and privileges
    are specific to each individual database within a Postgres instance.

    Inputs:

        spec - str; the path for the configuration file

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


    rendered_template = render_template(spec)
    spec = yaml.load(rendered_template)
    verify_spec(rendered_template, spec)

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
        module_sql = analyze_schemas(spec, cursor, verbose)
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
