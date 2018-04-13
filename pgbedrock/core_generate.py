import getpass
import logging

import psycopg2.extras
import yaml

from pgbedrock import LOG_FORMAT
from pgbedrock import common
from pgbedrock.context import DatabaseContext, PRIVILEGE_MAP
from pgbedrock.attributes import DEFAULT_ATTRIBUTES, COLUMN_NAME_TO_KEYWORD, is_valid_forever


logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


class FormattedDumper(yaml.Dumper):
    """
    A subclass of yaml's Dumper used to add a new line before each role definition and to ensure
    indentation is 4 spaces.

    Partly built using Jace Browning's example here:
        https://stackoverflow.com/questions/25108581/python-yaml-dump-bad-indentation
    """
    def increase_indent(self, flow=False, indentless=False):
        # Add a new line before each role definition
        if self.indent == 0:
            self.write_line_break()

        # In order to properly indent with 4 spaces in lists we need to override the
        # indentless setting
        return super(FormattedDumper, self).increase_indent(flow, indentless=False)


def add_attributes(spec, dbcontext):
    all_attributes = dbcontext.get_all_role_attributes()
    for rolename, attributes in all_attributes.items():
        role_values = {}

        if attributes.pop('rolcanlogin'):
            role_values['can_login'] = True

        if attributes.pop('rolsuper'):
            role_values['is_superuser'] = True

        nondefaults = remove_default_attributes(attributes)
        if nondefaults:
            nondefaults_list = nondefault_attributes_as_list(rolename, nondefaults)
            role_values['attributes'] = nondefaults_list

        spec[rolename] = role_values

    return spec


def add_memberships(spec, dbcontext):
    """ Add memberships to an existing spec """
    all_memberships = dbcontext.get_all_memberships()
    for member, group in all_memberships:
        if 'member_of' not in spec[member]:
            spec[member]['member_of'] = []
        spec[member]['member_of'].append(group)

    return spec


def add_ownerships(spec, dbcontext):
    """ Add object ownerships to an existing spec

    One set of assumptions is made here: if a schema's name is the same as its owner and that
    owner can login, then the schema is assumed to be a personal schema. This is an assumption
    though, and ithe implication is that when `pgbedrock configure` is run, if there are any
    objects in that schema that are not owned by the schema owner they will have their ownership
    changed (to be the same as the schema owner).
    """
    schemas_and_owners = dbcontext.get_all_schemas_and_owners()
    for schema, owner in schemas_and_owners.items():
        if schema == owner and spec[owner].get('can_login', False):
            # This is (assumed to be) a personal schema. See docstring for implications
            spec[owner]['has_personal_schema'] = True
        else:
            try:
                spec[owner]['owns']['schemas'].append(schema)
            except KeyError:
                spec[owner]['owns'] = {
                    'schemas': [schema]
                }

    return spec


def add_privileges(spec, dbcontext):
    """
    Add role privileges to the spec file
    """
    for role in spec.keys():
        role_privileges = {}
        for objkind in PRIVILEGE_MAP.keys():
            if objkind == 'schemas':
                schemas_privs = determine_schema_privileges(role, dbcontext)
                if schemas_privs:
                    role_privileges['schemas'] = schemas_privs

            else:
                obj_privs = {}
                writes, reads = determine_all_nonschema_privileges(role, objkind, dbcontext)

                if writes:
                    collapsed_writes = collapse_personal_schemas(role, writes, objkind, dbcontext)
                    obj_privs['write'] = sorted(collapsed_writes)

                if reads:
                    collapsed_reads = collapse_personal_schemas(role, reads, objkind, dbcontext)
                    obj_privs['read'] = sorted(collapsed_reads)

                if obj_privs:
                    role_privileges[objkind] = obj_privs

        if role_privileges:
            spec[role]['privileges'] = role_privileges

    return spec


def collapse_personal_schemas(role, objects, objkind, dbcontext):
    """ If all personal objects (e.g. 'roleA.*', 'roleB.*', etc.) are in
    objects, then replace them with 'personal_schemas.*'. We only verify that non-empty personal
    schemas are all present here. If so, we assume that the same behavior should be true for other
    personal schemas if / when they are populated.

    Note that this role's personal schema (if it exists) will not show up here at all as
    determine_all_nonschema_privileges() filters it out. That is ok and intended: once
    `pgbedrock configure` is run it will ensure that this role owns everything in its own
    personal schema """
    personal_schemas = dbcontext.get_all_personal_schemas()
    all_personal_schemas = set([schema + '.*' for schema in personal_schemas])

    if not all_personal_schemas:
        return objects

    non_empty_personal_schemas = set()
    for schema in personal_schemas:
        if schema != role and not dbcontext.is_schema_empty(schema, objkind):
            non_empty_personal_schemas.add(schema + '.*')

    if non_empty_personal_schemas.difference(objects) == set():
        objects.difference_update(all_personal_schemas)
        objects.add('personal_schemas.*')

    return objects


def determine_schema_privileges(role, dbcontext):
    """
    Identify and return two lists:
        1) a list of schemas this role can write to
        2) a list of schemas this role can read from

    If a role can write it to a schema is assumed it can read as well, so that schema will only
    show up in the write list. As a result of this, we determine schemas with write access first
    so we can exclude write schemas from the read schemas list.

    Note that in Postgres if you own a schema you will always have read (USAGE) access to that
    schema but you _may not_ have write (CREATE) access to it, though you do by default. Because
    this is confusing and non-intuitive, we will include schemas in the write section even if they
    are owned by this role (and because they are in the write section then they will also be granted
    read privileges as well).
    """
    # Make a copy of personal_schemas (by making a new set from it) as we will be mutating it
    personal_schemas = set(dbcontext.get_all_personal_schemas())

    # Get all schemas this role has write and read access to
    write_schemas_and_owners = dbcontext.get_role_current_nondefaults(role, 'schemas', 'write')
    read_schemas_and_owners = dbcontext.get_role_current_nondefaults(role,  'schemas', 'read')

    write_schemas = {s for s, _ in write_schemas_and_owners}
    read_schemas = {s for s, _ in read_schemas_and_owners}

    # Get all schemas owned by this role
    all_owned_schemas = dbcontext.get_all_schemas_and_owners()
    role_owned_schemas = {s for s, owner in all_owned_schemas.items() if owner == role}

    # Add all schemas owned by this role to the write and read schemas
    write_schemas.update(role_owned_schemas)
    read_schemas.update(role_owned_schemas)

    # Remove this role's personal schema if it exists
    write_schemas.difference_update({role})
    read_schemas.difference_update({role})
    personal_schemas.difference_update({role})

    # If all personal schemas are in write_schemas then replace them with 'personal_schemas'
    if personal_schemas and personal_schemas.difference(write_schemas) == set():
        write_schemas.difference_update(personal_schemas)
        write_schemas.add('personal_schemas')

    if personal_schemas and personal_schemas.difference(read_schemas) == set():
        read_schemas.difference_update(personal_schemas)
        read_schemas.add('personal_schemas')

    # Remove all schemas this role has write access to
    read_only_schemas = read_schemas.difference(write_schemas)

    schemas_privs = {}
    if write_schemas:
        schemas_privs['write'] = sorted(write_schemas)
    if read_only_schemas:
        schemas_privs['read'] = sorted(read_only_schemas)

    return schemas_privs


def determine_all_nonschema_privileges(role, objkind, dbcontext):
    all_writes = set()
    all_reads = set()

    for schema, owner in dbcontext.get_all_schemas_and_owners().items():
        # Skip this role's personal schema as we will be asserting upon running
        # pgbedrock that all objects in this schema are owned by this role
        if role == schema and role == owner:
            continue

        writes, reads = determine_nonschema_privileges_for_schema(role, objkind, schema, dbcontext)

        all_writes.update(writes)
        all_reads.update(reads)

    return all_writes, all_reads


def determine_nonschema_privileges_for_schema(role, objkind, schema, dbcontext):
    """
    Determine all non-schema privileges granted to a given role for all objects of objkind in
    the specified schema. Results will be returned as two sets: objects granted write access
    and objects granted read access.

    We explicitly start with writes because if a role has write access then pgbedrock will also
    grant it read access, meaning we won't need to grant that object a read. As a result, we have
    to start with writes first.

    If any write default privileges exist for this role x objkind x schema then we assume that write
    default privileges should be applied universally in this schema. This could definitely not be
    the case though. For example, because default privileges are scoped based on the grantor, it's
    possible that the role had write default privileges for things created by roleA but not for
    things created by roleB. pgbedrock is not fine-grained enough to handle a situation like this
    though, so if there is a write default privilege we just assume that this role should have
    default writes for all objects of objkind in this schema.

    Also note that we're lumping all write default privileges together. It is possible a role might
    have default privileges for UPDATE on all tables but no other write-level default privileges.
    Again, pgbedrock isn't meant to be this fine-grained: if it sees any write-level default
    privilege then it will identify this as a role that should get write default privileges, which
    means that this role will get _all_ write-level default privileges for that objkind in this
    schema.
    """
    # Get all objects of this objkind in this schema and which are not owned by this role
    objects_and_owners = dbcontext.get_schema_objects(schema)
    schema_objects = set()
    for entry in objects_and_owners:
        if entry.kind == objkind and entry.owner != role:
            schema_objects.add(entry.name)

    has_default_write = dbcontext.has_default_privilege(role, schema, objkind, 'write')
    all_writes = dbcontext.get_role_objects_with_access(role, schema, objkind, 'write')

    if has_default_write or (all_writes == schema_objects and all_writes != set()):
        # In the second condition, every object has a write privilege, so we assume that means
        # that this role should have default write privileges
        return set([schema + '.*']), set()

    # If we haven't returned yet then no write default privilege exists; we will have to
    # grant each write individually, meaning we also need to look at read privileges
    has_default_read = dbcontext.has_default_privilege(role, schema, objkind, 'read')
    all_reads = dbcontext.get_role_objects_with_access(role, schema, objkind, 'read')

    if has_default_read or (all_reads == schema_objects and all_reads != set()):
        # In the second condition, every object has a read privilege, so we assume that means
        # that this role should have default read privileges
        return all_writes, set([schema + '.*'])
    else:
        # We have to grant each read individually as well. Because a write will already grant
        # a read, we have to remove all write-granted objects from our read grants
        only_reads = all_reads.difference(all_writes)
        return all_writes, only_reads


def create_spec(host, port, user, password, dbname, role, verbose):
    db_connection = common.get_db_connection(host, port, dbname, user, password)
    # We will only be reading, so it is worth being safe here and ensuring that we can't write
    db_connection.set_session(readonly=True)
    cursor = db_connection.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if role:
        cursor.execute('SET ROLE=%(role)s', {'role': role})

    dbcontext = DatabaseContext(cursor, verbose)
    spec = initialize_spec(dbcontext)
    spec = add_attributes(spec, dbcontext)
    spec = add_memberships(spec, dbcontext)
    spec = add_ownerships(spec, dbcontext)
    spec = add_privileges(spec, dbcontext)

    return spec


def initialize_spec(dbcontext):
    """ Initialize the spec with each role having an empty dict """
    all_attributes = dbcontext.get_all_role_attributes()
    spec = {role: dict() for role in all_attributes.keys()}
    return spec


def nondefault_attributes_as_list(rolename, nondefaults):
    results = []
    for attr, val in nondefaults.items():
        if attr == 'rolvaliduntil':
            valid_until_date = str(val.date())
            results.append("VALID UNTIL '{}'".format(valid_until_date))
        elif attr == 'rolconnlimit':
            results.append('CONNECTION LIMIT {}'.format(val))
        elif attr == 'rolpassword':
            # We put a templated environment variable here instead of
            # rolpassword's val (which is just an md5 hash anyway)
            results.append('PASSWORD "{{{{ env[\'{}_PASSWORD\'] }}}}"'.format(rolename.upper()))
        else:
            keyword = COLUMN_NAME_TO_KEYWORD[attr]
            prefix = '' if val else 'NO'
            results.append(prefix + keyword)

    return results


def output_spec(spec):
    """ Send the YAML file to stdout after adding some customization to the YAML representation,
    namely:
        * Add a blank line between each role definition
        * Indent all items with 4 spaces
        * Convert None and empty Dicts to ''
    """

    def represent_dict(dumper, data):
        """
        Use '' for empty dicts. Based on Brice M. Dempsey's code here:
            https://stackoverflow.com/questions/5121931/in-python-how-can-you-load-yaml-mappings-as-ordereddicts
        """
        if data:
            return dumper.represent_dict(data)
        return dumper.represent_scalar('tag:yaml.org,2002:null', '')

    yaml.add_representer(dict, represent_dict)

    print(yaml.dump(spec, Dumper=FormattedDumper, default_flow_style=False, indent=4))


def remove_default_attributes(attributes):
    nondefaults = {}
    for attr, val in attributes.items():
        if attr == 'rolvaliduntil' and not is_valid_forever(val):
            nondefaults[attr] = val
        elif attr not in ('rolname', 'rolvaliduntil') and val != DEFAULT_ATTRIBUTES[attr]:
            nondefaults[attr] = val

    return nondefaults


def generate(host, port, user, password, dbname, prompt, role, verbose):
    """
    Generate a YAML spec that represents the role attributes, memberships, object ownerships,
    and privileges for all roles in a database.

    Note that roles and memberships are database cluster-wide settings, i.e. they are the same
    across multiple databases within a given Postgres instance. Object ownerships and privileges
    are specific to each individual database within a Postgres instance.

    Inputs:

        host - str; the database server host

        port - str; the database server port

        user - str; the database user name

        password - str; the database user's password

        dbname - str; the database to connect to and configure

        prompt - bool; whether to prompt for a password

        role - str; perform SET ROLE to this value prior to operation

        verbose - bool; whether to show all queries that are executed and all debug log
            messages during execution
    """
    if verbose:
        root_logger = logging.getLogger('')
        root_logger.setLevel(logging.DEBUG)

    if prompt:
        password = getpass.getpass()

    spec = create_spec(host, port, user, password, dbname, role, verbose)
    output_spec(spec)
