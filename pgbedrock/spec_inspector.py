from collections import defaultdict
import os

import cerberus
import jinja2
import yaml

from pgbedrock import common
from pgbedrock import context


DUPLICATE_ROLE_DEFINITIONS_ERR_MSG = 'Spec error: role(s) defined more than once: {}'
FILE_OPEN_ERROR_MSG = "Unable to open file '{}':\n{}"
MISSING_ENVVAR_MSG = "Required environment variable not found:\n{}"
MULTIPLE_SCHEMA_OWNER_ERR_MSG = 'Spec error: schema "{}" owned by more than one role: {}'
OBJECT_REF_READ_WRITE_ERR = (
    'Spec error: objects have been unnecessarily given both read and write privileges.'
    'pgbedrock automatically grants read access when write access is requested.\n\t{}'
)
UNDOCUMENTED_ROLES_MSG = ('Undocumented roles found: {}.\n'
                          'Please add these roles to the spec file or manually remove '
                          'them from the Postgres cluster')
UNOWNED_SCHEMAS_MSG = ('Schemas found in database with no owner in spec: {}.\n'
                       'Please add these schemas to the spec file or manually remove '
                       'them from the Postgres cluster')
VALIDATION_ERR_MSG = 'Spec error: role "{}", field "{}": {}'

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


def ensure_no_schema_owned_twice(spec):
    """ Check spec for schemas with multiple owners. """
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


def ensure_no_redundant_privileges(spec):
    """
    Verify objects aren't defined in both read and write privilege sections for a given role.
    """
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


def ensure_no_duplicate_roles(rendered_spec_template):
    """
    Ensure that no roles are declared multiple times.

    In a spec template, if a role is declared more than once there exists a risk that the
    re-declaration will override the desired configuration. pgbedrock considers a config containing
    this risk to be invalid and will throw an error.

    To accomplish this, the yaml.loader.Loader object is used to convert spec template into a
    document tree.  Then, the root object's child nodes (which are the roles) are checked for
    duplicates.

    Outputs a list of strings. The decision to return a list of strings was deliberate, despite the
    fact that the length of the list can at most be one. The reason for this is that the other spec
    verification functions also return a list of strings.  This return signature consistency makes
    the code in the verify_spec function cleaner.
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


def ensure_no_undocumented_roles(spec, dbcontext):
    """
    Ensure that all roles in the database are documented within the spec. This is done
    (vs. having pbedrock assume it should delete these roles) because the roles may own schemas,
    tables, functions, etc. There's enough going on that if the user just made a mistake by
    forgetting to add a role to their spec then we've caused serious damage; better to throw an
    error and ask the user to manually resolve this.
    """
    current_role_attributes = dbcontext.get_all_role_attributes()
    spec_roles = set(spec.keys())
    current_roles = set(current_role_attributes.keys())
    undocumented_roles = current_roles.difference(spec_roles)

    if undocumented_roles:
        undocumented_roles_fmtd = '"' + '", "'.join(sorted(undocumented_roles)) + '"'
        return [UNDOCUMENTED_ROLES_MSG.format(undocumented_roles_fmtd)]

    return []


def ensure_no_unowned_schemas(spec, dbcontext):
    """
    Ensure that all schemas in the database are documented within the spec. This is done
    (vs. having pgbedrock assume it should delete these schemas) because the schema likely contains
    tables, those tables may contain permissions, etc. There's enough going on that if the user
    just made a mistake by forgetting to add a schema to their spec we've caused serious damage;
    better to throw an error and ask the user to manually resolve this
    """
    current_schemas_and_owners = dbcontext.get_all_schemas_and_owners()
    current_schemas = set(current_schemas_and_owners.keys())
    spec_schemas = get_spec_schemas(spec)
    undocumented_schemas = current_schemas.difference(spec_schemas)
    if undocumented_schemas:
        undocumented_schemas_fmtd = '"' + '", "'.join(sorted(undocumented_schemas)) + '"'
        return [UNOWNED_SCHEMAS_MSG.format(undocumented_schemas_fmtd)]

    return []


def ensure_valid_schema(spec):
    """ Ensure spec has no schema errors """
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


def get_spec_schemas(spec):
    """ Get all personal and non-personal schemas defined in the spec file """
    spec_schemas = []
    for rolename, config in spec.items():
        config = config or {}
        spec_schemas.extend(config.get('owns', {}).get('schemas', []))

        if config.get('has_personal_schema'):
            spec_schemas.append(rolename)

    return set(spec_schemas)


def load_spec(spec_path, cursor, verbose, attributes, memberships, ownerships, privileges):
    """ Validate a spec passes various checks and, if so, return the loaded spec. """
    rendered_template = render_template(spec_path)
    spec = yaml.load(rendered_template)
    verify_spec(rendered_template, spec, cursor, verbose, attributes, memberships, ownerships,
                privileges)
    return spec


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


def verify_spec(rendered_template, spec, cursor, verbose, attributes, memberships, ownerships,
                privileges):
    assert isinstance(spec, dict)
    dbcontext = context.DatabaseContext(cursor, verbose)

    error_messages = []
    error_messages += ensure_valid_schema(spec)

    # Having all roles represented exactly once is critical for all submodules
    # so we check this regardless of which submodules are being used
    error_messages += ensure_no_duplicate_roles(rendered_template)
    error_messages += ensure_no_undocumented_roles(spec, dbcontext)

    if ownerships:
        error_messages += ensure_no_unowned_schemas(spec, dbcontext)
        for objkind in context.PRIVILEGE_MAP.keys():
            if objkind == 'schemas':
                error_messages += ensure_no_schema_owned_twice(spec)

    if privileges:
        error_messages += ensure_no_redundant_privileges(spec)

    if error_messages:
        common.fail('\n'.join(error_messages))
