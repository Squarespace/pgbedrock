from collections import defaultdict
import os

import cerberus
import jinja2
import yaml

from pgbedrock import common


DUPLICATE_ROLE_DEFINITIONS_ERR_MSG = 'Spec error: role(s) defined more than once: {}'
FILE_OPEN_ERROR_MSG = "Unable to open file '{}':\n{}"
MISSING_ENVVAR_MSG = "Required environment variable not found:\n{}"
MULTIPLE_SCHEMA_OWNER_ERR_MSG = 'Spec error: schema "{}" owned by more than one role: {}'
OBJECT_REF_READ_WRITE_ERR = (
    'Spec error: objects have been unnecessarily given both read and write privileges.'
    'pgbedrock automatically grants read access when write access is requested.\n\t{}'
)
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

    In a spec template, if a role is declared more than once there exists a risk that the
    re-declaration will override the desired configuration. pgbedrock considers a config containing
    this risk to be invalid and will throw an error.

    To accomplish this, the yaml.loader.Loader object is used to convert spec template into a
    document tree.  Then, the root object's child nodes (which are the roles) are checked for
    duplicates.

    Outputs a list of strings.

    The decision to return a list of strings was deliberate, despite the fact that the length of the
    list can at most be one. The reason for this is that the other spec verification functions
    (check_for_multi_schema_owners and check_read_write_obj_references, verify_schema) also return a
    list of strings.  This return signature consistency makes the code in the verify_spec function
    cleaner.
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


def load_spec(spec_path):
    rendered_template = render_template(spec_path)
    spec = yaml.load(rendered_template)
    verify_spec(rendered_template, spec)
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
