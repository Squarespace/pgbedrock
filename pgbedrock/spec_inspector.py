from collections import defaultdict
import copy
import os

import cerberus
import jinja2
import yaml

from pgbedrock import common
from pgbedrock import context

DEPENDENT_OBJECTS_MSG = ('Spec error: Ownership listed for dependent {objkind}: {dep_objs}\n'
                         'Ownership for a dependent object derives from the object is depends '
                         'on. Please remove these objects from the ownership sections within '
                         'your spec file')
DUPLICATE_ROLE_DEFINITIONS_ERR_MSG = 'Spec error: Role(s) defined more than once: {}'
FILE_OPEN_ERROR_MSG = "Unable to open file '{}':\n{}"
MISSING_ENVVAR_MSG = "Spec error: Required environment variable not found:\n{}"
MULTIPLE_SCHEMA_OWNER_ERR_MSG = 'Spec error: Schema "{}" owned by multiple roles: {}'
MULTIPLE_OBJKIND_OWNER_ERR_MSG = 'Spec error: {} "{}" owned by multiple roles: {}'
OBJECT_REF_READ_WRITE_ERR = (
    'Spec error: objects have been unnecessarily given both read and write privileges.'
    'pgbedrock automatically grants read access when write access is requested.{}'
)
UNKNOWN_OBJECTS_MSG = ('Spec error: Unknown {objkind} found: {unknown_objects}\n'
                       'Please manually add these {objkind} to the database or '
                       'remove them from the spec file')
UNOWNED_OBJECTS_MSG = ('Spec error: Unowned {objkind} found: {unowned_objects}\n'
                       'Please add these {objkind} to the spec file or manually remove '
                       'them from the Postgres cluster')
UNDOCUMENTED_ROLES_MSG = ('Spec error: Undocumented roles found: {}.\n'
                          'Please add these roles to the spec file or manually remove '
                          'them from the Postgres cluster')
UNOWNED_SCHEMAS_MSG = ('Spec error: Schemas found in database with no owner in spec: {}\n'
                       'Please add these schemas to the spec file or manually remove '
                       'them from the Postgres cluster')
VALIDATION_ERR_MSG = 'Spec error: Role "{}", field "{}": {}'

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
    owns:
        type: dict
        allowed:
            - schemas
            - tables
            - sequences
        valueschema:
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
    """


def convert_spec_to_objectnames(spec):
    """ Convert object names in a loaded spec from strings to ObjectName instances

    This converts items in the following sublists, if those sublists exist:
        * <role_name> -> owns -> <key in context.PRIVILEGE_MAP>
        * <role_name> -> privileges -> <key in context.PRIVILEGE_MAP> -> read
        * <role_name> -> privileges -> <key in context.PRIVILEGE_MAP> -> write
    """
    output_spec = copy.deepcopy(spec)
    for role, config in output_spec.items():
        if not config:
            continue

        for objkind, owned_items in config.get('owns', {}).items():
            if not owned_items:
                continue
            converted = [common.ObjectName.from_str(item) for item in owned_items]
            config['owns'][objkind] = converted

        for objkind, perm_dicts in config.get('privileges', {}).items():
            for priv_kind, granted_items in perm_dicts.items():
                if not granted_items:
                    continue
                converted = [common.ObjectName.from_str(item) for item in granted_items]
                config['privileges'][objkind][priv_kind] = converted

    return output_spec


def ensure_no_object_owned_twice(spec, dbcontext, objkind):
    """ Check spec for objects of objkind with multiple owners. """
    all_db_objects = dbcontext.get_all_object_attributes().get(objkind, dict())

    object_ownerships = defaultdict(list)
    for rolename, config in spec.items():
        if not config:
            continue

        if config.get('has_personal_schema'):
            schema_objects = all_db_objects.get(rolename, dict())
            nondependent_objects = [name for name, attr in schema_objects.items() if not attr['is_dependent']]
            for obj in nondependent_objects:
                object_ownerships[obj].append(rolename)

        if not config.get('owns') or not config['owns'].get(objkind):
            continue

        role_owned_objects = config['owns'][objkind]
        for objname in role_owned_objects:
            if objname.unqualified_name == '*':
                schema_objects = all_db_objects.get(objname.schema, dict())
                nondependent_objects = [name for name, attr in schema_objects.items() if not attr['is_dependent']]
                for obj in nondependent_objects:
                    object_ownerships[obj].append(rolename)
            else:
                object_ownerships[objname].append(rolename)

    error_messages = []
    for objname, owners in object_ownerships.items():
        if len(owners) > 1:
            owners_formatted = ", ".join(sorted(owners))
            error_messages.append(MULTIPLE_OBJKIND_OWNER_ERR_MSG.format(objkind[:-1].capitalize(),
                                                                        objname.qualified_name,
                                                                        owners_formatted))

    return error_messages


def ensure_no_schema_owned_twice(spec):
    """ Check spec for schemas with multiple owners. """
    schema_ownerships = defaultdict(list)
    for rolename, config in spec.items():
        if not config:
            continue
        if config.get('has_personal_schema'):
            # Indicates a role has a personal schema with its same name
            schema_ownerships[common.ObjectName(rolename)].append(rolename)
        if config.get('owns') and config['owns'].get('schemas'):
            role_owned_schemas = config['owns']['schemas']
            for schema in role_owned_schemas:
                schema_ownerships[schema].append(rolename)

    error_messages = []
    for schema, owners in schema_ownerships.items():
        if len(owners) > 1:
            owners_formatted = ", ".join(sorted(owners))
            error_messages.append(MULTIPLE_SCHEMA_OWNER_ERR_MSG.format(schema.qualified_name,
                                                                       owners_formatted))

    return error_messages


def ensure_no_redundant_privileges(spec):
    """
    Verify objects aren't defined in both read and write privilege sections for a given role.
    """
    multi_refs = defaultdict(dict)
    for rolename, config in spec.items():
        if config and config.get('privileges'):
            for obj in config['privileges']:
                try:
                    reads = set(config['privileges'][obj]['read'])
                    writes = set(config['privileges'][obj]['write'])
                    duplicates = reads.intersection(writes)
                    if duplicates:
                        multi_refs[rolename][obj] = list(duplicates)
                except KeyError:
                    continue

    if multi_refs:
        # Convert ObjectNames back to strings to print out in the error message
        for rolename, mapped_duplicates in multi_refs.items():
            for objkind, duplicate_objects in mapped_duplicates.items():
                multi_refs[rolename][objkind] = [dup.qualified_name for dup in duplicate_objects]

        multi_ref_strings = ["%s: %s" % (k, v) for k, v in multi_refs.items()]
        multi_ref_err_string = "\n\t".join(multi_ref_strings)
        return [OBJECT_REF_READ_WRITE_ERR.format(multi_ref_err_string)]

    return []


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
    loader = yaml.loader.Loader(rendered_spec_template)
    document_tree = loader.get_single_node()
    if document_tree is None:
        return None

    role_definitions = defaultdict(int)
    for node in document_tree.value:
        role_definitions[node[0].value] += 1
    multi_defined_roles = [k for k, v in role_definitions.items() if v > 1]
    if multi_defined_roles:
        multi_roles_fmtd = " ,".join(multi_defined_roles)
        return [DUPLICATE_ROLE_DEFINITIONS_ERR_MSG.format(multi_roles_fmtd)]

    return []


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


def ensure_no_missing_objects(spec, dbcontext, objkind):
    """
    Ensure that all objects of kind objkind in the database are documented within the spec, and
    vice versa. This is done for two reasons:

    Object defined in database but not in spec
        In this case, pgbedrock could delete the object, but this is hard-to-reverse. If the user
        happened to just forget to document something then a table could be dropped, etc. It's
        better to throw an error and ask the user to manually resolve this.

    Object defined in spec but not in database
        Similarly, if a object is defined in the spec but not in the database it is unclear what
        pgbedrock should do. It can't create the object as it doesn't know the DDL that the object
        should have. The only real option here is to alert the user to the mismatch and ask them to
        resolve it.
    """
    db_objects = set()
    for obj in dbcontext.get_all_raw_object_attributes():
        if obj.kind == objkind and not obj.is_dependent:
            db_objects.add(obj.objname)

    db_objects_by_schema = dbcontext.get_all_object_attributes().get(objkind, dict())
    spec_objects = set()
    for rolename, config in spec.items():
        if not config:
            continue

        if config.get('has_personal_schema'):
            schema_objects = db_objects_by_schema.get(rolename, dict())
            nondependent_objects = [name for name, attr in schema_objects.items() if not attr['is_dependent']]
            for obj in nondependent_objects:
                spec_objects.add(obj)

        if not config.get('owns') or not config['owns'].get(objkind):
            continue

        role_owned_objects = config['owns'][objkind]
        for objname in role_owned_objects:
            if objname.unqualified_name == '*':
                schema_objects = db_objects_by_schema.get(objname.schema, dict())
                nondependent_objects = [name for name, attr in schema_objects.items() if not attr['is_dependent']]
                for obj in nondependent_objects:
                    spec_objects.add(obj)
            else:
                spec_objects.add(objname)

    error_messages = []

    not_in_db = spec_objects.difference(db_objects)
    if not_in_db:
        qualified_names = [objname.qualified_name for objname in not_in_db]
        unknown_objects = ', '.join(sorted(qualified_names))
        msg = UNKNOWN_OBJECTS_MSG.format(objkind=objkind, unknown_objects=unknown_objects)
        error_messages.append(msg)

    not_in_spec = db_objects.difference(spec_objects)
    if not_in_spec:
        qualified_names = [objname.qualified_name for objname in not_in_spec]
        unowned_objects = ', '.join(sorted(qualified_names))
        msg = UNOWNED_OBJECTS_MSG.format(objkind=objkind, unowned_objects=unowned_objects)
        error_messages.append(msg)

    return error_messages


def ensure_no_unowned_schemas(spec, dbcontext):
    """
    Ensure that all schemas in the database are documented within the spec. This is done
    (vs. having pgbedrock assume it should delete these schemas) because the schema likely contains
    tables, those tables may contain permissions, etc. There's enough going on that if the user
    just made a mistake by forgetting to add a schema to their spec we've caused serious damage;
    better to throw an error and ask the user to manually resolve this
    """
    current_schemas_and_owners = dbcontext.get_all_schemas_and_owners()
    current_schemas = set(objname for objname in current_schemas_and_owners.keys())
    spec_schemas = get_spec_schemas(spec)
    undocumented_schemas = current_schemas.difference(spec_schemas)
    if undocumented_schemas:
        schema_names = [objname.qualified_name for objname in undocumented_schemas]
        undocumented_schemas_fmtd = '"' + '", "'.join(sorted(schema_names)) + '"'
        return [UNOWNED_SCHEMAS_MSG.format(undocumented_schemas_fmtd)]

    return []


def ensure_no_dependent_object_is_owned(spec, dbcontext, objkind):
    all_db_objects = dbcontext.get_all_object_attributes().get(objkind, dict())
    owned_dependent_objects = []
    for rolename, config in spec.items():
        if not config or not config.get('owns') or not config['owns'].get(objkind):
            continue

        role_owned_objects = config['owns'][objkind]
        for objname in role_owned_objects:
            if objname.unqualified_name == '*':
                continue

            try:
                obj_is_dependent = all_db_objects[objname.schema][objname]['is_dependent']
            except KeyError:
                # This object is missing in the db; that condition already being checked elsewhere
                continue

            if obj_is_dependent:
                owned_dependent_objects.append(objname)

    if owned_dependent_objects:
        qualified_names = [objname.qualified_name for objname in owned_dependent_objects]
        dep_objs = ', '.join(sorted(qualified_names))
        msg = DEPENDENT_OBJECTS_MSG.format(objkind=objkind, dep_objs=dep_objs)
        return [msg]

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
            spec_schemas.append(common.ObjectName(rolename))

    return set(spec_schemas)


def load_spec(spec_path, cursor, verbose, attributes, memberships, ownerships, privileges):
    """ Validate a spec passes various checks and, if so, return the loaded spec. """
    rendered_template = render_template(spec_path)
    unconverted_spec = yaml.load(rendered_template)

    # Validate the schema before verifying anything else about the spec. If the spec is invalid
    # then other checks may fail in erratic ways, so it is better to error out here
    error_messages = ensure_valid_schema(unconverted_spec)
    if error_messages:
        common.fail('\n'.join(error_messages))

    spec = convert_spec_to_objectnames(unconverted_spec)
    verify_spec(rendered_template, spec, cursor, verbose, attributes, memberships,
                ownerships, privileges)
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

    # Having all roles represented exactly once is critical for all submodules
    # so we check this regardless of which submodules are being used
    error_messages += ensure_no_duplicate_roles(rendered_template)
    error_messages += ensure_no_undocumented_roles(spec, dbcontext)

    if ownerships:
        for objkind in context.PRIVILEGE_MAP.keys():
            if objkind == 'schemas':
                error_messages += ensure_no_unowned_schemas(spec, dbcontext)
                error_messages += ensure_no_schema_owned_twice(spec)
            else:
                # We run each of these functions once per object kind as it is possible that
                # two objects of different kinds could have the same name in the same schema
                error_messages += ensure_no_missing_objects(spec, dbcontext, objkind)
                error_messages += ensure_no_object_owned_twice(spec, dbcontext, objkind)
                error_messages += ensure_no_dependent_object_is_owned(spec, dbcontext, objkind)

    if privileges:
        error_messages += ensure_no_redundant_privileges(spec)

    if error_messages:
        common.fail('\n'.join(error_messages))
