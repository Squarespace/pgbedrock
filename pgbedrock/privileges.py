import logging
import itertools

import click

from pgbedrock import common
from pgbedrock.context import DatabaseContext, PRIVILEGE_MAP


logger = logging.getLogger(__name__)


SKIP_SUPERUSER_PRIVILEGE_CONFIGURATION_MSG = '-- Skipping privilege configuration for superuser "{}"'
PERSONAL_SCHEMAS_ERROR_MSG = ("Unable to interpret reserved keyword 'personal_schemas' "
                              "for rolename '{}', object_kind '{}', access '{}'")
OBJECT_DOES_NOT_EXIST_ERROR_MSG = "{} '{}' requested for role \"{}\" does not exist"
OBJECTS_WITH_DEFAULTS = ('functions', 'tables', 'sequences', 'types')

Q_GRANT_NONDEFAULT = 'GRANT {} ON {} {} TO "{}";'
Q_REVOKE_NONDEFAULT = 'REVOKE {} ON {} {} FROM "{}";'
Q_GRANT_DEFAULT = """
    SET ROLE "{}";
    ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT {} ON {} TO "{}";
    RESET ROLE;
    """
Q_REVOKE_DEFAULT = """
    SET ROLE "{}";
    ALTER DEFAULT PRIVILEGES IN SCHEMA {} REVOKE {} ON {} FROM "{}";
    RESET ROLE;
    """


def analyze_privileges(spec, cursor, verbose):
    logger.debug('Starting analyze_privileges()')
    dbcontext = DatabaseContext(cursor, verbose)

    # We disable the progress bar when showing verbose output (using '' as our bar_template)
    # or # the bar will get lost in the # output
    bar_template = '' if verbose else common.PROGRESS_TEMPLATE
    with click.progressbar(spec.items(), label='Analyzing privileges: ', bar_template=bar_template,
                           show_eta=False, item_show_func=common.item_show_func) as all_roles:

        schema_writers = determine_schema_writers(spec)
        personal_schemas = determine_personal_schemas(spec)
        all_sql_to_run = []
        for rolename, config in all_roles:
            config = config or {}
            if dbcontext.is_superuser(rolename):
                all_sql_to_run.append(
                    SKIP_SUPERUSER_PRIVILEGE_CONFIGURATION_MSG.format(rolename)
                )
                continue
            all_desired_privs = config.get('privileges', {})

            for object_kind in PRIVILEGE_MAP.keys():
                desired_items_this_obj = all_desired_privs.get(object_kind, {})

                for access in ('read', 'write'):
                    desired_items = desired_items_this_obj.get(access, [])
                    # If a write privilege is desired then read access is as well
                    if access == 'read':
                        desired_items += desired_items_this_obj.get('write', [])

                    privconf = PrivilegeAnalyzer(rolename=rolename,
                                                 access=access,
                                                 object_kind=object_kind,
                                                 desired_items=desired_items,
                                                 dbcontext=dbcontext,
                                                 schema_writers=schema_writers,
                                                 personal_schemas=personal_schemas)
                    role_sql_to_run = privconf.analyze()
                    all_sql_to_run += role_sql_to_run

    return all_sql_to_run


def determine_role_members(spec):
    """ Create a dict mapping from each role to all direct and indirect members of that role """
    return {role: get_members(role, spec) for role in spec.keys()}


def get_members(group, spec):
    """ Get all members of a group role, whether they are direct members or
    indirect members (i.e. members of members of this role, etc.) """
    members = set()
    for role, config in spec.items():
        if config and group in config.get('member_of', ()):
            members.add(role)
            sub_members = get_members(role, spec)
            members.update(sub_members)

    return members


def determine_personal_schemas(spec):
    """
    Returns:
        set: A set of ObjectName instances of personal schemas
    """
    personal_schemas = set()
    for role, config in spec.items():
        if config and common.parse_bool(config.get('has_personal_schema', False)):
            personal_schemas.add(common.ObjectName(role))

    return personal_schemas


def determine_schema_owners(spec):
    """ Create a dict of {ObjectName(schema): owner} """
    schema_owners = dict()
    for role, config in spec.items():
        if not config:
            continue

        if 'owns' in config:
            owned_schemas = config['owns'].get('schemas', ())
            for schema in owned_schemas:
                schema_owners[schema] = role

        if common.parse_bool(config.get('has_personal_schema', False)):
            schema_owners[common.ObjectName(role)] = role

    return schema_owners


def determine_superusers(spec):
    superusers = set()
    for role, config in spec.items():
        if not config:
            continue

        if common.parse_bool(config.get('is_superuser', False)):
            superusers.add(role)

    return superusers


def determine_schema_writers(spec):
    """
    Create a dict mapping from each schema to all roles that can create objects in that
    schema, i.e.:

    Returns:
        dict: A dict of the form {common.ObjectName(schema): [roleA, roleB, roleC], ...}
    """
    members_of_role = determine_role_members(spec)
    personal_schemas = determine_personal_schemas(spec)
    schema_owners = determine_schema_owners(spec)

    # At a minimum, the schema owner could conceivably create objects
    writers = {schema: set([owner]) for schema, owner in schema_owners.items()}

    for role, config in spec.items():
        try:
            writable_schemas = set(config['privileges']['schemas']['write']) if config else set()
        except KeyError:
            writable_schemas = set()

        if common.ObjectName('personal_schemas') in writable_schemas:
            writable_schemas.remove(common.ObjectName('personal_schemas'))
            writable_schemas.update(personal_schemas)

        for schema in writable_schemas:
            writers[schema].add(role)
            role_members = members_of_role[role]
            writers[schema].update(role_members)

    # Superusers can write in any schema
    superusers = determine_superusers(spec)
    for vals in writers.values():
        vals.update(superusers)

    return writers


class PrivilegeAnalyzer(object):
    """ Analyze the privileges for one combination of role x access type x object kind (e.g.
    read-level table privileges for myrole1). Analysis is done via the .analyze() method
    and generates a set of SQL statements necessary to make the database match the desired
    set of items.
    """

    def __init__(self, rolename, access, object_kind, desired_items, schema_writers,
                 personal_schemas, dbcontext):
        log_msg = 'Initializing PrivilegeAnalyzer for rolename "{}", access "{}", and object "{}"'
        logger.debug(log_msg.format(rolename, access, object_kind))
        self.sql_to_run = []
        self.rolename = common.check_name(rolename)

        self.access = access
        self.object_kind = object_kind
        self.desired_items = desired_items
        self.schema_writers = schema_writers
        self.personal_schemas = personal_schemas
        self.default_acl_possible = self.object_kind in OBJECTS_WITH_DEFAULTS

        self.current_defaults = dbcontext.get_role_current_defaults(rolename, object_kind, access)
        self.current_nondefaults = dbcontext.get_role_current_nondefaults(rolename, object_kind, access)

        self.all_object_attrs = dbcontext.get_all_object_attributes()

    def analyze(self):
        self.identify_desired_objects()
        self.analyze_nondefaults()

        if self.default_acl_possible:
            self.analyze_defaults()

        return self.sql_to_run

    def analyze_defaults(self):
        """ Analyze default privileges. Note that we sort the grants / revokes before issuing
        them so the output will be more organized, making it easier for the end user to read """
        defaults_to_grant = self.desired_defaults.difference(self.current_defaults)
        logger.debug('defaults_to_grant: {}'.format(defaults_to_grant))
        for grantor, schema, pg_priv_kind in sorted(defaults_to_grant):
            self.grant_default(grantor, schema, pg_priv_kind)

        defaults_to_revoke = self.current_defaults.difference(self.desired_defaults)
        logger.debug('defaults_to_revoke: {}'.format(defaults_to_revoke))
        for grantor, schema, pg_priv_kind in sorted(defaults_to_revoke):
            self.revoke_default(grantor, schema, pg_priv_kind)

    def analyze_nondefaults(self):
        """ Analyze non-default privileges. Note that we sort the grants / revokes before issuing
        them so the output will be more organized, making it easier for the end user to read """
        nondefaults_to_grant = self.desired_nondefaults.difference(self.current_nondefaults)
        logger.debug('nondefaults_to_grant: {}'.format(nondefaults_to_grant))
        if nondefaults_to_grant:
            for objname, pg_priv_kind in sorted(nondefaults_to_grant):
                self.grant_nondefault(objname, pg_priv_kind)

        nondefaults_to_revoke = self.current_nondefaults.difference(self.desired_nondefaults)
        logger.debug('nondefaults_to_revoke: {}'.format(nondefaults_to_revoke))
        if nondefaults_to_revoke:
            for objname, pg_priv_kind in sorted(nondefaults_to_revoke):
                self.revoke_nondefault(objname, pg_priv_kind)

    def determine_desired_defaults(self, schemas):
        """
        For any given schema, we want to grant default privileges to this role from each role
        that can write in that schema. We cross this against all privilege types.

        Args:
            schemas (set): A set of common.ObjectNames instances representing schemas
        """
        self.desired_defaults = set()
        for schema in schemas:
            writers = self.schema_writers[schema]
            for writer in writers:
                # We don't need to grant default privileges for things this role will create
                if writer == self.rolename:
                    continue
                for pg_priv_kind in PRIVILEGE_MAP[self.object_kind][self.access]:
                    self.desired_defaults.add(tuple([writer, schema, pg_priv_kind]))

    def get_object_owner(self, objname, objkind=None):
        objkind = objkind or self.object_kind
        object_owners = self.all_object_attrs.get(objkind, dict()).get(objname.schema, dict())
        owner = object_owners.get(objname, dict()).get('owner', None)
        if owner:
            return owner
        else:
            obj_kind_singular = objkind[:-1]
            common.fail(OBJECT_DOES_NOT_EXIST_ERROR_MSG.format(obj_kind_singular,
                                                               objname.qualified_name,
                                                               self.rolename))

    def get_schema_objects(self, schema):
        """ Get all objects of kind self.object_kind which are in the given schema and not owned by
        self.rolename """
        object_owners = self.all_object_attrs.get(self.object_kind, dict()).get(schema, dict())
        return {objname for objname, attr in object_owners.items() if attr['owner'] != self.rolename}

    def grant_default(self, grantor, schema, privilege):
        query = Q_GRANT_DEFAULT.format(grantor, schema.qualified_name, privilege,
                                       self.object_kind.upper(), self.rolename)
        self.sql_to_run.append(query)

    def grant_nondefault(self, objname, privilege):
        obj_kind_singular = self.object_kind.upper()[:-1]
        query = Q_GRANT_NONDEFAULT.format(privilege, obj_kind_singular,
                                          objname.qualified_name, self.rolename)
        self.sql_to_run.append(query)

    def identify_desired_objects(self):
        """
        Create the sets of desired privileges. The sets will look like the following:

            self.desired_nondefaults:
                {(ObjectName(schema, unqualified_name), priv_name), ...}
                Example: {('myschema.mytable', 'SELECT'), ...}

            self.desired_defaults:
                {(grantor, schema, priv_name), ...}
                Example: {('svc-hr-etl', 'hr_schema', 'SELECT'), ...}
        """
        desired_nondefault_objs = set()
        schemas = []
        for objname in self.desired_items:
            if objname == common.ObjectName('personal_schemas') and self.object_kind == 'schemas':
                desired_nondefault_objs.update(self.personal_schemas)
            elif objname == common.ObjectName('personal_schemas') and self.object_kind != 'schemas':
                # The end-user is asking something impossible
                common.fail(PERSONAL_SCHEMAS_ERROR_MSG.format(self.rolename, self.object_kind, self.access))
            elif objname == common.ObjectName('personal_schemas', '*'):
                schemas.extend(self.personal_schemas)
            elif objname.unqualified_name != '*':
                # This is a single non-default privilege ask
                owner = self.get_object_owner(objname)
                if owner != self.rolename:
                    desired_nondefault_objs.add(objname)
            else:
                # We were given a schema.*; we'll process those below
                schemas.append(objname.only_schema())

        for schema in schemas:
            # For schemas, we wish to have privileges for all existing objects, so get all
            # existing objects not owned by this role and add them to self.desired_nondefaults
            schema_objects = self.get_schema_objects(schema.qualified_name)
            desired_nondefault_objs.update(schema_objects)

        # Cross our desired objects with the desired privileges
        priv_types = PRIVILEGE_MAP[self.object_kind][self.access]
        self.desired_nondefaults = set(itertools.product(desired_nondefault_objs, priv_types))

        if self.default_acl_possible:
            self.determine_desired_defaults(schemas)

    def revoke_default(self, grantor, schema, privilege):
        query = Q_REVOKE_DEFAULT.format(grantor, schema.qualified_name, privilege,
                                        self.object_kind.upper(), self.rolename)
        self.sql_to_run.append(query)

    def revoke_nondefault(self, objname, privilege):
        obj_kind_singular = self.object_kind.upper()[:-1]
        query = Q_REVOKE_NONDEFAULT.format(privilege, obj_kind_singular,
                                           objname.qualified_name, self.rolename)
        self.sql_to_run.append(query)
