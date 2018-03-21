import copy
import logging

import click

from pgbedrock import common
from pgbedrock.context import DatabaseContext


logger = logging.getLogger(__name__)

UNDOCUMENTED_SCHEMAS_MSG = ('Undocumented schemas found: {}.\n'
                            'Please add these schemas to the spec file or manually remove '
                            'them from the Postgres cluster')

Q_CREATE_SCHEMA = 'CREATE SCHEMA "{}" AUTHORIZATION "{}";'
Q_SET_SCHEMA_OWNER = 'ALTER SCHEMA "{}" OWNER TO "{}"; -- Previous owner: "{}"'
Q_SET_OBJECT_OWNER = 'ALTER {} {} OWNER TO "{}"; -- Previous owner: "{}"'


def analyze_schemas(spec, cursor, verbose):
    logger.debug('Starting analyze_schemas()')
    dbcontext = DatabaseContext(cursor, verbose)
    fail_if_undocumented_schemas(spec, dbcontext)

    # We disable the progress bar when showing verbose output (using '' as our bar_template)
    # or # the bar will get lost in the # output
    bar_template = '' if verbose else common.PROGRESS_TEMPLATE
    with click.progressbar(spec.items(), label='Analyzing schemas:    ', bar_template=bar_template,
                           show_eta=False, item_show_func=common.item_show_func) as all_roles:
        all_sql_to_run = []
        for rolename, config in all_roles:
            config = config or {}
            ownership = config.get('owns', {})
            schemas = copy.deepcopy(ownership.get('schemas', []))
            has_personal_schema = config.get('has_personal_schema')
            if has_personal_schema:
                schemas.append(rolename)

            for schema in schemas:
                is_personal_schema = (has_personal_schema and (schema == rolename))
                sql_to_run = SchemaAnalyzer(rolename, schema, dbcontext=dbcontext,
                                            is_personal_schema=is_personal_schema).analyze()
                all_sql_to_run += sql_to_run

        return all_sql_to_run


def fail_if_undocumented_schemas(spec, dbcontext):
    """
    Refuse to continue if schemas are in the database but are not documented in spec. This is done
    (vs. just deleting the schemas programmatically) because the schema likely contains tables,
    those tables may contain permissions, etc. There's enough going on that if the user just made
    a mistake by forgetting to add a schema to their spec we've caused serious damage; better to
    ask them to manually resolve this
    """
    current_schemas_and_owners = dbcontext.get_all_schemas_and_owners()
    current_schemas = set(current_schemas_and_owners.keys())
    spec_schemas = get_spec_schemas(spec)
    undocumented_schemas = current_schemas.difference(spec_schemas)
    if undocumented_schemas:
        undocumented_schemas_fmtd = '"' + '", "'.join(sorted(undocumented_schemas)) + '"'
        common.fail(msg=UNDOCUMENTED_SCHEMAS_MSG.format(undocumented_schemas_fmtd))


def get_spec_schemas(spec):
    """ Get all personal and non-personal schemas defined in the spec file """
    spec_schemas = []
    for rolename, config in spec.items():
        config = config or {}
        spec_schemas.extend(config.get('owns', {}).get('schemas', []))

        if config.get('has_personal_schema'):
            spec_schemas.append(rolename)

    return set(spec_schemas)


class SchemaAnalyzer(object):
    """ Analyze one schema and determine (via .analyze()) any SQL statements that are
    necessary to make sure that the schema exists, it has the correct owner, and if it is a
    personal schema that all objects in it (and that we track, i.e. the keys to the privileges.py
    modules's PRIVILEGE_MAP) are owned by the correct schema owner """

    def __init__(self, rolename, schema, dbcontext, is_personal_schema=False):
        self.sql_to_run = []
        self.rolename = common.check_name(rolename)
        logger.debug('self.rolename set to {}'.format(self.rolename))
        self.schema = schema
        self.is_personal_schema = is_personal_schema

        self.current_owner = dbcontext.get_schema_owner(schema)
        self.schema_objects = dbcontext.get_schema_objects(schema)
        # If there is no owner then the schema must not exist yet
        self.exists = self.current_owner is not None

    def analyze(self):
        if not self.exists:
            self.create_schema()
        elif self.current_owner != self.rolename:
            self.set_owner()

        if self.is_personal_schema:
            # Make it true that all tables in the personal schema are owned by the schema owner
            objects_to_change = self.get_improperly_owned_objects()
            for objkind, objname, prev_owner in objects_to_change:
                self.alter_object_owner(objkind, objname, prev_owner)

        return self.sql_to_run

    def get_improperly_owned_objects(self):
        """ Return all objects that are not owned by this schema's owner and which are not
        auto-dependent (i.e. a sequence that is linked to a table, in which case its ownership
        derives from that linked table). Note that we only look at objects supported by pgbedrock
        (i.e. tables and sequences). Each entry returned is a tuple of the form
        (objkind, objname, current_owner) """
        objects = []
        for item in self.schema_objects:
            if item.owner != self.rolename and not item.is_dependent:
                objects.append((item.kind, item.name, item.owner))
        return objects

    def alter_object_owner(self, objkind, objname, prev_owner):
        obj_kind_singular = objkind.upper()[:-1]
        query = Q_SET_OBJECT_OWNER.format(obj_kind_singular, objname, self.rolename, prev_owner)
        self.sql_to_run.append(query)

    def create_schema(self):
        query = Q_CREATE_SCHEMA.format(self.schema, self.rolename)
        self.sql_to_run.append(query)

    def set_owner(self):
        query = Q_SET_SCHEMA_OWNER.format(self.schema, self.rolename, self.current_owner)
        self.sql_to_run.append(query)
