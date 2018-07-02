import logging

import click

from pgbedrock import common
from pgbedrock.context import DatabaseContext


logger = logging.getLogger(__name__)

Q_CREATE_SCHEMA = 'CREATE SCHEMA "{}" AUTHORIZATION "{}";'
Q_SET_SCHEMA_OWNER = 'ALTER SCHEMA "{}" OWNER TO "{}"; -- Previous owner: "{}"'
Q_SET_OBJECT_OWNER = 'ALTER {} {} OWNER TO "{}"; -- Previous owner: "{}"'


def analyze_ownerships(spec, cursor, verbose):
    logger.debug('Starting analyze_ownerships()')
    dbcontext = DatabaseContext(cursor, verbose)

    # We disable the progress bar when showing verbose output (using '' as our bar_template)
    # or # the bar will get lost in the # output
    bar_template = '' if verbose else common.PROGRESS_TEMPLATE
    with click.progressbar(spec.items(), label='Analyzing ownerships: ', bar_template=bar_template,
                           show_eta=False, item_show_func=common.item_show_func) as all_roles:
        all_sql_to_run = []
        for rolename, config in all_roles:
            if not config:
                continue

            if config.get('has_personal_schema'):
                objname = common.ObjectName.from_str(rolename)
                sql_to_run = SchemaAnalyzer(rolename=rolename, objname=objname,
                                            dbcontext=dbcontext, is_personal_schema=True).analyze()
                all_sql_to_run += sql_to_run

            ownerships = config.get('owns', {})
            for objkind, objects_to_own in ownerships.items():
                if objkind == 'schemas':
                    for objname in objects_to_own:
                        sql_to_run = SchemaAnalyzer(rolename=rolename, objname=objname,
                                                    dbcontext=dbcontext,
                                                    is_personal_schema=False).analyze()
                        all_sql_to_run += sql_to_run
                else:
                    for objname in objects_to_own:
                        sql_to_run = NonschemaAnalyzer(rolename=rolename, objname=objname,
                                                       objkind=objkind, dbcontext=dbcontext).analyze()
                        all_sql_to_run += sql_to_run

        return all_sql_to_run


class NonschemaAnalyzer(object):
    """
    Analyze one object and determine (via .analyze()) any SQL statements that are
    necessary to make sure that the object has the correct owner.

    If the objname is schema.* then ownership for each of the objects (of kind objkind)
    in that schema will be verified and changed if necessary.
    """
    def __init__(self, rolename, objname, objkind, dbcontext):
        """
        Args:
            rolename (str): The name of the role that should own the object(s)

            objname (common.ObjectName): The object(s) to analyze

            objkind (str): The type of object. This must be one of the keys of
                context.PRIVILEGE_MAP, e.g. 'schemas', 'tables', etc.

            dbcontext (context.DatabaseContext): A context.DatabaseContext instance for getting
                information for the associated database
        """
        self.rolename = rolename
        self.objname = objname
        self.objkind = objkind
        self.dbcontext = dbcontext
        self.sql_to_run = []

    def expand_schema_objects(self, schema):
        """ Get all non-dependent objects of kind objkind within the specified schema """
        all_objkind_objects = self.dbcontext.get_all_object_attributes().get(self.objkind, dict())
        schema_objects = all_objkind_objects.get(schema, dict())
        nondependent_objects = [objname for objname, attr in schema_objects.items() if not attr['is_dependent']]
        return nondependent_objects

    def analyze(self):
        if self.objname.unqualified_name == '*':
            objects_to_manage = self.expand_schema_objects(self.objname.schema)
        else:
            objects_to_manage = [self.objname]

        all_object_attributes = self.dbcontext.get_all_object_attributes()
        for objname in objects_to_manage:
            current_owner = all_object_attributes[self.objkind][self.objname.schema][objname]['owner']
            if current_owner != self.rolename:
                obj_kind_singular = self.objkind.upper()[:-1]
                query = Q_SET_OBJECT_OWNER.format(obj_kind_singular, objname.qualified_name,
                                                  self.rolename, current_owner)
                self.sql_to_run.append(query)

        return self.sql_to_run


class SchemaAnalyzer(object):
    """
    Analyze one schema and determine (via .analyze()) any SQL statements that are
    necessary to make sure that the schema exists, it has the correct owner, and if it is a
    personal schema that all objects in it (and that we track, i.e. the keys to the privileges.py
    modules's PRIVILEGE_MAP) are owned by the correct schema owner
    """
    def __init__(self, rolename, objname, dbcontext, is_personal_schema=False):
        """
        Args:
            rolename (str): The name of the role that should own the schema

            objname (common.ObjectName): The schema to analyze

            dbcontext (context.DatabaseContext): A context.DatabaseContext instance for getting
                information for the associated database

            is_personal_schemas (bool): Whether this is a personal schema
        """
        self.sql_to_run = []
        self.rolename = common.check_name(rolename)
        logger.debug('self.rolename set to {}'.format(self.rolename))
        self.objname = objname
        self.is_personal_schema = is_personal_schema

        self.current_owner = dbcontext.get_schema_owner(self.objname)
        self.schema_objects = dbcontext.get_schema_objects(self.objname)
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
        (objkind, common.ObjectName, current_owner) """
        objects = []
        for item in self.schema_objects:
            if item.owner != self.rolename and not item.is_dependent:
                objects.append((item.kind, item.objname, item.owner))
        return objects

    def alter_object_owner(self, objkind, objname, prev_owner):
        obj_kind_singular = objkind.upper()[:-1]
        query = Q_SET_OBJECT_OWNER.format(obj_kind_singular, objname.qualified_name,
                                          self.rolename, prev_owner)
        self.sql_to_run.append(query)

    def create_schema(self):
        query = Q_CREATE_SCHEMA.format(self.objname.qualified_name, self.rolename)
        self.sql_to_run.append(query)

    def set_owner(self):
        query = Q_SET_SCHEMA_OWNER.format(self.objname.qualified_name,
                                          self.rolename, self.current_owner)
        self.sql_to_run.append(query)
