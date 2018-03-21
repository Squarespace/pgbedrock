import logging

import click

from pgbedrock import common
from pgbedrock.context import DatabaseContext


logger = logging.getLogger(__name__)

SKIP_SUPERUSER_MEMBERSHIPS_MSG = '-- Skipping membership configuration for superuser "{}"'

Q_GRANT_MEMBERSHIP = 'GRANT "{}" TO "{}";'
Q_REVOKE_MEMBERSHIP = 'REVOKE "{}" FROM "{}";'


def analyze_memberships(spec, cursor, verbose):
    logger.debug('Starting analyze_memberships()')
    dbcontext = DatabaseContext(cursor, verbose)

    # We disable the progress bar when showing verbose output (using '' as our bar_template)
    # or # the bar will get lost in the # output
    bar_template = '' if verbose else common.PROGRESS_TEMPLATE
    with click.progressbar(spec.items(), label='Analyzing memberships:', bar_template=bar_template,
                           show_eta=False, item_show_func=common.item_show_func) as all_roles:
        all_sql_to_run = []
        for rolename, spec_config in all_roles:
            spec_config = spec_config or {}
            spec_memberships = set(spec_config.get('member_of', []))
            sql_to_run = MembershipAnalyzer(rolename, spec_memberships, dbcontext).analyze()
            all_sql_to_run += sql_to_run

    return all_sql_to_run


class MembershipAnalyzer(object):
    """ Analyze one role's memberships and determine (via .analyze()) any SQL statements
    that are necessary to make the memberships match the provided spec memberships.
    """

    def __init__(self, rolename, spec_memberships, dbcontext):
        self.sql_to_run = []
        self.rolename = common.check_name(rolename)
        logger.debug('self.rolename set to {}'.format(self.rolename))
        self.desired_memberships = spec_memberships

        self.current_memberships = dbcontext.get_role_memberships(rolename)
        self.is_superuser = dbcontext.is_superuser(rolename)

    def analyze(self):
        # Check if the role is a superuser. If so, configuring memberships
        # is meaningless since superusers bypass all checks
        if self.is_superuser:
            skip_msg = SKIP_SUPERUSER_MEMBERSHIPS_MSG.format(self.rolename)
            self.sql_to_run.append(skip_msg)

        else:
            # Get all memberships that we have but don't want and remove them
            memberships_to_revoke = self.current_memberships.difference(self.desired_memberships)
            for group in memberships_to_revoke:
                self.revoke_membership(group)

            # Get all memberships that we want but don't have and create them
            memberships_to_grant = self.desired_memberships.difference(self.current_memberships)
            for group in memberships_to_grant:
                self.grant_membership(group)

        return self.sql_to_run

    def grant_membership(self, group):
        query = Q_GRANT_MEMBERSHIP.format(group, self.rolename)
        self.sql_to_run.append(query)

    def revoke_membership(self, group):
        query = Q_REVOKE_MEMBERSHIP.format(group, self.rolename)
        self.sql_to_run.append(query)
