from conftest import run_setup_sql
from pgbedrock import memberships as memb
from pgbedrock import attributes


ROLE1 = 'charlie'
ROLE2 = 'barney'
ROLE3 = 'wacko'
DESIRED_GROUP1 = 'desired_group1'
DESIRED_GROUP2 = 'desired_group2'
CURRENT_GROUP1 = 'current_group1'
CURRENT_GROUP2 = 'current_group2'

Q_HAS_ROLE = "SELECT pg_has_role('{}', '{}', 'member')"
DUMMY = 'foo'


@run_setup_sql([
    attributes.Q_CREATE_ROLE.format(ROLE1),
    attributes.Q_CREATE_ROLE.format(ROLE2),
    attributes.Q_CREATE_ROLE.format(ROLE3),
    attributes.Q_CREATE_ROLE.format(CURRENT_GROUP1),
    attributes.Q_CREATE_ROLE.format(DESIRED_GROUP1),
    attributes.Q_CREATE_ROLE.format(DESIRED_GROUP2),
    attributes.Q_ALTER_ROLE_WITH.format(ROLE1, 'SUPERUSER'),
    memb.Q_GRANT_MEMBERSHIP.format(CURRENT_GROUP1, ROLE3),
])
def test_analyze_memberships(cursor):
    """
    Test:
        * one superuser (to make sure they don't get evaluated)
        * two users, both of which will be removed from a group and added to a group
    """
    spec = {
        ROLE1: {'member_of': [DESIRED_GROUP1]},
        ROLE2: {'member_of': [DESIRED_GROUP1, DESIRED_GROUP2]},
        ROLE3: {'member_of': [DESIRED_GROUP1]}
    }

    expected = set([
        memb.SKIP_SUPERUSER_MEMBERSHIPS_MSG.format(ROLE1),
        memb.Q_GRANT_MEMBERSHIP.format(DESIRED_GROUP1, ROLE2),
        memb.Q_GRANT_MEMBERSHIP.format(DESIRED_GROUP2, ROLE2),
        memb.Q_GRANT_MEMBERSHIP.format(DESIRED_GROUP1, ROLE3),
        memb.Q_REVOKE_MEMBERSHIP.format(CURRENT_GROUP1, ROLE3),
    ])

    actual = memb.analyze_memberships(spec, cursor, verbose=False)
    assert set(actual) == expected


def test_analyze_no_desired_memberships_none_current(mockdbcontext):
    mockdbcontext.is_superuser = lambda x: False
    mockdbcontext.get_role_memberships = lambda x: set()
    memberships_ = set()

    actual = memb.MembershipAnalyzer(ROLE1, spec_memberships=memberships_,
                                     dbcontext=mockdbcontext).analyze()
    assert actual == []


def test_analyze_none_current_some_desired(mockdbcontext):
    mockdbcontext.is_superuser = lambda x: False
    mockdbcontext.get_role_memberships = lambda x: set()
    desired_groups = set([DESIRED_GROUP1, DESIRED_GROUP2])
    expected = set([
        memb.Q_GRANT_MEMBERSHIP.format(DESIRED_GROUP1, ROLE1),
        memb.Q_GRANT_MEMBERSHIP.format(DESIRED_GROUP2, ROLE1),
    ])

    actual = memb.MembershipAnalyzer(ROLE1, spec_memberships=desired_groups,
                                     dbcontext=mockdbcontext).analyze()
    assert set(actual) == expected


def test_analyze_some_current_none_desired(mockdbcontext):
    mockdbcontext.is_superuser = lambda x: False
    mockdbcontext.get_role_memberships = lambda x: set([CURRENT_GROUP1, CURRENT_GROUP2])
    desired_groups = set()
    expected = set([
        memb.Q_REVOKE_MEMBERSHIP.format(CURRENT_GROUP1, ROLE1),
        memb.Q_REVOKE_MEMBERSHIP.format(CURRENT_GROUP2, ROLE1),
    ])

    actual = memb.MembershipAnalyzer(ROLE1, spec_memberships=desired_groups,
                                     dbcontext=mockdbcontext).analyze()
    assert set(actual) == expected


def test_analyze_some_current_some_desired(mockdbcontext):
    mockdbcontext.is_superuser = lambda x: False
    mockdbcontext.get_role_memberships = lambda x: set([DESIRED_GROUP1, CURRENT_GROUP1,
                                                        CURRENT_GROUP2])
    desired_groups = set([DESIRED_GROUP1, DESIRED_GROUP2])

    expected = set([
        memb.Q_GRANT_MEMBERSHIP.format(DESIRED_GROUP2, ROLE1),
        memb.Q_REVOKE_MEMBERSHIP.format(CURRENT_GROUP1, ROLE1),
        memb.Q_REVOKE_MEMBERSHIP.format(CURRENT_GROUP2, ROLE1),
    ])

    actual = memb.MembershipAnalyzer(ROLE1, spec_memberships=desired_groups,
                                     dbcontext=mockdbcontext).analyze()
    assert set(actual) == expected


def test_analyze_skip_superuser(mockdbcontext):
    mockdbcontext.is_superuser = lambda x: True
    expected = [memb.SKIP_SUPERUSER_MEMBERSHIPS_MSG.format(ROLE2)]
    actual = memb.MembershipAnalyzer(ROLE2, spec_memberships=DUMMY,
                                     dbcontext=mockdbcontext).analyze()
    assert actual == expected


def test_grant_membership(mockdbcontext):
    mockdbcontext.is_superuser = lambda x: False
    memconf = memb.MembershipAnalyzer(ROLE1, spec_memberships=DUMMY, dbcontext=mockdbcontext)
    memconf.grant_membership(DESIRED_GROUP1)
    assert memconf.sql_to_run == [memb.Q_GRANT_MEMBERSHIP.format(DESIRED_GROUP1, ROLE1)]


def test_revoke_membership(mockdbcontext):
    mockdbcontext.is_superuser = lambda x: False
    memconf = memb.MembershipAnalyzer(ROLE1, spec_memberships=DUMMY, dbcontext=mockdbcontext)
    memconf.revoke_membership(CURRENT_GROUP1)
    assert memconf.sql_to_run == [memb.Q_REVOKE_MEMBERSHIP.format(CURRENT_GROUP1, ROLE1)]
