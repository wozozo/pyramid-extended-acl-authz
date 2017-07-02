import pytest


def test_extended_acl_permits_results_bool_value():
    from .. import ExtendedACLAllowed, ExtendedACLDenied
    assert bool(ExtendedACLAllowed([], [], []))
    assert not bool(ExtendedACLDenied([], [], []))


def test_extended_acl_permits_results_msg():
    from .. import ExtendedACLAllowed, ExtendedACLDenied, ACE
    from pyramid.security import Allow, Deny
    from pyramid.testing import DummyResource
    context = DummyResource()
    allow_acl = [
        (Allow, ['p1', 'p2'], ['perm1', 'perm2']),
        (Allow, ['p3'], ['perm1']),
        (Allow, ['p4', 'p5'], ['perm2']),
        (Allow, ['p6'], ['perm3', 'perm4']),
        ]
    acl_allowed = ExtendedACLAllowed(
        [
            ((context, allow_acl), ACE(Allow, {'p1', 'p2'}, {'perm1', 'perm2'}, None)),
            ((context, allow_acl), ACE(Allow, {'p3'}, {'perm1'}, None)),
            ((context, allow_acl), ACE(Allow, {'p4', 'p5'}, {'perm2'}, None)),
            ((context, allow_acl), ACE(Allow, {'p6'}, {'perm3', 'perm4'}, None)),
            ],
        {'perm4', 'perm1', 'perm2', 'perm3'},
        {'p4', 'p5', 'p6', 'p1', 'p2', 'p3'}
        )
    assert acl_allowed.msg == (
        "ExtendedACLAllowed permission(s) {perm1, perm2, perm3, perm4} for principal(s) {p1, p2, p3, p4, p5, p6}"
        " via ACE('Allow', ['p1', 'p2'], ['perm1', 'perm2']) in ACL %(acl)r on context %(context)r"
        " via ACE('Allow', ['p3'], ['perm1']) in ACL %(acl)r on context %(context)r"
        " via ACE('Allow', ['p4', 'p5'], ['perm2']) in ACL %(acl)r on context %(context)r"
        " via ACE('Allow', ['p6'], ['perm3', 'perm4']) in ACL %(acl)r on context %(context)r"
        ) % dict(acl=allow_acl, context=context)


    deny_acl = [
        (Deny, ['p7'], ['perm1', 'perm2']),
        ]
    acl_denied = ExtendedACLDenied(
        [
            ((context, deny_acl), ACE(Deny, {'p7'}, {'perm1', 'perm2'}, None)),
            ],
        {'perm1', 'perm2'},
        {'p7'}
        )
    assert acl_denied.msg == (
        "ExtendedACLDenied permission(s) {perm1, perm2} for principal(s) {p7}"
        " via ACE('Deny', ['p7'], ['perm1', 'perm2']) in ACL %(acl)r on context %(context)r"
        ) % dict(acl=deny_acl, context=context)


class TestExtendedAuthorizationPolicy(object):

    @pytest.fixture
    def target(self):
        from .. import ExtendedACLAuthorizationPolicy
        return ExtendedACLAuthorizationPolicy()

    def test_permits_no_parent(self, target):
        from pyramid.security import Allow, Deny
        from pyramid.testing import DummyResource
        context = DummyResource(
            __parent__=None,
            __acl__=[
                (Allow, ['p1', 'p2'], ['perm1', 'perm2']),
                (Allow, ['p3'], ['perm1']),
                (Deny, ['p5', 'p6'], ['perm2']),
                (Allow, ['p4', 'p5'], ['perm2']),
                (Allow, ['p6'], ['perm3', 'perm4']),
                ]
            )
        for principal in ['p1', 'p2', 'p4', 'p5']:
            for permission in ['perm1', 'perm2', 'perm3', 'perm4']:
                assert not target.permits(context, [principal], permission)
        assert target.permits(context, ['p3'], 'perm1')
        assert not target.permits(context, ['p3'], 'perm2')
        assert not target.permits(context, ['p3'], 'perm3')
        assert not target.permits(context, ['p3'], 'perm4')
        assert not target.permits(context, ['p6'], 'perm1')
        assert not target.permits(context, ['p6'], 'perm2')
        assert target.permits(context, ['p6'], 'perm3')
        assert target.permits(context, ['p6'], 'perm4')
        assert target.permits(context, ['p6'], 'perm3+perm4')
        assert target.permits(context, ['p4', 'p5'], 'perm2')
        assert not target.permits(context, ['p4', 'p5', 'p6'], 'perm2')
        assert target.permits(context, ['p4', 'p5', 'p6'], 'perm3')
        assert target.permits(context, ['p4', 'p5', 'p6'], 'perm4')

    def test_permits_parent_no_inherit(self, target):
        from pyramid.security import Allow, Deny
        from pyramid.testing import DummyResource
        parent_context = DummyResource(
            __parent__=None,
            __acl__=[
                (Allow, ['p1', 'p2'], ['perm1', 'perm2']),
                (Allow, ['p3'], ['perm1']),
                (Deny, ['p5', 'p6'], ['perm2']),
                (Allow, ['p4', 'p5'], ['perm2']),
                (Allow, ['p6'], ['perm3', 'perm4']),
                ]
            )
        context = DummyResource(
            __parent__=parent_context,
            __acl_inherit__=False,
            __acl__=[
                (Deny, ['p1', 'p2'], ['perm1', 'perm2']),
                (Deny, ['p3'], ['perm1']),
                (Allow, ['p5', 'p6'], ['perm2']),
                (Deny, ['p4', 'p5'], ['perm2']),
                (Allow, ['p6'], ['perm5']),
                ]
            )
        assert not target.permits(context, ['p1', 'p2'], 'perm1')
        assert not target.permits(context, ['p1', 'p2'], 'perm2')
        assert not target.permits(context, ['p1', 'p2'], 'perm3')
        assert not target.permits(context, ['p1', 'p2'], 'perm4')
        assert not target.permits(context, ['p1', 'p2'], 'perm5')
        assert target.permits(context, ['p5', 'p6'], 'perm2')
        assert not target.permits(context, ['p6'], 'perm1')
        assert not target.permits(context, ['p6'], 'perm2')
        assert not target.permits(context, ['p6'], 'perm3')
        assert not target.permits(context, ['p6'], 'perm4')
        assert target.permits(context, ['p6'], 'perm5')

    def test_permits_parent_inherit(self, target):
        from pyramid.security import Allow, Deny
        from pyramid.testing import DummyResource
        parent_context = DummyResource(
            __parent__=None,
            __acl__=[
                (Allow, ['p1', 'p2'], ['perm1', 'perm2']),
                (Allow, ['p3'], ['perm1']),
                (Deny, ['p5', 'p6'], ['perm2']),
                (Allow, ['p4', 'p5'], ['perm2']),
                (Allow, ['p6'], ['perm3', 'perm4']),
                ]
            )
        context = DummyResource(
            __parent__=parent_context,
            __acl_inherit__=True,
            __acl__=[
                (Deny, ['p3'], ['perm1']),
                (Allow, ['p5', 'p6'], ['perm2']),
                (Deny, ['p4', 'p5'], ['perm2']),
                (Allow, ['p6'], ['perm5']),
                ]
            )
        assert target.permits(context, ['p1', 'p2'], 'perm1')
        assert target.permits(context, ['p1', 'p2'], 'perm2')
        assert not target.permits(context, ['p1', 'p2'], 'perm3')
        assert not target.permits(context, ['p1', 'p2'], 'perm4')
        assert not target.permits(context, ['p1', 'p2'], 'perm5')
        assert not target.permits(context, ['p1', 'p2', 'p3'], 'perm1')
        assert target.permits(context, ['p1', 'p2', 'p3'], 'perm2')
        assert target.permits(context, ['p5', 'p6'], 'perm2')
        assert not target.permits(context, ['p6'], 'perm1')
        assert not target.permits(context, ['p6'], 'perm2')
        assert target.permits(context, ['p6'], 'perm3')
        assert target.permits(context, ['p6'], 'perm4')
        assert target.permits(context, ['p6'], 'perm5')
