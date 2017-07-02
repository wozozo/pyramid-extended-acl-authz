import itertools
from collections import namedtuple
from zope.interface import implementer
from pyramid.interfaces import IAuthorizationPolicy
from pyramid.location import lineage
from pyramid.compat import is_nonstr_iter
from pyramid.security import (
    PermitsResult,
    Allow,
    Deny,
    Everyone,
    )


ACEBase = namedtuple('ACEBase', ['action', 'principals', 'permissions'])
class ACE(ACEBase):

    def __new__(cls, action, principals, permissions, original_ace=None):
        inst = ACEBase.__new__(cls, action, principals, permissions)
        inst.original_ace = original_ace
        return inst

    def __repr__(self):
        return 'ACE(%r, %r, %r)' % (self.action, sorted(self.principals), sorted(self.permissions))


class ExtendedACLPermitsResult(int):

    def __new__(cls, aces, permissions, principals):
        inst = int.__new__(cls, cls.boolval)
        inst.aces = aces
        inst.permissions = permissions
        inst.principals = principals
        return inst

    @property
    def msg(self):
        s = [
            '%s permission(s) {%s} for principal(s) {%s}' % (
                self.__class__.__name__,
                ', '.join(str(x) for x in sorted(self.permissions)),
                ', '.join(str(x) for x in sorted(self.principals))
                )
            ]
        for (context, acl), ace in self.aces:
            s.append('via %r in ACL %r on context %r' % (ace, acl, context,))
        return ' '.join(s)

    def __str__(self):
        return self.msg

    def __repr__(self):
        return '<%s instance at %s with msg %r>' % (self.__class__.__name__,
                                                    id(self),
                                                    self.msg)


class ExtendedACLAllowed(ExtendedACLPermitsResult):
    boolval = 1


class ExtendedACLDenied(ExtendedACLPermitsResult):
    boolval = 0


def resolve_acl(location):
    try:
        acl = location.__acl__
    except AttributeError:
        return None, True

    if acl and callable(acl):
        acl = acl()

    acl_inherit = None
    try:
        acl_inherit = acl.inherits
    except AttributeError:
        pass

    if acl_inherit is None:
        try:
            acl_inherit = location.__acl_inherit__
        except AttributeError:
            pass

    return acl, acl_inherit


def parse_permission(permission):
    return set(
        permission if is_nonstr_iter(permission)
        else permission.split('+'))


@implementer(IAuthorizationPolicy)
class ExtendedACLAuthorizationPolicy(object):

    def __init__(self, acl_resolver=resolve_acl, permission_parser=parse_permission, acl_inheritance_default=False):
        self.acl_resolver = acl_resolver
        self.permission_parser = permission_parser
        self.acl_inheritance_default = acl_inheritance_default


    def _collect_acls_to_examine(self, context):
        acls_to_examine = []
        for location in lineage(context):
            acl, inherits = self.acl_resolver(location)
            acls_to_examine.append((location, acl))
            if inherits is None:
                inherits = self.acl_inheritance_default
            if not inherits:
                break

        acls_to_examine.reverse()
        return acls_to_examine

    def permits(self, context, principals, permission):
        acls_to_examine = self._collect_acls_to_examine(context)

        applicable_aces = []
        granted_permissions = set()

        for location, acl in acls_to_examine:
            for ace in reversed(acl):
                ace_action, ace_principals, ace_permissions = ace

                if not is_nonstr_iter(ace_principals):
                    ace_principals = [ace_principals]
                everyone = False
                if Everyone in ace_principals:
                    ace_principals = [Everyone]
                    everyone = True

                ace_principals = set(ace_principals)
                if not is_nonstr_iter(ace_permissions):
                    ace_permissions = [ace_permissions]

                if everyone or ace_principals.issubset(principals):
                    applicable_aces.append(
                        (
                            (location, acl),
                            ACE(ace_action, ace_principals, ace_permissions, ace)
                            )
                        )
                    if ace_action == Allow:
                        granted_permissions.update(ace_permissions)
                    else:
                        granted_permissions.difference_update(ace_permissions)

        required_permissions = self.permission_parser(permission)

        if granted_permissions.issuperset(required_permissions):
            return ExtendedACLAllowed(
                applicable_aces,
                required_permissions,
                principals
                )
        else:
            return ExtendedACLDenied(
                applicable_aces,
                required_permissions,
                principals
                )

    def principals_allowed_by_permission(self, context, permission):
        allowed = set()

        acls_to_examine = self._collect_acls_to_examine(context)
        permissions = self.permission_parser(permission)

        for location, acl in acls_to_examine:

            for ace_action, ace_principal, ace_permissions in reversed(acl):
                if not is_nonstr_iter(ace_principals):
                    ace_principals = [ace_principals]
                ace_principals = set(ace_principals)
                if not is_nonstr_iter(ace_permissions):
                    ace_permissions = [ace_permissions]

                if ace_permissions.issuperset(permissions):
                    if ace_action == Allow:
                        allowed.update(ace_principals)
                    elif ace_action == Deny:
                        if Everyone in ace_principals:
                            allowed.clear()
                        else:
                            allowed.difference_update(ace_principals)

        return allowed
