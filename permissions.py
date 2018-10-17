"""
Provides a set of pluggable permission policies.
"""
from __future__ import unicode_literals
import six
SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')


class OperandHolder:
    def __init__(self, operator_class, op1_class, op2_class):
        self.operator_class = operator_class
        self.op1_class = op1_class
        self.op2_class = op2_class

    def __call__(self, *args, **kwargs):
        op1 = self.op1_class(*args, **kwargs)
        op2 = self.op2_class(*args, **kwargs)
        return self.operator_class(op1, op2)


class AND:
    def __init__(self, op1, op2):
        self.op1 = op1
        self.op2 = op2

    def has_permission(self, request, view):
        return (
                self.op1.has_permission(request, view) &
                self.op2.has_permission(request, view)
        )

    def has_object_permission(self, request, view, obj):
        return (
                self.op1.has_object_permission(request, view, obj) &
                self.op2.has_object_permission(request, view, obj)
        )


class OR:
    def __init__(self, op1, op2):
        self.op1 = op1
        self.op2 = op2

    def has_permission(self, request, view):
        return (
                self.op1.has_permission(request, view) |
                self.op2.has_permission(request, view)
        )

    def has_object_permission(self, request, view, obj):
        return (
                self.op1.has_object_permission(request, view, obj) |
                self.op2.has_object_permission(request, view, obj)
        )


class BasePermissionMetaclass(type):
    def __and__(cls, other):
        return OperandHolder(AND, cls, other)

    def __or__(cls, other):
        return OperandHolder(OR, cls, other)

    def __rand__(cls, other):
        return OperandHolder(AND, other, cls)

    def __ror__(cls, other):
        return OperandHolder(OR, other, cls)


@six.add_metaclass(BasePermissionMetaclass)
class BasePermission(object):
    """
    A base class from which all permission classes should inherit.
    """

    def has_permission(self, request, view):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        return True

    def has_object_permission(self, request, view, obj):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        return True


class AllowAny(BasePermission):
    """
    Allow any access.
    This isn't strictly required, since you could use an empty
    permission_classes list, but it's useful because it makes the intention
    more explicit.
    """

    def has_permission(self, request, view):
        return True


class IsAuthenticated(BasePermission):
    """
    Allows access only to authenticated users.
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated


class IsAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_staff


class IsAuthenticatedOrReadOnly(BasePermission):
    """
    The request is authenticated as a user, or is a read-only request.
    """

    def has_permission(self, request, view):
        return (
                request.method in SAFE_METHODS or
                request.user and
                request.user.is_authenticated
        )


