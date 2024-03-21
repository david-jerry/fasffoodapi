from rest_framework import permissions
from rest_framework.exceptions import ValidationError

class IsStaffPermission(permissions.BasePermission):
    """
    Custom permission to allow access only to staff members.
    """

    message = "Only authenticated staff member can perform this action."

    def has_permission(self, request, view):
        if request.user.is_vendor:
            return True
        raise ValidationError(self.message)

class IsVendorPermission(permissions.BasePermission):
    """
    Permission class to allow only vendors to perform certain actions.
    """

    message = "Only vendors can perform this action."

    def has_permission(self, request, view):
        if request.user.is_vendor:
            return True
        raise ValidationError(self.message)


class IsOwnerOrReadOnlyPermission(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to modify it.
    """
    message = "Only vendors can perform this action."

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return obj.user == request.user
        raise ValidationError(self.message)


class IsCustomerOrVendorPermission(permissions.BasePermission):
    """
    Permission class to allow customers and vendors to perform certain actions.
    """

    message = "Only customers or vendors can perform this action."

    def has_permission(self, request, view):
        if request.user.is_authenticated:
            if request.user.is_customer or request.user.is_vendor:
                return True
            else:
                raise ValidationError(self.message)
        raise ValidationError("Authentication is required to access this resource.")
