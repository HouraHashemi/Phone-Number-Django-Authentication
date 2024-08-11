from rest_framework import permissions

class IsAdminOrSelf(permissions.BasePermission):


    def has_permission(self, request, view):
        # Allow access to list and create for everyone
        if request.method == 'POST':
            return request.user 
        # For GET requests, only allow admin users
        if request.method == 'GET':
            return request.user and request.user.is_staff
        return False


    def has_object_permission(self, request, view, obj):
        # Admins can access any object
        if request.user.is_staff:
            return True
        # Regular users can only access their own object
        return obj == request.user
