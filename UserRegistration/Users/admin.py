from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['id','phone' ,'username', 'email', 'first_name', 'last_name', 'is_staff']
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("username", "password1", "password2",'email','first_name','last_name'),
            },
        ),
    )
    # first_name and last name are not in the model. so they are not mandetory.

