from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from authentication.models import *

# Register your models here.


class UserAdmin(UserAdmin):
    filter_horizontal = ()
    list_display = ('email', 'username',)
    list_filter = ('is_staff', 'is_active',)
    fieldsets = (
        (None, {'fields': ('email', 'password',)}),
        ('Personal Info', {'fields': ('username',
         'last_login', 'date_joined', 'profile_picture',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff',
         'is_superuser', 'is_merchant', 'is_verified', 'is_blocked',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'profile_picture'),
        }),
    )
    readonly_fields = ('date_joined',)
    search_fields = ('email', 'username',)
    ordering = ('-id',)


admin.site.register(User, UserAdmin)
admin.site.register(ActivationLink)