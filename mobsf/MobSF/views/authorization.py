"""User management and authorization."""
from itertools import chain
from inspect import signature
from functools import wraps
from enum import Enum
import logging

from django.contrib.auth.models import (
    Group,
    Permission,
    User,
)
from django.shortcuts import (
    redirect,
    render,
)
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import (
    login_required,
    permission_required as pr,
)
from django.views.decorators.http import require_http_methods
from django.template.defaulttags import register
from django.conf import settings

from mobsf.MobSF.forms import RegisterForm
from mobsf.MobSF.utils import (
    USERNAME_REGEX,
    get_md5,
)
from mobsf.DynamicAnalyzer.views.common.shared import (
    send_response,
)

logger = logging.getLogger(__name__)
register.filter('md5', get_md5)


PERM_CAN_SCAN = 'can_scan'
PERM_CAN_SUPPRESS = 'can_suppress'
PERM_CAN_DELETE = 'can_delete'


class Permissions(Enum):
    SCAN = f'StaticAnalyzer.{PERM_CAN_SCAN}'
    SUPPRESS = f'StaticAnalyzer.{PERM_CAN_SUPPRESS}'
    DELETE = f'StaticAnalyzer.{PERM_CAN_DELETE}'


MAINTAINER_GROUP = 'Maintainer'
VIEWER_GROUP = 'Viewer'


def permission_required(perm):
    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            sig = signature(view)
            arguments = sig.bind(request, *args, **kwargs)
            api = arguments.arguments.get('api')
            if settings.DISABLE_AUTHENTICATION == '1' or api:
                # Disable authorization for all functions
                return view(request, *args, **kwargs)
            # Enforce authorization for all web function calls
            return pr(
                perm.value,
                raise_exception=True)(view)(request, *args, **kwargs)
        return wrapper
    return decorator


def has_permission(request, permission, api):
    """Check if user has permission."""
    try:
        if request.user.is_staff:
            return True
        if settings.DISABLE_AUTHENTICATION == '1' or api:
            return True
        if request.user.has_perm(permission.value):
            return True
    except Exception:
        logger.exception('[ERROR] Failed to check permissions')
    return False


def create_authorization_roles():
    """Create Authorization Roles."""
    try:
        maintainer, _created = Group.objects.get_or_create(
            name=MAINTAINER_GROUP)
        Group.objects.get_or_create(name=VIEWER_GROUP)

        scan_permissions = Permission.objects.filter(
            codename=PERM_CAN_SCAN)
        suppress_permissions = Permission.objects.filter(
            codename=PERM_CAN_SUPPRESS)
        delete_permissions = Permission.objects.filter(
            codename=PERM_CAN_DELETE)
        all_perms = list(chain(
            scan_permissions, suppress_permissions, delete_permissions))
        maintainer.permissions.set(all_perms)
    except Exception:
        logger.exception('[ERROR] Failed to create roles and permissions')


@login_required
@staff_member_required
def users(request):
    """Show all users."""
    if settings.DISABLE_AUTHENTICATION == '1':
        return redirect('/')
    users = get_user_model().objects.all()
    context = {
        'title': 'All Users',
        'users': users,
        'version': settings.MOBSF_VER,
    }
    return render(request, 'auth/users.html', context)


@login_required
@staff_member_required
def create_user(request):
    if settings.DISABLE_AUTHENTICATION == '1':
        return redirect('/')
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            role = request.POST.get('role')
            username = request.POST.get('username')
            if not username:
                messages.error(request, 'No Username Provided')
                return redirect('create_user')
            if not USERNAME_REGEX.match(username):
                messages.error(request, 'Invalid Username')
                return redirect('create_user')
            user = form.save()
            user.is_staff = False
            if role == 'maintainer':
                user.groups.add(Group.objects.get(name=MAINTAINER_GROUP))
            else:
                user.groups.add(Group.objects.get(name=VIEWER_GROUP))
            messages.success(
                request,
                'User created successfully!')
            return redirect('create_user')
        else:
            messages.error(
                request,
                'Please correct the error below.')
    else:
        form = RegisterForm()
    context = {
        'title': 'Create User',
        'version': settings.VERSION,
        'form': form,
    }
    return render(request, 'auth/register.html', context)


@login_required
@staff_member_required
@require_http_methods(['POST'])
def delete_user(request):
    data = {'deleted': 'Failed to delete user'}
    try:
        if settings.DISABLE_AUTHENTICATION == '1':
            return redirect('/')
        username = request.POST.get('username')
        if not username:
            data = {'deleted': 'No Username Provided'}
            return send_response(data)
        if not USERNAME_REGEX.match(username):
            data = {'deleted': 'Invalid Username'}
            return send_response(data)
        u = User.objects.get(username=username)
        if u.is_staff:
            data = {'deleted': 'Cannot delete staff users'}
            return send_response(data)
        u.groups.clear()
        u.delete()
        data = {'deleted': 'yes'}
    except User.DoesNotExist:
        data = {'deleted': 'User does not exist'}
    except Exception as e:
        data = {'deleted': e.message}
    return send_response(data)
