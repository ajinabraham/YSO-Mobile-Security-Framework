"""User management and authorization."""
from itertools import chain

from django.contrib.auth.models import Group, Permission
from django.shortcuts import (
    redirect,
    render,
)
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.template.defaulttags import register
from django.conf import settings

from mobsf.MobSF.forms import RegisterForm
from mobsf.MobSF.utils import get_md5


register.filter('md5', get_md5)
PERM_CAN_SCAN = 'can_scan'
PERM_CAN_SUPPRESS = 'can_suppress'
PERM_CAN_DELETE = 'can_delete'
PERMISSIONS = {
    'SCAN': f'StaticAnalyzer.{PERM_CAN_SCAN}',
    'SUPPRESS': f'StaticAnalyzer.{PERM_CAN_SUPPRESS}',
    'DELETE': f'StaticAnalyzer.{PERM_CAN_DELETE}',
}
DJANGO_PERMISSIONS = {
    'SCAN': (PERM_CAN_SCAN, 'Scan Files'),
    'SUPPRESS': (PERM_CAN_SUPPRESS, 'Suppress Findings'),
    'DELETE': (PERM_CAN_DELETE, 'Delete Scans'),
}
MAINTAINER_GROUP = 'Maintainer'
VIEWER_GROUP = 'Viewer'


def create_authorization_roles():
    """Create Authorization Roles."""
    maintainer, _created = Group.objects.get_or_create(name=MAINTAINER_GROUP)
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


@login_required
@staff_member_required
def users(request):
    """Show all users."""
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
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            role = request.POST.get('role')
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
