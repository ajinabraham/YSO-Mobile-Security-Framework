"""SAML2 SSO logic."""
from urllib.parse import urlparse
import logging

from onelogin.saml2.auth import (
    OneLogin_Saml2_Auth,
)
from onelogin.saml2.idp_metadata_parser import (
    OneLogin_Saml2_IdPMetadataParser,
)

from django.conf import settings
from django.contrib.auth.models import (
    Group,
    User,
)
from django.contrib.auth import login
from django.urls import reverse
from django.shortcuts import redirect
from django.views.decorators.http import require_http_methods

from mobsf.MobSF.views.authorization import (
    MAINTAINER_GROUP,
    VIEWER_GROUP,
)
from mobsf.MobSF.utils import (
    print_n_send_error_response,
)
from mobsf.MobSF.security import (
    sanitize_redirect,
)

logger = logging.getLogger(__name__)
ASSERTION_IDS = set()


def get_url_components(url):
    """Get URL components."""
    purl = urlparse(url)
    return purl.scheme, purl.netloc, purl.port


def init_saml_auth(req):
    """Initialize SAML auth."""
    host = req['sp_url']
    acs_route = reverse('saml_acs')
    saml_settings = {
        'strict': True,
        'debug': True,
        'sp': {
            'entityId': f'{host}{acs_route}',
            'assertionConsumerService': {
                'url': f'{host}{acs_route}',
                'binding': ('urn:oasis:names:tc:'
                            'SAML:2.0:bindings:HTTP-POST'),
            },
        },
        'idp': {
            'entityId': settings.IDP_ENTITY_ID,
            'singleSignOnService': {
                'url': settings.IDP_SSO_URL,
                'binding': ('urn:oasis:names:tc:'
                            'SAML:2.0:bindings:HTTP-Redirect'),
            },
            'x509cert': settings.IDP_X509CERT,
        },
    }
    try:
        idp_data = None
        if settings.IDP_METADATA_URL:
            idp_data = OneLogin_Saml2_IdPMetadataParser.parse_remote(
                settings.IDP_METADATA_URL,
                timeout=5)
        if idp_data:
            saml_settings['idp'] = idp_data['idp']
    except Exception:
        logger.exception('[ERROR] parsing IdP metadata URL.')
    return OneLogin_Saml2_Auth(req, saml_settings)


def prepare_django_request(request):
    """Prepare Django request for SAML."""
    scheme = 'https' if request.is_secure() else 'http'
    netloc = request.get_host()
    port = request.get_port()
    if settings.SP_HOST:
        scheme, netloc, port = get_url_components(
            settings.SP_HOST.strip('/'))
        if not port:
            port = 443 if scheme == 'https' else 80
    https_state = 'on' if scheme == 'https' else 'off'
    sp_url = f'{scheme}://{netloc}'
    result = {
        'https': https_state,
        'http_host': netloc,
        'server_port': port,
        'script_name': request.get_full_path_info(),
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy(),
        'lowercase_urlencoding': bool(settings.IDP_IS_ADFS == '1'),
        'query_string': request.META['QUERY_STRING'],
        'sp_url': sp_url,
    }
    return result


def check_replay(auth):
    """Check for replay attack."""
    request_id = auth.get_last_assertion_id()
    if request_id:
        if request_id in ASSERTION_IDS:
            raise Exception('Replay attack detected.')
        ASSERTION_IDS.add(request_id)


def get_redirect_url(req):
    """Check for open redirect and return redirect url."""
    redirect_url = '/'
    if 'RelayState' not in req['post_data']:
        return redirect_url
    relay_state = req['post_data']['RelayState']
    # Allow only relative URLs
    if relay_state:
        redirect_url = sanitize_redirect(relay_state)
    return redirect_url


def get_user_role(roles):
    """Get user role."""
    maintainer_groups = [g.lower() for g in settings.IDP_MAINTAINER_GROUP]
    viewer_groups = [g.lower() for g in settings.IDP_VIEWER_GROUP]
    user_roles = [gp.lower() for gp in roles]
    mrole = any(gp in maintainer_groups for gp in user_roles)
    vrole = any(gp in viewer_groups for gp in user_roles)
    if mrole or settings.IDP_MOBSF_DEFAULT_GROUP == 'Maintainer':
        logger.info('User assigned to %s group.', MAINTAINER_GROUP)
        return MAINTAINER_GROUP
    elif vrole or settings.IDP_MOBSF_DEFAULT_GROUP == 'Viewer':
        logger.info('User assigned to %s group.', VIEWER_GROUP)
        return VIEWER_GROUP
    logger.warning('User does not have an authorized SSO group.')
    return None


@require_http_methods(['GET'])
def saml_login(request):
    """Handle SSO Login."""
    try:
        if settings.DISABLE_AUTHENTICATION == '1':
            return redirect('/')
        req = prepare_django_request(request)
        auth = init_saml_auth(req)
        nextp = request.GET.get('next', '')
        redirect_url = sanitize_redirect(nextp)
        return redirect(auth.login(return_to=redirect_url))
    except Exception as exp:
        return print_n_send_error_response(
            request,
            exp,
            False)


@require_http_methods(['POST'])
def saml_acs(request):
    """Handle SSO Assertion Consumer Service."""
    try:
        if settings.DISABLE_AUTHENTICATION == '1':
            return redirect('/')
        req = prepare_django_request(request)
        auth = init_saml_auth(req)
        auth.process_response()
        check_replay(auth)
        if not auth.is_authenticated():
            raise Exception(
                'SAML authentication failed.')
        # Extract user attributes for AuthZ and AuthN
        attributes = auth.get_attributes()
        if not attributes.get('email'):
            raise Exception(
                'email attribute not found in SAML response.')
        if not attributes.get('role'):
            raise Exception(
                'role attribute not found in SAML response.')
        email = attributes['email'][0]
        role = get_user_role(attributes['role'])
        if not role:
            raise Exception(
                'You do not have an authorized SSO group.')
        if User.objects.filter(username=email).exists():
            user = User.objects.get(username=email)
            user.groups.clear()
            user.groups.add(Group.objects.get(name=role))
            login(request, user)
        else:
            user = User.objects.create_user(
                username=email,
                email=email)
            user.is_staff = False
            user.groups.add(Group.objects.get(name=role))
            login(request, user)
        return redirect(get_redirect_url(req))
    except Exception as exp:
        return print_n_send_error_response(
            request,
            exp,
            False)
