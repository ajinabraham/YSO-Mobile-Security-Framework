import os
import re
import logging

from . import settings

logger = logging.getLogger(__name__)


def upstream_proxy(flaw_type, for_urllib=False):
    """Set upstream Proxy if needed."""
    if settings.UPSTREAM_PROXY_ENABLED:
        if not settings.UPSTREAM_PROXY_USERNAME:
            proxy_port = str(settings.UPSTREAM_PROXY_PORT)
            proxy_host = '{}://{}:{}'.format(
                settings.UPSTREAM_PROXY_TYPE,
                docker_translate_proxy_ip(settings.UPSTREAM_PROXY_IP),
                proxy_port)
            proxies = {flaw_type: proxy_host}
        else:
            proxy_port = str(settings.UPSTREAM_PROXY_PORT)
            proxy_host = '{}://{}:{}@{}:{}'.format(
                settings.UPSTREAM_PROXY_TYPE,
                settings.UPSTREAM_PROXY_USERNAME,
                settings.UPSTREAM_PROXY_PASSWORD,
                docker_translate_proxy_ip(settings.UPSTREAM_PROXY_IP),
                proxy_port)
            proxies = {flaw_type: proxy_host}
    else:
        if for_urllib:
            proxies = {}
        else:
            proxies = {flaw_type: None}
    verify = settings.UPSTREAM_PROXY_SSL_VERIFY in ('1', '"1"')
    return proxies, verify


def docker_translate_localhost(identifier):
    """Convert localhost to host.docker.internal."""
    if not identifier:
        return identifier
    if not os.getenv('MOBSF_PLATFORM') == 'docker':
        return identifier
    try:
        identifier = identifier.strip()
        docker_internal = 'host.docker.internal:'
        if re.match(r'^emulator-\d{4}$', identifier):
            adb_port = int(identifier.split('emulator-')[1]) + 1
            # ADB port is console port + 1
            return f'{docker_internal}{adb_port}'
        m = re.match(r'^(localhost|127\.0\.0\.1):\d{1,5}$', identifier)
        if m:
            adb_port = int(identifier.split(m.group(1))[1].replace(':', ''))
            return f'{docker_internal}{adb_port}'
        return identifier
    except Exception:
        logger.exception('Failed to convert device '
                         'identifier for docker connectivity')
        return identifier


def docker_translate_proxy_ip(ip):
    """Convert localhost proxy ip to host.docker.internal."""
    if not os.getenv('MOBSF_PLATFORM') == 'docker':
        return ip
    if ip and ip.strip() in ('127.0.0.1', 'localhost'):
        return 'host.docker.internal'
    return ip
