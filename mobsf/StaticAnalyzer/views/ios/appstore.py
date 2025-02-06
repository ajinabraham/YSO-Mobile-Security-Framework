# -*- coding: utf_8 -*-
import logging

import requests

from django.conf import settings

from mobsf.MobSF.utils import append_scan_status
from mobsf.MobSF.proxy import upstream_proxy

logger = logging.getLogger(__name__)


def app_search(checksum, app_id):
    """IOS Get App Details from App Store."""
    msg = f'Fetching Details from App Store: {app_id}'
    logger.info(msg)
    append_scan_status(checksum, msg)
    lookup_url = settings.ITUNES_URL
    req_url = '{}?bundleId={}&country={}&entity=software'.format(
        lookup_url, app_id, 'us')
    headers = {
        'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) '
                       'AppleWebKit/537.36 (KHTML, like Gecko) '
                       'Chrome/39.0.2171.95 Safari/537.36')}
    try:
        det = {}
        proxies, verify = upstream_proxy('https')
        req = requests.get(
            req_url,
            timeout=5,
            headers=headers,
            proxies=proxies,
            verify=verify)
        resp = req.json()
        if resp['results']:
            det = resp['results'][0]
            return {
                'features': det['features'] or [],
                'icon': (det['artworkUrl512']
                         or det['artworkUrl100']
                         or det['artworkUrl60'] or ''),
                'developer_id': det['artistId'],
                'developer': det['artistName'],
                'developer_url': det['artistViewUrl'],
                'developer_website': det['sellerUrl'],
                'supported_devices': det['supportedDevices'],
                'title': det['trackName'],
                'app_id': det['bundleId'],
                'category': det['genres'] or [],
                'description': det['description'],
                'price': det['price'],
                'itunes_url': det['trackViewUrl'],
                'score': det['averageUserRating'],
                'error': False,
            }
        logger.warning('Unable to get app details.')
        return {'error': True}
    except Exception as exp:
        msg = 'Failed to get app details'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))
        return {'error': True}
