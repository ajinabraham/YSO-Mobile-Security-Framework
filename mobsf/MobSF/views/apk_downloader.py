# -*- coding: utf_8 -*-
"""Android APK Downloader."""
import logging
from tempfile import gettempdir
from pathlib import Path
from zipfile import ZipFile

import requests

from bs4 import BeautifulSoup

from django.conf import settings

from mobsf.MobSF.views.scanning import (
    add_to_recent_scan,
    handle_uploaded_file,
)
from mobsf.MobSF.proxy import upstream_proxy
from mobsf.MobSF.utils import (
    is_internet_available,
    is_path_traversal,
    is_zip_magic,
    strict_package_check,
)


logger = logging.getLogger(__name__)


def fetch_html(url):
    """Get Result HTML."""
    headers = {
        'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) '
                       'AppleWebKit/537.36 (KHTML, like Gecko) '
                       'Chrome/39.0.2171.95 Safari/537.36'),
        'Accept-Encoding': 'deflate, gzip'}
    try:
        proxies, verify = upstream_proxy('https')
        res = requests.get(url,
                           timeout=5,
                           headers=headers,
                           proxies=proxies,
                           verify=verify,
                           stream=True)
        if res.status_code == 200:
            return BeautifulSoup(res.text, features='lxml')
    except Exception:
        pass
    return None


def download_file(url, outfile):
    try:
        logger.info('Downloading APK...')
        proxies, verify = upstream_proxy('https')
        with requests.get(url,
                          timeout=5,
                          stream=True,
                          proxies=proxies,
                          verify=verify) as r:
            r.raise_for_status()
            with open(outfile, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return outfile
    except Exception:
        pass
    return None


def get_scan_type(location):
    """Get APK type."""
    with ZipFile(location, 'r') as zf:
        for fil in zf.namelist():
            if fil.endswith('.apk'):
                return 'apks'
    return 'apk'


def add_apk(dwd_file, filename):
    """Add APK to MobSF."""
    with dwd_file.open('rb') as flip:
        if not is_zip_magic(flip):
            logger.warning('Downloaded file is not an APK/Split APK')
            return None
        md5 = handle_uploaded_file(flip, '.apk')
        apk = Path(settings.UPLD_DIR) / md5 / f'{md5}.apk'
        scan_type = get_scan_type(apk)
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': md5,
            'scan_type': scan_type,
            'file_name': filename,
        }
        add_to_recent_scan(data)
        return data
    return None


def find_apk_link(url, domain):
    """Find APK download link."""
    try:
        logger.info('Looking for download link form %s', domain)
        bsp = fetch_html(url)
        if not bsp:
            return None
        link = bsp.find('a', href=True, string='click here')
        if link:
            logger.info('Download link found from %s', domain)
            return link['href']
        logger.warning('Download link not found in %s', domain)
    except Exception:
        logger.warning('Failed to obtain download link from %s', domain)
    return None


def try_provider(package, provider, domain):
    """Try using a provider."""
    downloaded_file = None
    data = None
    apk_name = f'{package}.apk'
    temp_file = Path(gettempdir()) / apk_name
    link = find_apk_link(provider, domain)
    if link:
        downloaded_file = download_file(link, temp_file)
    if downloaded_file:
        data = add_apk(downloaded_file, apk_name)
    if data:
        return data
    return None


def apk_download(package):
    """Download APK."""
    downloaded_file = None
    data = None
    try:
        if not is_internet_available():
            logger.warning('Internet Not Available. Unable to download APK')
            return None
        if not strict_package_check(package) or is_path_traversal(package):
            return None
        logger.info('Attempting to download: %s', package)
        # APKTADA
        data = try_provider(
            package,
            f'{settings.APKTADA}{package}',
            'apktada.com')
        if data:
            return data
        # APKPURE
        data = try_provider(
            package,
            settings.APKPURE.format(package),
            'apkpure.com')
        if data:
            return data
        # APKPLZ
        data = try_provider(
            package,
            f'{settings.APKPLZ}{package}',
            'apkplz.net')
        if data:
            return data
        logger.warning('Unable to find download link for %s', package)
        return None
    except Exception:
        logger.exception('Failed to download the apk')
        return None
    finally:
        if downloaded_file:
            downloaded_file.unlink()
