# -*- coding: utf_8 -*-
"""Download Frida Server."""
import logging
from pathlib import Path
from lzma import LZMAFile
from shutil import copyfileobj

import requests

from django.conf import settings

from mobsf.MobSF.utils import is_internet_available
from mobsf.MobSF.proxy import upstream_proxy


logger = logging.getLogger(__name__)


def clean_up_old_binaries(dirc, version):
    """Delete Old Binaries."""
    for f in Path(dirc).iterdir():
        if f.is_file() and f.name.startswith('frida-server'):
            if version in f.name:
                continue
            try:
                f.unlink()
            except Exception:
                pass


def download_frida_server(url, version, fname, proxies, verify):
    """Download frida-server-binary."""
    try:
        download_dir = Path(settings.DWD_DIR)
        logger.info('Downloading binary %s', fname)
        dwd_loc = download_dir / fname
        with requests.get(
                url,
                timeout=5,
                proxies=proxies,
                verify=verify,
                stream=True) as r:
            with LZMAFile(r.raw) as f:
                with open(dwd_loc, 'wb') as flip:
                    copyfileobj(f, flip)
        clean_up_old_binaries(download_dir, version)
        return True
    except Exception:
        logger.exception('[ERROR] Downloading Frida Server Binary')
    return False


def update_frida_server(arch, version):
    """Download Assets of a given version."""
    download_dir = Path(settings.DWD_DIR)
    fserver = f'frida-server-{version}-android-{arch}'
    frida_bin = download_dir / fserver
    if frida_bin.is_file():
        return True
    if not is_internet_available():
        return False
    try:
        proxies, verify = upstream_proxy('https')
    except Exception:
        logger.exception('[ERROR] Setting upstream proxy')
    try:
        response = requests.get(f'{settings.FRIDA_SERVER}{version}',
                                timeout=5,
                                proxies=proxies,
                                verify=verify)
        for item in response.json()['assets']:
            if item['name'] == f'{fserver}.xz':
                url = item['browser_download_url']
                return download_frida_server(url, version, fserver, proxies, verify)
        return False
    except Exception:
        logger.exception('[ERROR] Fetching Frida Server Release')
    return False
