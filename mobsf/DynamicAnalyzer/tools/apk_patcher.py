"""Inject Frida Gadget to an APK."""
import subprocess
from pathlib import Path
from lzma import LZMAFile
from shutil import copyfileobj
from tempfile import gettempdir
import logging

import requests

from django.conf import settings

from mobsf.MobSF.proxy import upstream_proxy
from mobsf.MobSF.utils import (
    find_java_binary,
    is_file_exists,
    is_internet_available,
)


logger = logging.getLogger(__name__)


class GadgetPatcher:

    def __init__(self, app_dir, tools_dir, apk_file) -> None:
        self.app_dir = app_dir
        self.tools_dir = tools_dir
        self.apk_file = apk_file
        self.output_dir = Path(self.app_dir) / 'apktool_repack'
        if (len(settings.APKTOOL_BINARY) > 0
                and is_file_exists(settings.APKTOOL_BINARY)):
            self.apktool_path = settings.APKTOOL_BINARY
        else:
            self.apktool_path = Path(self.tools_dir) / 'apktool_2.7.0.jar'

    def decompile_apk(self):
        """Decompile APK."""
        args = [find_java_binary(),
                '-Djdk.util.zip.disableZip64ExtraFieldValidation=true',
                '-jar',
                self.apktool_path,
                '--frame-path',
                gettempdir(),
                '-f', '-r', '-s', 'd',
                self.apk_file,
                '-o',
                self.output_dir]
        manifest = self.output_dir / 'AndroidManifest.xml'
        if not is_file_exists(manifest):
            # Skip if already decompiled
            subprocess.check_output(args)

    def recompile_apk(self):
        """Recompile APK."""
        args = [find_java_binary(),
                '-Djdk.util.zip.disableZip64ExtraFieldValidation=true',
                '-jar',
                self.apktool_path,
                '-f', 'b',
                '-o',
                '.patched.apk'.join(
                    self.apk_file.rsplit('.apk', 1)),
                self.output_dir]
        subprocess.check_output(args)

    def download_frida_gadget(self, frida_arch, aarch, version):
        """Download Frida Gadget."""
        gadget_bin = self.output_dir / 'lib' / {aarch} / 'libfrida-gadget.so'
        fgadget = f'frida-gadget-{version}-android-{frida_arch}.so'
        if gadget_bin.is_file():
            return True
        if not is_internet_available():
            return None
        try:
            proxies, verify = upstream_proxy('https')
        except Exception:
            logger.exception('[ERROR] Setting upstream proxy')
            return None
        try:
            response = requests.get(f'{settings.FRIDA_SERVER}{version}',
                                    timeout=5,
                                    proxies=proxies,
                                    verify=verify)
            for item in response.json()['assets']:
                if item['name'] == f'{fgadget}.xz':
                    url = item['browser_download_url']
                    break
            if not url:
                return None
            logger.info('Downloading frida-gadget %s', fgadget)
            with requests.get(url,
                              timeout=5,
                              stream=True,
                              proxies=proxies,
                              verify=verify) as r:
                with LZMAFile(r.raw) as f:
                    with open(gadget_bin, 'wb') as flip:
                        copyfileobj(f, flip)
                return True
        except Exception:
            logger.exception('[ERROR] Fetching Frida Gadget Release')
        return None
