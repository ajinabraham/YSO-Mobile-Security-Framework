import logging
import sys
import shutil
import tempfile
import zipfile
import platform
import ssl
from pathlib import Path
from urllib.request import (
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
    getproxies,
)

from mobsf.MobSF.proxy import upstream_proxy

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)-15s - %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S')
logger = logging.getLogger(__name__)


def download_file(url, file_path):
    req = Request(url)
    system_proxies = getproxies()
    if system_proxies:
        proxies = system_proxies
    else:
        proxies, verify = upstream_proxy('https', for_urllib=True)
    proxy_handler = ProxyHandler(proxies)
    if verify:
        ssl_context = ssl.create_default_context()
    else:
        ssl_context = ssl._create_unverified_context()
    https_handler = HTTPSHandler(context=ssl_context)
    opener = build_opener(proxy_handler, https_handler)
    with opener.open(req) as response:
        if response.status == 200:
            file_size = int(response.headers.get('Content-Length', 0))
            downloaded = 0
            block_size = 8192  # 8KB

            with open(file_path, 'wb') as f:
                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    downloaded += len(buffer)
                    f.write(buffer)

                    # Print progress
                    if file_size > 0:
                        done = int(50 * downloaded / file_size)
                        fmt = (f'\r[{"#" * done}{"-" * (50 - done)}] '
                               f'{downloaded * 100 / file_size:.2f}%')
                        sys.stdout.write(fmt)
                        sys.stdout.flush()

            if downloaded != file_size:
                err = (f'Downloaded file size ({downloaded}) '
                       f'does not match expected size ({file_size})')
                raise Exception(err)

            return downloaded
        else:
            raise Exception(f'Failed to download file. Status code: {response.status}')


def install_jadx(mobsf_home, version='1.5.0'):
    """Install JADX dynamically."""
    try:
        url = ('https://github.com/skylot/jadx/releases/download/'
               f'v{version}/jadx-{version}.zip')
        jadx_dir = Path(mobsf_home) / 'tools' / 'jadx'
        extract_dir = jadx_dir / f'jadx-{version}'

        if extract_dir.exists():
            logger.info('JADX is already installed at %s', extract_dir)
            return

        logger.info('Downloading JADX from %s', url)
        shutil.rmtree(jadx_dir, ignore_errors=True)

        with tempfile.NamedTemporaryFile(
                delete=False,
                mode='wb',
                suffix='.zip') as tmp_zip_file:

            downloaded_size = download_file(url, tmp_zip_file.name)
            logger.info('JADX download complete. File size: %d bytes', downloaded_size)

            # Extract the zip file
            logger.info('Extracting JADX to %s', extract_dir)
            extract_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(tmp_zip_file.name, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    zip_ref.extract(member, extract_dir)

        # Set execute permission
        set_rwxr_xr_x_permission_recursively(extract_dir)

        logger.info('JADX installed successfully')
    except Exception:
        logger.exception('Error during JADX installation')
    finally:
        if 'tmp_zip_file' in locals():
            Path(tmp_zip_file.name).unlink()


def set_rwxr_xr_x_permission_recursively(directory_path):
    """Set execute permissions recursively."""
    if platform.system() == 'Windows':
        logger.info('Permission setting is skipped on non-Unix systems.')
        return

    logger.info('Setting execute permission for JADX directory')
    directory_path.chmod(0o755)

    # Recursively set permissions for all files and
    # directories within the root directory
    for path in directory_path.rglob('*'):
        path.chmod(0o755)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    install_jadx(sys.argv[1])
