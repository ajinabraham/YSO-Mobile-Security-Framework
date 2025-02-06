"""Common Utils."""
import ast
import base64
import hashlib
import io
import json
import logging
import ntpath
import os
import platform
import random
import re
import sys
import shutil
import signal
import string
import subprocess
import stat
import socket
import sqlite3
import unicodedata
import threading
from urllib.parse import urlparse
from pathlib import Path
from concurrent.futures import (
    ThreadPoolExecutor,
    TimeoutError as ThreadPoolTimeoutError,
)

from packaging.version import Version

import distro

import psutil

import requests

from mobsf.MobSF.proxy import (
    docker_translate_localhost,
    upstream_proxy,
)

from django.shortcuts import render
from django.utils import timezone

from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.MobSF. init import api_key

from . import settings

logger = logging.getLogger(__name__)
ADB_PATH = None
BASE64_REGEX = re.compile(r'^[-A-Za-z0-9+/]*={0,3}$')
MD5_REGEX = re.compile(r'^[0-9a-f]{32}$')
# Regex to capture strings between quotes or <string> tag
STRINGS_REGEX = re.compile(r'(?<=\")(.+?)(?=\")|(?<=\<string>)(.+?)(?=\<)')
# MobSF Custom regex to catch maximum URI like strings
URL_REGEX = re.compile(
    (
        r'((?:https?://|s?ftps?://|'
        r'file://|javascript:|data:|www\d{0,3}[.])'
        r'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
    ),
    re.UNICODE)
EMAIL_REGEX = re.compile(r'[\w+.-]{1,20}@[\w-]{1,20}\.[\w]{2,10}')
USERNAME_REGEX = re.compile(r'^\w[\w\-\@\.]{1,35}$')
GOOGLE_API_KEY_REGEX = re.compile(r'AIza[0-9A-Za-z-_]{35}$')
GOOGLE_APP_ID_REGEX = re.compile(r'\d{1,2}:\d{1,50}:android:[a-f0-9]{1,50}')
PKG_REGEX = re.compile(
    r'package\s+([a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*);')


class Color(object):
    GREEN = '\033[92m'
    GREY = '\033[0;37m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def get_system_resources():
    """Get CPU and Memory Available."""
    # Get number of physical cores
    physical_cores = psutil.cpu_count(logical=False)
    # Get number of logical processors (threads)
    logical_processors = psutil.cpu_count(logical=True)
    # Get total RAM
    total_ram = psutil.virtual_memory().total / (1024 ** 3)  # Convert bytes to GB
    return physical_cores, logical_processors, total_ram


def print_version():
    """Print MobSF Version."""
    logger.info(settings.BANNER)
    ver = settings.MOBSF_VER
    logger.info('Author: Ajin Abraham | opensecurity.in')
    mobsf_api_key = api_key(settings.MOBSF_HOME)
    if platform.system() == 'Windows':
        logger.info('Mobile Security Framework %s', ver)
        print(f'REST API Key: {mobsf_api_key}')
        print('Default Credentials: mobsf/mobsf')
    else:
        logger.info(
            '%sMobile Security Framework %s%s', Color.GREY, ver, Color.END)
        print(f'REST API Key: {Color.BOLD}{mobsf_api_key}{Color.END}')
        print(f'Default Credentials: {Color.BOLD}mobsf/mobsf{Color.END}')
    os = platform.system()
    pltfm = platform.platform()
    dist = ' '.join(distro.linux_distribution(
        full_distribution_name=False)).strip()
    dst_str = ' '
    if dist:
        dst_str = f' ({dist}) '
    env_str = f'OS Environment: {os}{dst_str}{pltfm}'
    logger.info(env_str)
    cores, threads, ram = get_system_resources()
    logger.info('CPU Cores: %s, Threads: %s, RAM: %.2f GB', cores, threads, ram)
    find_java_binary()
    check_basic_env()
    thread = threading.Thread(target=check_update, name='check_update')
    thread.start()


def check_update():
    try:
        if not is_internet_available():
            logger.warning('Internet Not Available. Skipping Update check')
            return
        logger.info('Checking for Update.')
        github_url = settings.GITHUB_URL
        try:
            proxies, verify = upstream_proxy('https')
        except Exception:
            logger.exception('Setting upstream proxy')
        local_version = settings.VERSION
        response = requests.head(github_url, timeout=5,
                                 proxies=proxies, verify=verify)
        remote_version = response.next.path_url.split('v')[1]
        if remote_version:
            sem_loc = Version(local_version)
            sem_rem = Version(remote_version)
            if sem_loc < sem_rem:
                logger.warning('A new version of MobSF is available, '
                               'Please update to %s from master branch.',
                               remote_version)
            else:
                logger.info('No updates available.')
    except requests.exceptions.HTTPError:
        logger.warning('\nCannot check for updates..'
                       ' No Internet Connection Found.')
        return
    except Exception:
        logger.exception('Cannot Check for updates.')


def find_java_binary():
    """Find Java."""
    # Respect user settings
    if platform.system() == 'Windows':
        jbin = 'java.exe'
    else:
        jbin = 'java'
    if is_dir_exists(settings.JAVA_DIRECTORY):
        if settings.JAVA_DIRECTORY.endswith('/'):
            return settings.JAVA_DIRECTORY + jbin
        elif settings.JAVA_DIRECTORY.endswith('\\'):
            return settings.JAVA_DIRECTORY + jbin
        else:
            return settings.JAVA_DIRECTORY + '/' + jbin
    if os.getenv('JAVA_HOME'):
        java = os.path.join(
            os.getenv('JAVA_HOME'),
            'bin',
            jbin)
        if is_file_exists(java):
            return java
    return 'java'


def find_aapt(tool_name):
    """Find the specified tool (aapt or aapt2)."""
    # Check system PATH for the tool
    tool_path = shutil.which(tool_name)
    if tool_path:
        return tool_path

    # Check common Android SDK locations
    home_dir = Path.home()  # Get the user's home directory
    sdk_paths = [
        home_dir / 'Library' / 'Android' / 'sdk',  # macOS
        home_dir / 'Android' / 'Sdk',              # Linux
        home_dir / 'AppData' / 'Local' / 'Android' / 'Sdk',  # Windows
    ]

    for sdk_path in sdk_paths:
        build_tools_path = sdk_path / 'build-tools'
        if build_tools_path.exists():
            for version in sorted(build_tools_path.iterdir(), reverse=True):
                tool_path = version / tool_name
                if tool_path.exists():
                    return str(tool_path)

    return None


def print_n_send_error_response(request,
                                msg,
                                api=False,
                                exp='Description'):
    """Print and log errors."""
    logger.error(msg)
    if api:
        api_response = {'error': msg}
        return api_response
    else:
        context = {
            'title': 'Error',
            'exp': exp,
            'doc': msg,
            'version': settings.MOBSF_VER,
        }
        template = 'general/error.html'
        return render(request, template, context, status=500)


def filename_from_path(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def get_md5(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest()


def find_between(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ''


def is_number(s):
    if not s:
        return False
    if s == 'NaN':
        return False
    try:
        float(s)
        return True
    except ValueError:
        pass
    try:
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
    return False


def python_list(value):
    if not value:
        value = []
    if isinstance(value, list):
        return value
    return ast.literal_eval(value)


def python_dict(value):
    if not value:
        value = {}
    if isinstance(value, dict):
        return value
    return ast.literal_eval(value)


def is_base64(b_str):
    return BASE64_REGEX.match(b_str)


def is_internet_available():
    try:
        proxies, verify = upstream_proxy('https')
    except Exception:
        logger.exception('Setting upstream proxy')
    try:
        requests.get(settings.GOOGLE,
                     timeout=5,
                     proxies=proxies,
                     verify=verify)
        return True
    except Exception:
        try:
            requests.get(settings.BAIDU,
                         timeout=5,
                         proxies=proxies,
                         verify=verify)
            return True
        except Exception:
            return False


def sha256(file_path):
    blocksize = 65536
    hasher = hashlib.sha256()
    with io.open(file_path, mode='rb') as afile:
        buf = afile.read(blocksize)
        while buf:
            hasher.update(buf)
            buf = afile.read(blocksize)
    return hasher.hexdigest()


def sha256_object(file_obj):
    blocksize = 65536
    hasher = hashlib.sha256()
    buf = file_obj.read(blocksize)
    while buf:
        hasher.update(buf)
        buf = file_obj.read(blocksize)
    return hasher.hexdigest()


def gen_sha256_hash(msg):
    """Generate SHA 256 Hash of the message."""
    if isinstance(msg, str):
        msg = msg.encode('utf-8')
    hash_object = hashlib.sha256(msg)
    return hash_object.hexdigest()


def is_file_exists(file_path):
    if os.path.isfile(file_path):
        return True
    # This fix situation where a user just typed "adb" or another executable
    # inside settings.py/config.py
    if shutil.which(file_path):
        return True
    else:
        return False


def is_dir_exists(dir_path):
    if os.path.isdir(dir_path):
        return True
    else:
        return False


def find_process_by(name):
    """Return a set of process path matching name."""
    proc = set()
    for p in psutil.process_iter(attrs=['name']):
        if (name == p.info['name']):
            proc.add(p.exe())
    return proc


def get_device():
    """Get Device."""
    if os.getenv('ANALYZER_IDENTIFIER'):
        return docker_translate_localhost(
            os.getenv('ANALYZER_IDENTIFIER'))
    elif settings.ANALYZER_IDENTIFIER:
        return docker_translate_localhost(
            settings.ANALYZER_IDENTIFIER)
    else:
        dev_id = ''
        out = subprocess.check_output([get_adb(), 'devices']).splitlines()
        if len(out) > 2:
            dev_id = out[1].decode('utf-8').split('\t')[0]
            if 'daemon started successfully' not in dev_id:
                return docker_translate_localhost(dev_id)
    logger.error(get_android_dm_exception_msg())


def get_adb():
    """Get ADB binary path."""
    try:
        adb_loc = None
        adb_msg = ('Set adb path, ADB_BINARY in'
                   f' {get_config_loc()}'
                   ' with same adb binary used'
                   ' by Genymotion VM/Emulator AVD.')
        global ADB_PATH
        if (len(settings.ADB_BINARY) > 0
                and is_file_exists(settings.ADB_BINARY)):
            ADB_PATH = settings.ADB_BINARY
            return ADB_PATH
        if ADB_PATH:
            return ADB_PATH
        if platform.system() == 'Windows':
            adb_loc = find_process_by('adb.exe')
        else:
            adb_loc = find_process_by('adb')
        if len(adb_loc) > 1:
            logger.warning('Multiple ADB locations found. %s', adb_msg)
            logger.warning(adb_loc)
        if adb_loc:
            ADB_PATH = adb_loc.pop()
            return ADB_PATH
    except Exception:
        if not adb_loc:
            logger.warning('Cannot find adb! %s', adb_msg)
        logger.exception('Getting ADB Location')
    finally:
        if ADB_PATH:
            os.environ['MOBSF_ADB'] = ADB_PATH
        else:
            os.environ['MOBSF_ADB'] = 'adb'
            logger.warning('Dynamic Analysis related '
                           'functions will not work. '
                           '\nMake sure a Genymotion Android VM/'
                           'Android Studio Emulator'
                           ' is running before performing'
                           ' Dynamic Analysis.')
    return 'adb'


def check_basic_env():
    """Check if we have basic env for MobSF to run."""
    logger.info('MobSF Basic Environment Check')
    try:
        import http_tools  # noqa F401
    except ImportError:
        logger.exception('httptools not installed!')
        os.kill(os.getpid(), signal.SIGTERM)
    try:
        import lxml  # noqa F401
    except ImportError:
        logger.exception('lxml is not installed!')
        os.kill(os.getpid(), signal.SIGTERM)
    if not is_file_exists(find_java_binary()):
        logger.error(
            'JDK 8+ is not available. '
            'Set JAVA_HOME environment variable'
            ' or JAVA_DIRECTORY in '
            '%s', get_config_loc())
        logger.info('Current Configuration: '
                    'JAVA_DIRECTORY=%s', settings.JAVA_DIRECTORY)
        logger.info('Example Configuration:'
                    '\nJAVA_DIRECTORY = "C:/Program Files/'
                    'Java/jdk1.7.0_17/bin/"'
                    '\nJAVA_DIRECTORY = "/usr/bin/"')
        os.kill(os.getpid(), signal.SIGTERM)


def update_local_db(db_name, url, local_file):
    """Update Local DBs."""
    update = None
    inmemoryfile = None
    try:
        proxies, verify = upstream_proxy('https')
    except Exception:
        logger.exception('[ERROR] Setting upstream proxy')
    try:
        response = requests.get(url,
                                timeout=3,
                                proxies=proxies,
                                verify=verify)
        resp = response.content
        inmemoryfile = io.BytesIO(resp)
        # Create on first run
        if not is_file_exists(local_file):
            return resp
        # Check1: SHA256 Change
        if sha256_object(inmemoryfile) != sha256(local_file):
            # Hash Changed
            logger.info('%s Database is outdated!', db_name)
            update = resp
        else:
            logger.info('%s Database is up-to-date', db_name)
        return update
    except (requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError):
        logger.warning('Failed to download %s DB.', db_name)
    except Exception:
        logger.exception('[ERROR] %s DB Update', db_name)
        return update
    finally:
        if inmemoryfile:
            inmemoryfile.truncate(0)


def read_sqlite(sqlite_file):
    """Sqlite Dump - Readable Text."""
    logger.info('Reading SQLite db')
    table_dict = {}
    try:
        con = sqlite3.connect(sqlite_file)
        cur = con.cursor()
        cur.execute('SELECT name FROM sqlite_master WHERE type=\'table\';')
        tables = cur.fetchall()
        for table in tables:
            table_dict[table[0]] = {'head': [], 'data': []}
            cur.execute('PRAGMA table_info(\'%s\')' % table)
            rows = cur.fetchall()
            for sq_row in rows:
                table_dict[table[0]]['head'].append(sq_row[1])
            cur.execute('SELECT * FROM \'%s\'' % table)
            rows = cur.fetchall()
            for sq_row in rows:
                tmp_row = []
                for each_row in sq_row:
                    tmp_row.append(str(each_row))
                table_dict[table[0]]['data'].append(tmp_row)
    except Exception:
        logger.exception('Reading SQLite db')
    return table_dict


def is_pipe_or_link(path):
    """Check for named pipe."""
    return os.path.islink(path) or stat.S_ISFIFO(os.stat(path).st_mode)


def get_network():
    """Get Network IPs."""
    ips = []
    try:
        for det in psutil.net_if_addrs().values():
            ips.append(det[0].address)
    except Exception:
        logger.exception('Failed to enumerate network interfaces')
    return ips


def get_proxy_ip(identifier):
    """Get Proxy IP."""
    proxy_ip = None
    try:
        if not identifier:
            return proxy_ip
        ips = get_network()
        if ':' not in identifier or not ips:
            return proxy_ip
        device_ip = identifier.split(':', 1)[0]
        ip_range = device_ip.rsplit('.', 1)[0]
        guess_ip = ip_range + '.1'
        if guess_ip in ips:
            return guess_ip
        for ip_addr in ips:
            to_check = ip_addr.rsplit('.', 1)[0]
            if to_check == ip_range:
                return ip_addr
    except Exception:
        logger.error('Error getting Proxy IP')
    return proxy_ip


def is_safe_path(safe_root, check_path):
    """Detect Path Traversal."""
    safe_root = os.path.realpath(os.path.normpath(safe_root))
    check_path = os.path.realpath(os.path.normpath(check_path))
    return os.path.commonprefix([check_path, safe_root]) == safe_root


def file_size(app_path):
    """Return the size of the file."""
    return round(float(os.path.getsize(app_path)) / (1024 * 1024), 2)


def is_md5(user_input):
    """Check if string is valid MD5."""
    stat = MD5_REGEX.match(user_input)
    if not stat:
        logger.error('Invalid scan hash')
    return stat


def get_config_loc():
    """Get config location."""
    if settings.USE_HOME:
        return os.path.join(
            os.path.expanduser('~'),
            '.MobSF',
            'config.py',
        )
    else:
        return 'MobSF/settings.py'


def clean_filename(filename, replace=' '):
    if platform.system() == 'Windows':
        whitelist = f'-_.() {string.ascii_letters}{string.digits}'
        # replace spaces
        for r in replace:
            filename = filename.replace(r, '_')
        # keep only valid ascii chars
        cleaned_filename = unicodedata.normalize(
            'NFKD', filename).encode('ASCII', 'ignore').decode()
        # keep only whitelisted chars
        return ''.join(c for c in cleaned_filename if c in whitelist)
    return filename


def cmd_injection_check(data):
    """OS Cmd Injection from Commix."""
    breakers = [
        ';', '%3B', '&', '%26', '&&',
        '%26%26', '|', '%7C', '||',
        '%7C%7C', '%0a', '%0d%0a',
    ]
    return any(i in data for i in breakers)


def strict_package_check(user_input):
    """Strict package name check.

    For android package and ios bundle id
    """
    pat = re.compile(r'^([a-zA-Z]{1}[\w.-]{1,255})$')
    resp = re.match(pat, user_input)
    if not resp or '..' in user_input:
        logger.error('Invalid package name/bundle id/class name')
    return resp


def strict_ios_class(user_input):
    """Strict check to see if input is valid iOS class."""
    pat = re.compile(r'^([\w\.]+)$')
    resp = re.match(pat, user_input)
    if not resp:
        logger.error('Invalid class name')
    return resp


def is_instance_id(user_input):
    """Check if string is valid instance id."""
    reg = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    stat = re.match(reg, user_input)
    if not stat:
        logger.error('Invalid instance identifier')
    return stat


def common_check(instance_id):
    """Common checks for instance APIs."""
    if not getattr(settings, 'CORELLIUM_API_KEY', ''):
        return {
            'status': 'failed',
            'message': 'Missing Corellium API key'}
    elif not is_instance_id(instance_id):
        return {
            'status': 'failed',
            'message': 'Invalid instance identifier'}
    else:
        return None


def is_path_traversal(user_input):
    """Check for path traversal."""
    if not user_input:
        return False
    if (('../' in user_input)
        or ('%2e%2e' in user_input)
        or ('..' in user_input)
            or ('%252e' in user_input)):
        logger.error('Path traversal attack detected')
        return True
    return False


def is_zip_magic(file_obj):
    magic = file_obj.read(4)
    file_obj.seek(0, 0)
    # ZIP magic PK.. no support for spanned and empty arch
    return bool(magic == b'\x50\x4B\x03\x04')


def is_elf_so_magic(file_obj):
    magic = file_obj.read(4)
    file_obj.seek(0, 0)
    # ELF/SO Magic
    return bool(magic == b'\x7F\x45\x4C\x46')


def is_dylib_magic(file_obj):
    magic = file_obj.read(4)
    file_obj.seek(0, 0)
    # DYLIB Magic
    magics = (
        b'\xCA\xFE\xBA\xBE',  # 32 bit
        b'\xFE\xED\xFA\xCE',  # 32 bit
        b'\xCE\xFA\xED\xFE',  # 32 bit
        b'\xFE\xED\xFA\xCF',  # 64 bit
        b'\xCF\xFA\xED\xFE',  # 64 bit
        b'\xCA\xFE\xBA\xBF',  # 64 bit
    )
    return bool(magic in magics)


def is_a_magic(file_obj):
    magic = file_obj.read(4)
    file_obj.seek(0, 0)
    magics = (
        b'\x21\x3C\x61\x72',
        b'\xCA\xFE\xBA\xBF',  # 64 bit
        b'\xCA\xFE\xBA\xBE',  # 32 bit
    )
    return bool(magic in magics)


def disable_print():
    sys.stdout = open(os.devnull, 'w')


# Restore
def enable_print():
    sys.stdout = sys.__stdout__


def find_key_in_dict(key, var):
    """Recursively look up a key in a nested dict."""
    if hasattr(var, 'items'):
        for k, v in var.items():
            if k == key:
                yield v
            if isinstance(v, dict):
                for result in find_key_in_dict(key, v):
                    yield result
            elif isinstance(v, list):
                for d in v:
                    for result in find_key_in_dict(key, d):
                        yield result


def key(data, key_name):
    """Return the data for a key_name."""
    return data.get(key_name)


def replace(value, arg):
    """
    Replacing filter.

    Use `{{ "aaa"|replace:"a|b" }}`
    """
    if len(arg.split('|')) != 2:
        return value

    what, to = arg.split('|')
    return value.replace(what, to)


def pathify(value):
    """Convert to path."""
    return value.replace('.', '/')


def relative_path(value):
    """Show relative path to two parents."""
    sep = None
    if '/' in value:
        sep = '/'
    elif '\\\\' in value:
        sep = '\\\\'
    elif '\\' in value:
        sep = '\\'
    if not sep or value.count(sep) < 2:
        return value
    path = Path(value)
    return path.relative_to(path.parent.parent).as_posix()


def pretty_json(value):
    """Pretty print JSON."""
    try:
        return json.dumps(json.loads(value), indent=4)
    except Exception:
        return value


def base64_decode(value):
    """Try Base64 decode."""
    commonb64s = ('eyJ0')
    decoded = None
    try:
        if is_base64(value) or value.startswith(commonb64s):
            decoded = base64.b64decode(
                value).decode('ISO-8859-1')
    except Exception:
        pass
    if decoded:
        return f'{value}\n\nBase64 Decoded: {decoded}'
    return value


def base64_encode(value):
    """Base64 encode."""
    if isinstance(value, str):
        value = value.encode('utf-8')
    return base64.b64encode(value)


def android_component(data):
    """Return Android component from data."""
    cmp = ''
    if 'Activity-Alias' in data:
        cmp = 'activity_alias_'
    elif 'Activity' in data:
        cmp = 'activity_'
    elif 'Service' in data:
        cmp = 'service_'
    elif 'Content Provider' in data:
        cmp = 'provider_'
    elif 'Broadcast Receiver' in data:
        cmp = 'receiver_'
    return cmp


def get_android_dm_exception_msg():
    return (
        'Is your Android VM/emulator running? MobSF cannot'
        ' find the android device identifier.'
        ' Please read official documentation.'
        ' If this error persists, set ANALYZER_IDENTIFIER in '
        f'{get_config_loc()} or via environment variable'
        ' MOBSF_ANALYZER_IDENTIFIER')


def get_android_src_dir(app_dir, typ):
    """Get Android source code location."""
    src = None
    if typ == 'apk':
        src = app_dir / 'java_source'
    elif typ == 'studio':
        src = app_dir / 'app' / 'src' / 'main' / 'java'
        kt = app_dir / 'app' / 'src' / 'main' / 'kotlin'
        if not src.exists() and kt.exists():
            src = kt
    elif typ == 'eclipse':
        src = app_dir / 'src'
    return src


def settings_enabled(attr):
    """Get settings state if present."""
    disabled = ('', ' ', '""', '" "', '0', '"0"', False)
    try:
        return getattr(settings, attr) not in disabled
    except Exception:
        return False


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    """Generate random string."""
    return ''.join(random.choice(chars) for _ in range(size))


def valid_host(host):
    """Check if host is valid."""
    try:
        prefixs = ('http://', 'https://')
        if not host.startswith(prefixs):
            host = f'http://{host}'
        parsed = urlparse(host)
        domain = parsed.netloc
        path = parsed.path
        if len(domain) == 0:
            # No valid domain
            return False
        if len(path) > 0:
            # Only host is allowed
            return False
        if ':' in domain:
            # IPv6
            return False
        # Local network
        invalid_prefix = (
            '100.64.',
            '127.',
            '192.',
            '198.',
            '10.',
            '172.',
            '169.',
            '0.',
            '203.0.',
            '224.0.',
            '240.0',
            '255.255.',
            'localhost',
            '::1',
            '64::ff9b::',
            '100::',
            '2001::',
            '2002::',
            'fc00::',
            'fe80::',
            'ff00::')
        if domain.startswith(invalid_prefix):
            return False
        ip = socket.gethostbyname(domain)
        if ip.startswith(invalid_prefix):
            # Resolve dns to get IP
            return False
        return True
    except Exception:
        return False


def append_scan_status(checksum, status, exception=None):
    """Append Scan Status to Database."""
    try:
        db_obj = RecentScansDB.objects.get(MD5=checksum)
        if status == 'init':
            db_obj.SCAN_LOGS = []
            db_obj.save()
            return
        current_logs = python_dict(db_obj.SCAN_LOGS)
        current_logs.append({
            'timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status': status,
            'exception': exception})
        db_obj.SCAN_LOGS = current_logs
        db_obj.save()
    except RecentScansDB.DoesNotExist:
        # Expected to fail for iOS Dynamic Analysis Report Generation
        # Calls MalwareScan and TrackerScan with different checksum
        pass
    except Exception:
        logger.exception('Appending Scan Status to Database')


def get_scan_logs(checksum):
    """Get the scan logs for the given checksum."""
    try:
        db_entry = RecentScansDB.objects.filter(MD5=checksum)
        if db_entry.exists():
            return python_list(db_entry[0].SCAN_LOGS)
    except Exception:
        msg = 'Fetching scan logs from the DB failed.'
        logger.exception(msg)
    return []


class TaskTimeoutError(Exception):
    pass


def run_with_timeout(func, limit, *args, **kwargs):
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=limit)
        except ThreadPoolTimeoutError:
            msg = f'function <{func.__name__}> timed out after {limit} seconds'
            raise TaskTimeoutError(msg)


def set_permissions(path):
    base_path = Path(path)
    # Read/Write for directories without execute
    perm_dir = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
    # Read/Write for files
    perm_file = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH

    # Set permissions for directories and files
    for item in base_path.rglob('*'):
        try:
            if item.is_dir():
                item.chmod(perm_dir)
            elif item.is_file():
                item.chmod(perm_file)
        except Exception:
            pass
