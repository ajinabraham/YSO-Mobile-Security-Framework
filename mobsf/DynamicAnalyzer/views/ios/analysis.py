# -*- coding: utf_8 -*-
"""iOS Dynamic Analysis."""
import logging
import json
import re
from pathlib import Path

from mobsf.StaticAnalyzer.views.common.shared_func import (
    EMAIL_REGEX,
    URL_REGEX,
)
from mobsf.DynamicAnalyzer.views.android.analysis import (
    get_app_files,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)

logger = logging.getLogger(__name__)


def get_screenshots(checksum, download_dir):
    """Get Screenshots."""
    screenshots = []
    screen_dir = Path(download_dir)
    for img in screen_dir.glob('*.png'):
        if img.name.startswith(checksum):
            screenshots.append(img.name)
    return screenshots


def get_logs_data(app_dir):
    """Get Data for analysis."""
    data = []
    dump_file = Path(app_dir) / 'mobsf_dump_file.txt'
    fd_log_file = Path(app_dir) / 'mobsf_frida_out.txt'
    if dump_file.exists():
        data.append(dump_file.read_text('utf-8', 'ignore'))
    if fd_log_file.exists():
        data.append(fd_log_file.read_text('utf-8', 'ignore'))
    return '\n'.join(data)


def run_analysis(app_dir, checksum):
    """Run Dynamic File Analysis."""
    analysis_result = {}
    logger.info('iOS Dynamic File Analysis')
    domains = {}
    # Collect Log data
    data = get_logs_data(app_dir)
    urls = re.findall(URL_REGEX, data.lower())
    if urls:
        urls = list(set(urls))
    else:
        urls = []
    # Domain Extraction and Malware Check
    logger.info('Performing Malware Check on extracted Domains')
    domains = MalwareDomainCheck().scan(urls)

    # Email Etraction Regex
    emails = []
    for email in EMAIL_REGEX.findall(data.lower()):
        if (email not in emails) and (not email.startswith('//')):
            emails.append(email)
    analysis_result['appdata'] = get_app_files(
        app_dir,
        f'{checksum}-app-container')
    analysis_result['urls'] = urls
    analysis_result['domains'] = domains
    analysis_result['emails'] = emails
    return analysis_result


def ios_api_analysis(app_dir):
    """The iOS API Analysis."""
    dump = {
        'cookies': [],
        'crypto': [],
        'network': [],
        'files': set(),
        'keychain': [],
        'logs': set(),
        'credentials': [],
        'userdefaults': {},
        'pasteboard': [],
        'textinputs': [],
        'datadir': [],
        'sqlite': [],
    }
    try:
        dump_file = app_dir / 'mobsf_dump_file.txt'
        if not dump_file.exists():
            return dump
        logger.info('Frida Analyzing Dump data')
        data = dump_file.read_text(
            encoding='utf-8',
            errors='ignore').splitlines()
        for line in data:
            parsed = json.loads(line)
            if parsed.get('cookies'):
                dump['cookies'] = parsed['cookies']
            elif parsed.get('crypto'):
                dump['crypto'].append(parsed['crypto'])
            elif parsed.get('filename'):
                dump['files'].add(parsed['filename'])
            elif parsed.get('keychain'):
                dump['keychain'] = parsed['keychain']
            elif parsed.get('nslog'):
                dump['logs'].add(parsed['nslog'])
            elif parsed.get('credentialstorage'):
                dump['credentials'] = parsed['credentialstorage']
            elif parsed.get('nsuserdefaults'):
                dump['userdefaults'] = parsed['nsuserdefaults']
            elif parsed.get('pasteboard'):
                dump['pasteboard'].append(parsed['pasteboard'])
            elif parsed.get('textinput'):
                dump['textinputs'].append(parsed['textinput'])
            elif parsed.get('network'):
                dump['network'].append(parsed['network'])
            elif parsed.get('datadir'):
                dump['datadir'] = parsed['datadir']
            elif parsed.get('sql'):
                dump['sqlite'].append(parsed['sql'])
            if len(dump['network']) > 0:
                dump['network'] = list(
                    {v['url']: v for v in dump['network']}.values())
    except Exception:
        logger.exception('Analyzing dump data failed')
    return dump
