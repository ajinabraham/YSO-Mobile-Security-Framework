# -*- coding: utf_8 -*-
"""
Shared Functions.

AppSec Dashboard
"""
import logging
import math

from django.shortcuts import render

from mobsf.MobSF import settings
from mobsf.MobSF.utils import (
    is_md5,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry as adb)
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry as idb)
from mobsf.MobSF.views.authentication import (
    login_required,
)

logger = logging.getLogger(__name__)


def common_fields(findings, data):
    """Common Fields for Android and iOS."""
    # Code Analysis
    for cd in data['code_analysis']['findings'].values():
        if cd['metadata']['severity'] == 'good':
            sev = 'secure'
        else:
            sev = cd['metadata']['severity']
        desc = cd['metadata']['description']
        ref = cd['metadata'].get('ref', '')

        files_dict = cd.get('files', {})
        files_lines = [f'{file}, line(s) {lines}'
                       for file, lines in files_dict.items()]
        all_files_str = '\n'.join(files_lines)

        if files_dict:
            fdesc = f'{desc}\n{ref}\n\nFiles:\n{all_files_str}'
        else:
            fdesc = f'{desc}\n{ref}'

        findings[sev].append({
            'title': cd['metadata']['description'],
            'description': fdesc,
            'section': 'code',
        })
    # Permissions
    dang_perms = []
    fmt_perm = ''
    for pm, meta in data['permissions'].items():
        status = meta['status']
        description = meta.get('description')
        if status == 'dangerous':
            info = meta.get('info')
            if not info:
                info = meta.get('reason')
            dang_perms.append(
                f'{pm} ({status}): '
                f'{info} - {description}')
    if dang_perms:
        fmt_perm += '\n\n'.join(dang_perms)
        findings['hotspot'].append({
            'title': (
                f'Found {len(dang_perms)} '
                'critical permission(s)'),
            'description': (
                'Ensure that these permissions '
                'are required by the application.\n\n'
                f'{fmt_perm}'),
            'section': 'permissions',
        })
    # File Analysis
    cert_files = None
    cfp = []
    for fa in data.get('file_analysis', []):
        if isinstance(fa, str):
            # FA is being used by so/dylib
            continue
        if 'Cert' in fa.get('finding', ''):
            cfp = fa['files']
            break
        if 'Cert' in fa.get('issue', ''):
            cert_files = fa['files']
            break
    if cert_files:
        for f in cert_files:
            cfp.append(f['file_path'])
    if cfp:
        fcerts = '\n'.join(cfp)
        findings['hotspot'].append({
            'title': (
                f'Found {len(cfp)} '
                'certificate/key file(s)'),
            'description': (
                'Ensure that these files '
                'does not contain any '
                'private information or '
                'sensitive key materials.\n\n'
                f'{fcerts}'),
            'section': 'files',
        })
    # Malicious Domains
    for domain, value in data['domains'].items():
        if value['bad'] == 'yes':
            findings['high'].append({
                'title': f'Malicious domain found - {domain}',
                'description': str(value['geolocation']),
                'section': 'domains',
            })
        if value.get('ofac') and value['ofac'] is True:
            country = ''
            if value['geolocation'].get('country_long'):
                country = value['geolocation'].get('country_long')
            elif value['geolocation'].get('region'):
                country = value['geolocation'].get('region')
            elif value['geolocation'].get('city'):
                country = value['geolocation'].get('city')
            findings['hotspot'].append({
                'title': ('App may communicate to a server '
                          f'({domain}) in OFAC sanctioned country '
                          f'({country})'),
                'description': str(value['geolocation']),
                'section': 'domains',
            })
    # Firebase
    for fb in data['firebase_urls']:
        findings[fb['severity']].append({
            'title': fb['title'],
            'description': fb['description'],
            'section': 'firebase',
        })
    # Trackers
    if 'trackers' in data['trackers']:
        findings['total_trackers'] = data['trackers']['total_trackers']
        t = len(data['trackers']['trackers'])
        findings['trackers'] = t
        if t > 4:
            sev = 'hotspot' if settings.EFR_01 == '1' else 'high'
            findings[sev].append({
                'title': 'Application contains Privacy Trackers',
                'description': (
                    f'This app has more than {t} privacy trackers.'
                    ' Trackers can track device or users and '
                    'are privacy concerns for end users.'),
                'section': 'trackers',
            })
        elif t > 0:
            sev = 'hotspot' if settings.EFR_01 == '1' else 'warning'
            findings[sev].append({
                'title': 'Application contains Privacy Trackers',
                'description': (
                    f'This app has {t} privacy trackers.'
                    ' Trackers can track device or users and '
                    'are privacy concerns for end users.'),
                'section': 'trackers',
            })
        else:
            findings['secure'].append({
                'title': 'This application has no privacy trackers',
                'description': (
                    'This application does not include any user '
                    'or device trackers. Unable to find trackers '
                    'during static analysis.'),
                'section': 'trackers',
            })
    # Possible Hardcoded Secrets
    secrets = data['secrets']
    if len(secrets) > 1:
        sec = '\n'.join(secrets)
        sev = 'hotspot' if settings.EFR_01 == '1' else 'warning'
        findings[sev].append({
            'title': 'This app may contain hardcoded secrets',
            'description': (
                'The following secrets were identified from the app. '
                'Ensure that these are not secrets or private information.\n'
                f'{sec}'),
            'section': 'secrets',
        })
    high = len(findings.get('high'))
    warn = len(findings.get('warning'))
    sec = len(findings.get('secure'))
    findings['security_score'] = get_secure_score(high, warn, sec)
    findings['app_name'] = data.get('app_name', '')
    findings['file_name'] = data.get('file_name', '')
    findings['hash'] = data['md5']


def get_secure_score(high, warn, sec):
    loss_score = high * 10 + warn * 5  - sec * 2
    normalize_reverse = 2 / (1 + pow(math.e, loss_score / 30))
    return int(min(normalize_reverse, 1) * 100)


def get_android_dashboard(context, from_ctx=False):
    """Get Android AppSec Dashboard."""
    findings = {
        'high': [],
        'warning': [],
        'info': [],
        'secure': [],
        'hotspot': [],
        'total_trackers': None,
    }
    if from_ctx:
        data = context
    else:
        data = adb(context)
    # Certificate Analysis
    if (data.get('certificate_analysis')
            and 'certificate_findings' in data['certificate_analysis']):
        for i in data['certificate_analysis']['certificate_findings']:
            if i[0] == 'info':
                continue
            findings[i[0]].append({
                'title': i[2],
                'description': i[1],
                'section': 'certificate',
            })
    # Network Security
    if (data.get('network_security')
            and 'network_findings' in data['network_security']):
        for n in data['network_security']['network_findings']:
            desc = '\n'.join(n['scope'])
            desc = f'Scope:\n{desc}\n\n'
            title_parts = n['description'].split('.', 1)
            if len(title_parts) > 1:
                desc += title_parts[1].strip()
                title = title_parts[0]
            else:
                title = n['description']
            findings[n['severity']].append({
                'title': title,
                'description': desc,
                'section': 'network',
            })
    # Manifest Analysis
    if (data.get('manifest_analysis')
            and 'manifest_findings' in data['manifest_analysis']):
        for m in data['manifest_analysis']['manifest_findings']:
            if m['severity'] == 'info':
                continue
            title = m['title'].replace('<strong>', '')
            title = title.replace('</strong>', '')
            fmt = title.split('<br>', 1)
            if len(fmt) > 1:
                desc = fmt[1].replace('<br>', '') + '\n' + m['description']
            else:
                desc = m['description']
            findings[m['severity']].append({
                'title': fmt[0],
                'description': desc,
                'section': 'manifest',
            })
    common_fields(findings, data)
    findings['version_name'] = data.get('version_name', '')
    return findings


def get_ios_dashboard(context, from_ctx=False):
    """Get iOS AppSec Dashboard."""
    findings = {
        'high': [],
        'warning': [],
        'info': [],
        'secure': [],
        'hotspot': [],
        'total_trackers': None,
    }
    if from_ctx:
        data = context
    else:
        data = idb(context)
    # Transport Security
    if (data.get('ats_analysis')
            and 'ats_findings' in data['ats_analysis']):
        for n in data['ats_analysis']['ats_findings']:
            findings[n['severity']].append({
                'title': n['issue'],
                'description': n['description'],
                'section': 'network',
            })
    # Binary Code Analysis
    if (data.get('binary_analysis')
            and 'findings' in data['binary_analysis']):
        for issue, cd in data['binary_analysis']['findings'].items():
            if cd['severity'] == 'good':
                sev = 'secure'
            else:
                sev = cd['severity']
            findings[sev].append({
                'title': issue,
                'description': str(cd['detailed_desc']),
                'section': 'binary',
            })
    # Macho Analysis
    ma = data['macho_analysis']
    if ma:
        nx = ma['nx']
        if nx['severity'] in {'high', 'warning'}:
            findings[nx['severity']].append({
                'title': 'NX bit is not set properly for this application',
                'description': nx['description'],
                'section': 'macho',
            })
        pie = ma['pie']
        if pie['severity'] in {'high', 'warning'}:
            findings[pie['severity']].append({
                'title': (
                    'PIE flag is not configured securely'
                    ' for this application binary'),
                'description': pie['description'],
                'section': 'macho',
            })
        stack_canary = ma['stack_canary']
        if stack_canary['severity'] in {'high', 'warning'}:
            findings[stack_canary['severity']].append({
                'title': (
                    'Stack Canary is not properly '
                    'configured for this application'),
                'description': stack_canary['description'],
                'section': 'macho',
            })
        arc = ma['arc']
        if arc['severity'] in {'high', 'warning'}:
            findings[arc['severity']].append({
                'title': 'Application binary is not compiled with ARC flag',
                'description': arc['description'],
                'section': 'macho',
            })
        rpath = ma['rpath']
        if rpath['severity'] in {'high', 'warning'}:
            findings[rpath['severity']].append({
                'title': 'Application binary has rpath set',
                'description': rpath['description'],
                'section': 'macho',
            })
        symbol = ma['symbol']
        if symbol['severity'] in {'high', 'warning'}:
            findings[symbol['severity']].append({
                'title': 'Application binary does not have symbols stripped',
                'description': symbol['description'],
                'section': 'macho',
            })
    common_fields(findings, data)
    findings['version_name'] = data.get('app_version', '')
    return findings


@login_required
def appsec_dashboard(request, checksum, api=False):
    """Provide data for appsec dashboard."""
    try:
        if not is_md5(checksum):
            # We need this check since checksum is not validated
            # in REST API
            return print_n_send_error_response(
                request,
                'Invalid Hash',
                api)
        android_static_db = StaticAnalyzerAndroid.objects.filter(
            MD5=checksum)
        ios_static_db = StaticAnalyzerIOS.objects.filter(
            MD5=checksum)
        if android_static_db.exists():
            context = get_android_dashboard(android_static_db)
        elif ios_static_db.exists():
            context = get_ios_dashboard(ios_static_db)
        else:
            if api:
                return {'not_found': 'Report not found or supported'}
            else:
                msg = 'Report not found or supported'
                return print_n_send_error_response(request, msg, api)
        context['version'] = settings.MOBSF_VER
        context['title'] = 'AppSec Scorecard'
        context['efr01'] = True if settings.EFR_01 == '1' else False
        if api:
            return context
        else:
            return render(
                request,
                'static_analysis/appsec_dashboard.html',
                context)
    except Exception as exp:
        logger.exception('Error Generating Application Security Dashboard')
        msg = str(exp)
        exp = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp)
        else:
            return print_n_send_error_response(request, msg, False, exp)
