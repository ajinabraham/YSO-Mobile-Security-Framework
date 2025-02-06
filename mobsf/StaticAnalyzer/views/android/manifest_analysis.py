# -*- coding: utf_8 -*-
# flake8: noqa
"""Module for android manifest analysis."""
import logging

import requests
from concurrent.futures import ThreadPoolExecutor

from mobsf.MobSF.utils import (
    append_scan_status,
    is_number,
    valid_host,
)

from mobsf.MobSF.proxy import upstream_proxy

from mobsf.StaticAnalyzer.views.android import (
    network_security,
)
from mobsf.StaticAnalyzer.views.android.kb import (
    android_manifest_desc,
)


logger = logging.getLogger(__name__)
ANDROID_4_2_LEVEL = 17
ANDROID_5_0_LEVEL = 21
ANDROID_8_0_LEVEL = 26
ANDROID_9_0_LEVEL = 28
ANDROID_10_0_LEVEL = 29
ANDROID_MANIFEST_FILE = 'AndroidManifest.xml'
ANDROID_API_LEVEL_MAP = {
    '1': '1.0',
    '2': '1.1',
    '3': '1.5',
    '4': '1.6',
    '5': '2.0-2.1',
    '8': '2.2-2.2.3',
    '9': '2.3-2.3.2',
    '10': '2.3.3-2.3.7',
    '11': '3.0',
    '12': '3.1',
    '13': '3.2-3.2.6',
    '14': '4.0-4.0.2',
    '15': '4.0.3-4.0.4',
    '16': '4.1-4.1.2',
    '17': '4.2-4.2.2',
    '18': '4.3-4.3.1',
    '19': '4.4-4.4.4',
    '20': '4.4W-4.4W.2',
    '21': '5.0-5.0.2',
    '22': '5.1-5.1.1',
    '23': '6.0-6.0.1',
    '24': '7.0',
    '25': '7.1-7.1.2',
    '26': '8.0',
    '27': '8.1',
    '28': '9',
    '29': '10',
    '30': '11',
    '31': '12',
    '32': '12L',
    '33': '13',
    '34': '14',
    '35': '15',
    '36': '16',
}


def assetlinks_check(act_name, well_knowns):
    """Well known assetlink check."""
    findings = []

    with ThreadPoolExecutor() as executor:
        futures = []
        for w_url, host in well_knowns.items():
            logger.info(
                'App Link Assetlinks Check - [%s] %s', act_name, host)
            futures.append(
                executor.submit(_check_url, host, w_url))
        for future in futures:
            findings.append(future.result())

    return findings


def _check_url(host, w_url):
    """Check for the presence of Assetlinks URL."""
    try:
        iden = 'sha256_cert_fingerprints'
        proxies, verify = upstream_proxy('https')
        status = False
        status_code = 0

        urls = {w_url}
        if w_url.startswith('http://'):
            # Upgrade http to https
            urls.add(f'https://{w_url[7:]}')

        for url in urls:
            r = requests.get(url,
                             timeout=5,
                             allow_redirects=False,
                             proxies=proxies,
                             verify=verify)

            status_code = r.status_code
            if (str(status_code).startswith('2') and iden in str(r.json())):
                status = True
                break
        if status_code in (301, 302):
            logger.warning('Status Code: [%d], Redirecting to '
                           'a different URL, skipping check!', status_code)
        return {'url': w_url,
                'host': host,
                'status_code': status_code,
                'status': status}

    except Exception:
        logger.error(f'Well Known Assetlinks Check for URL: {w_url}')
        return {'url': w_url,
                'host': host,
                'status_code': None,
                'status': False}


def get_browsable_activities(node, ns):
    """Get Browsable Activities."""
    try:
        browse_dic = {}
        schemes = []
        mime_types = []
        hosts = []
        ports = []
        paths = []
        path_prefixs = []
        path_patterns = []
        well_known = {}
        well_known_path = '/.well-known/assetlinks.json'
        catg = node.getElementsByTagName('category')
        for cat in catg:
            if cat.getAttribute(f'{ns}:name') == 'android.intent.category.BROWSABLE':
                data_tag = node.getElementsByTagName('data')
                for data in data_tag:
                    scheme = data.getAttribute(f'{ns}:scheme')
                    if scheme and scheme not in schemes:
                        schemes.append(scheme)
                    mime = data.getAttribute(f'{ns}:mimeType')
                    if mime and mime not in mime_types:
                        mime_types.append(mime)
                    host = data.getAttribute(f'{ns}:host')
                    if host and host not in hosts:
                        hosts.append(host)
                    port = data.getAttribute(f'{ns}:port')
                    if port and port not in ports:
                        ports.append(port)
                    path = data.getAttribute(f'{ns}:path')
                    if path and path not in paths:
                        paths.append(path)
                    path_prefix = data.getAttribute(f'{ns}:pathPrefix')
                    if path_prefix and path_prefix not in path_prefixs:
                        path_prefixs.append(path_prefix)
                    path_pattern = data.getAttribute(f'{ns}:pathPattern')
                    if path_pattern and path_pattern not in path_patterns:
                        path_patterns.append(path_pattern)
                    # Collect possible well-known paths
                    if (scheme
                        and scheme in ('http', 'https')
                        and host
                            and host != '*'):
                        host = host.replace('*.', '').replace('#', '')
                        if not valid_host(host):
                            continue
                        shost = f'{scheme}://{host}'
                        if port and is_number(port):
                            c_url = f'{shost}:{port}{well_known_path}'
                        else:
                            c_url = f'{shost}{well_known_path}'
                        well_known[c_url] = shost
        schemes = [scheme + '://' for scheme in schemes]
        browse_dic['schemes'] = schemes
        browse_dic['mime_types'] = mime_types
        browse_dic['hosts'] = hosts
        browse_dic['ports'] = ports
        browse_dic['paths'] = paths
        browse_dic['path_prefixs'] = path_prefixs
        browse_dic['path_patterns'] = path_patterns
        browse_dic['browsable'] = bool(browse_dic['schemes'])
        browse_dic['well_known'] = well_known
        return browse_dic
    except Exception:
        logger.exception('Getting Browsable Activities')


def manifest_analysis(app_dic, man_data_dic):
    """Analyse manifest file."""
    # pylint: disable=C0301
    checksum = app_dic['md5']
    mfxml = app_dic['manifest_parsed_xml']
    ns = app_dic['manifest_namespace']
    src_type = app_dic['zipped']
    app_dir = app_dic['app_dir']
    try:
        msg = 'Manifest Analysis Started'
        logger.info(msg)
        append_scan_status(checksum, msg)
        exp_count = dict.fromkeys(['act', 'ser', 'bro', 'cnt'], 0)
        applications = mfxml.getElementsByTagName('application')
        data_tag = mfxml.getElementsByTagName('data')
        intents = mfxml.getElementsByTagName('intent-filter')
        actions = mfxml.getElementsByTagName('action')
        granturipermissions = mfxml.getElementsByTagName(
            'grant-uri-permission')
        permissions = mfxml.getElementsByTagName('permission')
        ret_value = []
        ret_list = []
        exported = []
        browsable_activities = {}
        permission_dict = {}
        do_netsec = False
        debuggable = False
        # PERMISSION
        for permission in permissions:
            if permission.getAttribute(f'{ns}:protectionLevel'):
                protectionlevel = permission.getAttribute(
                    f'{ns}:protectionLevel')
                if protectionlevel == '0x00000000':
                    protectionlevel = 'normal'
                elif protectionlevel == '0x00000001':
                    protectionlevel = 'dangerous'
                elif protectionlevel == '0x00000002':
                    protectionlevel = 'signature'
                elif protectionlevel == '0x00000003':
                    protectionlevel = 'signatureOrSystem'

                permission_dict[permission.getAttribute(
                    f'{ns}:name')] = protectionlevel
            elif permission.getAttribute(f'{ns}:name'):
                permission_dict[permission.getAttribute(
                    f'{ns}:name')] = 'normal'
        # GENERAL
        if man_data_dic['min_sdk'] and int(man_data_dic['min_sdk']) < ANDROID_8_0_LEVEL:
            minsdk = man_data_dic.get('min_sdk')
            android_version = ANDROID_API_LEVEL_MAP.get(minsdk, 'XX')
            ret_list.append(('vulnerable_os_version', (android_version, minsdk,), ()))
        elif man_data_dic['min_sdk'] and int(man_data_dic['min_sdk']) < ANDROID_10_0_LEVEL:
            minsdk = man_data_dic.get('min_sdk')
            android_version = ANDROID_API_LEVEL_MAP.get(minsdk, 'XX')
            ret_list.append(('vulnerable_os_version2', (android_version, minsdk,), ()))
        # APPLICATIONS
        # Handle multiple application tags in AAR
        backupDisabled = False
        for application in applications:
            # Esteve 23.07.2016 - begin - identify permission at the
            # application level
            if application.getAttribute(f'{ns}:permission'):
                perm_appl_level_exists = True
                perm_appl_level = application.getAttribute(
                    f'{ns}:permission')
            else:
                perm_appl_level_exists = False
            # End
            if application.getAttribute(f'{ns}:usesCleartextTraffic') == 'true':
                ret_list.append(('clear_text_traffic', (), ()))
            if application.getAttribute(f'{ns}:directBootAware') == 'true':
                ret_list.append(('direct_boot_aware', (), ()))
            if application.getAttribute(f'{ns}:networkSecurityConfig'):
                item = application.getAttribute(f'{ns}:networkSecurityConfig')
                ret_list.append(('has_network_security', (item,), ()))
                do_netsec = item
            if application.getAttribute(f'{ns}:debuggable') == 'true':
                ret_list.append(('app_is_debuggable', (), ()))
                debuggable = True
            if application.getAttribute(f'{ns}:allowBackup') == 'true':
                ret_list.append(('app_allowbackup', (), ()))
            elif application.getAttribute(f'{ns}:allowBackup') == 'false':
                backupDisabled = True
            else:
                if not backupDisabled:
                    ret_list.append(('allowbackup_not_set', (), ()))
            if application.getAttribute(f'{ns}:testOnly') == 'true':
                ret_list.append(('app_in_test_mode', (), ()))
            for node in application.childNodes:
                an_or_a = ''
                if node.nodeName == 'activity':
                    itemname = 'Activity'
                    cnt_id = 'act'
                    an_or_a = 'n'
                elif node.nodeName == 'activity-alias':
                    itemname = 'Activity-Alias'
                    cnt_id = 'act'
                    an_or_a = 'n'
                elif node.nodeName == 'provider':
                    itemname = 'Content Provider'
                    cnt_id = 'cnt'
                elif node.nodeName == 'receiver':
                    itemname = 'Broadcast Receiver'
                    cnt_id = 'bro'
                elif node.nodeName == 'service':
                    itemname = 'Service'
                    cnt_id = 'ser'
                else:
                    itemname = 'NIL'
                item = ''
                # Checks for Activities
                if itemname in ['Activity', 'Activity-Alias']:
                    item = node.getAttribute(f'{ns}:name')
                    # Browsable Activities
                    browse_dic = get_browsable_activities(node, ns)
                    if browse_dic['browsable']:
                        browsable_activities[node.getAttribute(
                            f'{ns}:name')] = browse_dic
                    for finding in assetlinks_check(item, browse_dic['well_known']):
                        if not finding['status']:
                            ret_list.append(('well_known_assetlinks',
                                            (item, finding['host']),
                                            (finding['url'],
                                             finding['status_code'])))

                    # Task Affinity
                    task_affinity = node.getAttribute(f'{ns}:taskAffinity')
                    if (task_affinity):
                        ret_list.append(('task_affinity_set', (item,), ()))

                    # LaunchMode
                    try:
                        affected_sdk = int(
                            man_data_dic['min_sdk']) < ANDROID_5_0_LEVEL
                    except Exception:
                        # in case min_sdk is not defined we assume vulnerability
                        affected_sdk = True
                    launchmode = node.getAttribute(f'{ns}:launchMode')
                    modes = ('singleTask', 'singleInstance')
                    if (affected_sdk
                            and launchmode in modes):
                        ret_list.append(('non_standard_launchmode', (item,), ()))

                    # Android Task Hijacking or StrandHogg 1.0
                    try:
                        target_sdk = int(man_data_dic['target_sdk'])
                    except Exception:
                        try:
                            target_sdk = int(man_data_dic['min_sdk'])
                        except Exception:
                            target_sdk = ANDROID_8_0_LEVEL
                    if (target_sdk < ANDROID_9_0_LEVEL
                            and launchmode == 'singleTask'):
                        ret_list.append(('task_hijacking', (item,), (target_sdk,)))

                    # Android StrandHogg 2.0
                    exported_act = node.getAttribute(f'{ns}:exported')
                    if (target_sdk < ANDROID_10_0_LEVEL
                            and exported_act == 'true'
                            and (launchmode != 'singleInstance' or task_affinity != '')):
                        ret_list.append(('task_hijacking2', (item,), (target_sdk,)))

                # Exported Check
                item = ''
                is_inf = False
                is_perm_exist = False
                # Esteve 23.07.2016 - begin - initialise variables to identify
                # the existence of a permission at the component level that
                # matches a permission at the manifest level
                prot_level_exist = False
                protlevel = ''
                # End
                if itemname != 'NIL':
                    if node.getAttribute(f'{ns}:exported') == 'true':
                        perm = ''
                        item = node.getAttribute(f'{ns}:name')
                        if node.getAttribute(f'{ns}:permission'):
                            # permission exists
                            perm = ('<strong>Permission: </strong>'
                                    + node.getAttribute(f'{ns}:permission'))
                            is_perm_exist = True
                        if item != man_data_dic['mainactivity']:
                            if is_perm_exist:
                                prot = ''
                                if node.getAttribute(f'{ns}:permission') in permission_dict:
                                    prot = ('</br><strong>protectionLevel: </strong>'
                                            + permission_dict[node.getAttribute(f'{ns}:permission')])
                                    # Esteve 23.07.2016 - begin - take into account protection level of the permission when claiming that a component is protected by it;
                                    # - the permission might not be defined in the application being analysed, if so, the protection level is not known;
                                    # - activities (or activity-alias) that are exported and have an unknown or normal or dangerous protection level are
                                    # included in the EXPORTED data structure for further treatment; components in this situation are also
                                    # counted as exported.
                                    prot_level_exist = True
                                    protlevel = permission_dict[
                                        node.getAttribute(f'{ns}:permission')]
                                if prot_level_exist:
                                    if protlevel == 'normal':
                                        ret_list.append(
                                            ('exported_protected_permission_normal', (itemname, item, perm + prot), (an_or_a, itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    elif protlevel == 'dangerous':
                                        ret_list.append(
                                            ('exported_protected_permission_dangerous', (itemname, item, perm + prot), (an_or_a, itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    elif protlevel == 'signature':
                                        ret_list.append(
                                            ('exported_protected_permission_signature', (itemname, item, perm + prot), (an_or_a, itemname)))
                                    elif protlevel == 'signatureOrSystem':
                                        ret_list.append(
                                            ('exported_protected_permission_signatureorsystem', (itemname, item, perm + prot), (an_or_a, itemname)))
                                else:
                                    ret_list.append(
                                        ('exported_protected_permission_not_defined', (itemname, item, perm), (an_or_a, itemname)))
                                    if itemname in ['Activity', 'Activity-Alias']:
                                        exported.append(item)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                # Esteve 23.07.2016 - end
                            else:
                                # Esteve 24.07.2016 - begin - At this point, we are dealing with components that do not have a permission neither at the component level nor at the
                                # application level. As they are exported, they
                                # are not protected.
                                if perm_appl_level_exists is False:
                                    ret_list.append(
                                        ('explicitly_exported', (itemname, item), (an_or_a, itemname)))
                                    if itemname in ['Activity', 'Activity-Alias']:
                                        exported.append(item)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                # Esteve 24.07.2016 - end
                                # Esteve 24.07.2016 - begin - At this point, we are dealing with components that have a permission at the application level, but not at the component
                                #  level. Two options are possible:
                                #        1) The permission is defined at the manifest level, which allows us to differentiate the level of protection as
                                #           we did just above for permissions specified at the component level.
                                #        2) The permission is not defined at the manifest level, which means the protection level is unknown, as it is not
                                # defined in the analysed application.
                                else:
                                    perm = '<strong>Permission: </strong>' + perm_appl_level
                                    prot = ''
                                    if perm_appl_level in permission_dict:
                                        prot = ('</br><strong>protectionLevel: </strong>'
                                                + permission_dict[perm_appl_level])
                                        prot_level_exist = True
                                        protlevel = permission_dict[
                                            perm_appl_level]
                                    if prot_level_exist:
                                        if protlevel == 'normal':
                                            ret_list.append(
                                                ('exported_protected_permission_normal_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                        elif protlevel == 'dangerous':
                                            ret_list.append(
                                                ('exported_protected_permission_dangerous_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                        elif protlevel == 'signature':
                                            ret_list.append(
                                                ('exported_protected_permission', (itemname, item, perm + prot), (an_or_a, itemname)))
                                        elif protlevel == 'signatureOrSystem':
                                            ret_list.append(
                                                ('exported_protected_permission_signatureorsystem_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                    else:
                                        ret_list.append(
                                            ('exported_protected_permission_app_level', (itemname, item, perm), (an_or_a, itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                # Esteve 24.07.2016 - end

                    elif node.getAttribute(f'{ns}:exported') != 'false':
                        # Check for Implicitly Exported
                        # Logic to support intent-filter
                        intentfilters = node.childNodes
                        for i in intentfilters:
                            inf = i.nodeName
                            if inf == 'intent-filter':
                                is_inf = True
                        if is_inf:
                            item = node.getAttribute(f'{ns}:name')
                            if node.getAttribute(f'{ns}:permission'):
                                # permission exists
                                perm = ('<strong>Permission: </strong>'
                                        + node.getAttribute(f'{ns}:permission'))
                                is_perm_exist = True
                            if item != man_data_dic['mainactivity']:
                                if is_perm_exist:
                                    prot = ''
                                    if node.getAttribute(f'{ns}:permission') in permission_dict:
                                        prot = ('</br><strong>protectionLevel: </strong>'
                                                + permission_dict[node.getAttribute(f'{ns}:permission')])
                                        # Esteve 24.07.2016 - begin - take into account protection level of the permission when claiming that a component is protected by it;
                                        # - the permission might not be defined in the application being analysed, if so, the protection level is not known;
                                        # - activities (or activity-alias) that are exported and have an unknown or normal or dangerous protection level are
                                        #  included in the EXPORTED data structure for further treatment; components in this situation are also
                                        #  counted as exported.
                                        prot_level_exist = True
                                        protlevel = permission_dict[
                                            node.getAttribute(f'{ns}:permission')]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                ret_list.append(
                                                    ('exported_protected_permission_normal', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                ret_list.append(
                                                    ('exported_protected_permission_dangerous', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'signature':
                                                ret_list.append(
                                                    ('exported_protected_permission_signature', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            elif protlevel == 'signatureOrSystem':
                                                ret_list.append(
                                                    ('exported_protected_permission_signatureorsystem', (itemname, item, perm + prot), (an_or_a, itemname)))
                                    else:
                                        ret_list.append(
                                            ('exported_protected_permission_not_defined', (itemname, item, perm), (an_or_a, itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    # Esteve 24.07.2016 - end
                                else:
                                    # Esteve 24.07.2016 - begin - At this point, we are dealing with components that do not have a permission neither at the component level nor at the
                                    # application level. As they are exported,
                                    # they are not protected.
                                    if perm_appl_level_exists is False:
                                        ret_list.append(
                                            ('exported_intent_filter_exists', (itemname, item), (an_or_a, itemname, itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    # Esteve 24.07.2016 - end
                                    # Esteve 24.07.2016 - begin - At this point, we are dealing with components that have a permission at the application level, but not at the component
                                    # level. Two options are possible:
                                    # 1) The permission is defined at the manifest level, which allows us to differentiate the level of protection as
                                    #  we did just above for permissions specified at the component level.
                                    # 2) The permission is not defined at the manifest level, which means the protection level is unknown, as it is not
                                    #  defined in the analysed application.
                                    else:
                                        perm = '<strong>Permission: </strong>' + perm_appl_level
                                        prot = ''
                                        if perm_appl_level in permission_dict:
                                            prot = ('</br><strong>protectionLevel: </strong>'
                                                    + permission_dict[perm_appl_level])
                                            prot_level_exist = True
                                            protlevel = permission_dict[
                                                perm_appl_level]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                ret_list.append(
                                                    ('exported_protected_permission_normal_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                ret_list.append(
                                                    ('exported_protected_permission_dangerous_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'signature':
                                                ret_list.append(
                                                    ('exported_protected_permission', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            elif protlevel == 'signatureOrSystem':
                                                ret_list.append(
                                                    ('exported_protected_permission_signatureorsystem_app_level', (itemname, item, perm + prot), (an_or_a, itemname)))
                                        else:
                                            ret_list.append(
                                                ('exported_protected_permission_app_level', (itemname, item, perm), (an_or_a, itemname)))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                    # Esteve 24.07.2016 - end
                                    # Esteve 29.07.2016 - begin The component is not explicitly exported (android:exported is not 'true'). It is not implicitly exported either (it does not
                                    # make use of an intent filter). Despite that, it could still be exported by default, if it is a content provider and the android:targetSdkVersion
                                    # is older than 17 (Jelly Bean, Android version 4.2). This is true regardless of the system's API level.
                                    # Finally, it must also be taken into account that, if the minSdkVersion is greater or equal than 17, this check is unnecessary, because the
                                    # app will not be run on a system where the
                                    # system's API level is below 17.
                        else:
                            if man_data_dic['min_sdk'] and man_data_dic['target_sdk'] and int(man_data_dic['min_sdk']) < ANDROID_4_2_LEVEL:
                                if itemname == 'Content Provider' and int(man_data_dic['target_sdk']) < ANDROID_4_2_LEVEL:
                                    perm = ''
                                    item = node.getAttribute(f'{ns}:name')
                                    if node.getAttribute(f'{ns}:permission'):
                                        # permission exists
                                        perm = ('<strong>Permission: </strong>'
                                                + node.getAttribute(f'{ns}:permission'))
                                        is_perm_exist = True
                                    if is_perm_exist:
                                        prot = ''
                                        if node.getAttribute(f'{ns}:permission') in permission_dict:
                                            prot = ('</br><strong>protectionLevel: </strong>'
                                                    + permission_dict[node.getAttribute(f'{ns}:permission')])
                                            prot_level_exist = True
                                            protlevel = permission_dict[
                                                node.getAttribute(f'{ns}:permission')]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                ret_list.append(
                                                    ('exported_provider_normal', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                ret_list.append(
                                                    ('exported_provider_danger', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'signature':
                                                ret_list.append(
                                                    ('exported_provider_signature', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            elif protlevel == 'signatureOrSystem':
                                                ret_list.append(
                                                    ('exported_provider_signatureorsystem', (itemname, item, perm + prot), (an_or_a, itemname)))
                                        else:
                                            ret_list.append(
                                                ('exported_provider_unknown', (itemname, item, perm), (an_or_a, itemname)))
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                    else:
                                        if perm_appl_level_exists is False:
                                            ret_list.append(
                                                ('exported_provider', (itemname, item), (an_or_a, itemname)))
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                        else:
                                            perm = '<strong>Permission: </strong>' + perm_appl_level
                                            prot = ''
                                            if perm_appl_level in permission_dict:
                                                prot = ('</br><strong>protectionLevel: </strong>'
                                                        + permission_dict[perm_appl_level])
                                                prot_level_exist = True
                                                protlevel = permission_dict[
                                                    perm_appl_level]
                                            if prot_level_exist:
                                                if protlevel == 'normal':
                                                    ret_list.append(
                                                        ('exported_provider_normal_app', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                elif protlevel == 'dangerous':
                                                    ret_list.append(
                                                        ('exported_provider_danger_appl', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                elif protlevel == 'signature':
                                                    ret_list.append(
                                                        ('exported_provider_signature_appl', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                elif protlevel == 'signatureOrSystem':
                                                    ret_list.append(
                                                        ('exported_provider_signatureorsystem_app', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            else:
                                                ret_list.append(
                                                    ('exported_provider_unknown_app', (itemname, item, perm), (an_or_a, itemname)))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                    # Esteve 29.07.2016 - end
                                    # Esteve 08.08.2016 - begin - If the content provider does not target an API version lower than 17, it could still be exported by default, depending
                                    # on the API version of the platform. If it was below 17, the content
                                    # provider would be exported by default.
                                else:
                                    if itemname == 'Content Provider' and int(man_data_dic['target_sdk']) >= 17:
                                        perm = ''
                                        item = node.getAttribute(
                                            f'{ns}:name')
                                        if node.getAttribute(f'{ns}:permission'):
                                            # permission exists
                                            perm = ('<strong>Permission: </strong>'
                                                    + node.getAttribute(f'{ns}:permission'))
                                            is_perm_exist = True
                                        if is_perm_exist:
                                            prot = ''
                                            if node.getAttribute(f'{ns}:permission') in permission_dict:
                                                prot = ('</br><strong>protectionLevel: </strong>'
                                                        + permission_dict[node.getAttribute(f'{ns}:permission')])
                                                prot_level_exist = True
                                                protlevel = permission_dict[
                                                    node.getAttribute(f'{ns}:permission')]
                                            if prot_level_exist:
                                                if protlevel == 'normal':
                                                    ret_list.append(
                                                        ('exported_provider_normal_new', (itemname, item, perm + prot), (itemname)))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                if protlevel == 'dangerous':
                                                    ret_list.append(
                                                        ('exported_provider_danger_new', (itemname, item, perm + prot), (itemname)))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                if protlevel == 'signature':
                                                    ret_list.append(
                                                        ('exported_provider_signature_new', (itemname, item, perm + prot), (itemname)))
                                                if protlevel == 'signatureOrSystem':
                                                    ret_list.append(
                                                        ('exported_provider_signatureorsystem_new', (itemname, item, perm + prot), (an_or_a, itemname)))
                                            else:
                                                ret_list.append(
                                                    ('exported_provider_unknown_new', (itemname, item, perm), (itemname)))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                        else:
                                            if perm_appl_level_exists is False:
                                                ret_list.append(
                                                    ('exported_provider_2', (itemname, item), (an_or_a, itemname)))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            else:
                                                perm = '<strong>Permission: </strong>' + perm_appl_level
                                                prot = ''
                                                if perm_appl_level in permission_dict:
                                                    prot = ('</br><strong>protectionLevel: </strong>'
                                                            + permission_dict[perm_appl_level])
                                                    prot_level_exist = True
                                                    protlevel = permission_dict[
                                                        perm_appl_level]
                                                if prot_level_exist:
                                                    if protlevel == 'normal':
                                                        ret_list.append(
                                                            ('exported_provider_normal_app_new', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                        exp_count[cnt_id] = exp_count[
                                                            cnt_id] + 1
                                                    elif protlevel == 'dangerous':
                                                        ret_list.append(
                                                            ('exported_provider_danger_app_new', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                        exp_count[cnt_id] = exp_count[
                                                            cnt_id] + 1
                                                    elif protlevel == 'signature':
                                                        ret_list.append(
                                                            ('exported_provider_signature_app_new', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                    elif protlevel == 'signatureOrSystem':
                                                        ret_list.append(
                                                            ('exported_provider_signatureorsystem_app_new', (itemname, item, perm + prot), (an_or_a, itemname)))
                                                else:
                                                    ret_list.append(
                                                        ('exported_provider_unknown_app_new', (itemname, item, perm), (an_or_a, itemname)))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                    # Esteve 08.08.2016 - end

        # GRANT-URI-PERMISSIONS
        for granturi in granturipermissions:
            if granturi.getAttribute(f'{ns}:pathPrefix') == '/':
                ret_list.append(
                    ('improper_provider_permission', ('pathPrefix=/',), ()))
            elif granturi.getAttribute(f'{ns}:path') == '/':
                ret_list.append(('improper_provider_permission', ('path=/',), ()))
            elif granturi.getAttribute(f'{ns}:pathPattern') == '*':
                ret_list.append(('improper_provider_permission', ('path=*',), ()))
        # DATA
        for data in data_tag:
            if data.getAttribute(f'{ns}:scheme') == 'android_secret_code':
                xmlhost = data.getAttribute(f'{ns}:host')
                ret_list.append(('dialer_code_found', (xmlhost,), ()))

            elif data.getAttribute(f'{ns}:port'):
                dataport = data.getAttribute(f'{ns}:port')
                ret_list.append(('sms_receiver_port_found', (dataport,), ()))
        # INTENTS
        processed_priorities = {}
        for intent in intents:
            if intent.getAttribute(f'{ns}:priority').isdigit():
                value = intent.getAttribute(f'{ns}:priority')
                if int(value) > 100:
                    if value not in processed_priorities:
                        processed_priorities[value] = 1
                    else:
                        processed_priorities[value] += 1
        for priority, count in processed_priorities.items():
            ret_list.append(
                ('high_intent_priority_found', (priority, count,), ()))
        # ACTIONS
        for action in actions:
            if action.getAttribute(f'{ns}:priority').isdigit():
                value = action.getAttribute(f'{ns}:priority')
                if int(value) > 100:
                    ret_list.append(
                        ('high_action_priority_found', (value,), ()))
        for a_key, t_name, t_desc in ret_list:
            a_template = android_manifest_desc.MANIFEST_DESC.get(a_key)
            if a_template:
                ret_value.append({
                    'rule': a_key,
                    'title': a_template['title'] % t_name,
                    'severity': a_template['level'],
                    'description': a_template['description'] % t_desc,
                    'name': a_template['name'] % t_name,
                    'component': t_name,
                })
            else:
                logger.warning("No template found for key '%s'", a_key)

        for category in man_data_dic['categories']:
            if category == 'android.intent.category.LAUNCHER':
                break

        permissions = {}
        for k, permission in man_data_dic['perm'].items():
            permissions[k] = (
                {
                    'status': permission[0],
                    'info': permission[1],
                    'description': permission[2],
                })
        # Prepare return dict
        exported_comp = {
            'exported_activities': exp_count['act'],
            'exported_services': exp_count['ser'],
            'exported_receivers': exp_count['bro'],
            'exported_providers': exp_count['cnt'],
        }
        man_an_dic = {
            'manifest_anal': ret_value,
            'exported_act': exported,
            'exported_cnt': exported_comp,
            'browsable_activities': browsable_activities,
            'permissions': permissions,
            'network_security': network_security.analysis(
                checksum,
                app_dir,
                do_netsec,
                debuggable,
                src_type),
        }
        return man_an_dic
    except Exception as exp:
        msg = 'Error Performing Manifest Analysis'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
