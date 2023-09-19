# -*- coding: utf_8 -*-
"""Android Static Code Analysis."""

import logging
import os
import re
import shutil
from pathlib import Path

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MalwareAnalyzer.views.apkid import apkid_analysis
from mobsf.MalwareAnalyzer.views.quark import quark_analysis
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import MalwareDomainCheck

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template.defaulttags import register

from mobsf.MobSF.utils import (
    android_component,
    error_response,
    file_size,
    is_admin,
    is_dir_exists,
    is_file_exists,
    key,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.common.binary.lib_analysis import (
    library_analysis,
)
from mobsf.StaticAnalyzer.views.android.app import (
    get_app_name,
    parse_apk,
)
from mobsf.StaticAnalyzer.views.android.cert_analysis import (
    cert_info,
    get_hardcoded_cert_keystore,
)
from mobsf.StaticAnalyzer.views.android.code_analysis import code_analysis
from mobsf.StaticAnalyzer.views.android.converter import (
    apk_2_java,
    dex_2_smali,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry,
    save_get_ctx,
)
from mobsf.StaticAnalyzer.views.android.icon_analysis import (
    find_icon_path_zip,
    get_icon_apk,
)
from mobsf.StaticAnalyzer.views.android.manifest_analysis import (
    manifest_analysis,
)
from mobsf.StaticAnalyzer.views.android.manifest_utils import (
    get_manifest,
    manifest_data,
)
from mobsf.StaticAnalyzer.views.android.playstore import get_app_details
from mobsf.StaticAnalyzer.views.android.strings import (
    get_strings_metadata,
)
from mobsf.StaticAnalyzer.views.android.xapk import (
    handle_split_apk,
    handle_xapk,
)
from mobsf.StaticAnalyzer.views.android.jar_aar import (
    aar_analysis,
    jar_analysis,
)
from mobsf.StaticAnalyzer.views.android.so import (
    so_analysis,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    firebase_analysis,
    get_avg_cvss,
    hash_gen,
    unzip,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    get_android_dashboard,
)


logger = logging.getLogger(__name__)
register.filter('key', key)
register.filter('android_component', android_component)


def static_analyzer_request(request):
    response = static_analyzer(request.GET, False)
    if 'template' in response:
        response['is_admin'] = is_admin(request)
        return render(request, response['template'], response)
    elif 'error' in response:
        return error_response(request, response['error'])
    else:
        return response


def static_analyzer(request_data, api=False):
    """Do static analysis on a request and save to db."""
    try:
        typ = request_data['scan_type']
        checksum = request_data['hash']
        filename = request_data['file_name']
        re_scan = request_data.get('rescan', 0)
        rescan = False
        if re_scan == '1':
            rescan = True

        # Input validation
        app_dic = {}
        match = re.match('^[0-9a-f]{32}$', checksum)
        allowed_exts = (
            '.apk', '.xapk', '.zip', '.apks',
            '.jar', '.aar', '.so')
        allowed_typ = [i.replace('.', '') for i in allowed_exts]
        if (match
                and filename.lower().endswith(allowed_exts)
                and typ in allowed_typ):
            app_dic['dir'] = Path(settings.BASE_DIR)  # BASE DIR
            app_dic['app_name'] = filename  # APP ORIGINAL NAME
            app_dic['md5'] = checksum  # MD5
            logger.info('Scan Hash: %s', checksum)
            # APP DIRECTORY
            app_dic['app_dir'] = Path(settings.UPLD_DIR) / checksum
            app_dic['tools_dir'] = app_dic['dir'] / 'StaticAnalyzer' / 'tools'
            app_dic['tools_dir'] = app_dic['tools_dir'].as_posix()
            logger.info('Starting Analysis on: %s', app_dic['app_name'])
            if typ == 'xapk':
                # Handle XAPK
                # Base APK will have the MD5 of XAPK
                if not handle_xapk(app_dic):
                    raise Exception('Invalid XAPK File')
                typ = 'apk'
            elif typ == 'apks':
                # Handle Split APK
                if not handle_split_apk(app_dic):
                    raise Exception('Invalid Split APK File')
                typ = 'apk'
            if typ == 'apk':
                app_dic['app_file'] = app_dic['md5'] + '.apk'  # NEW FILENAME
                app_dic['app_path'] = (
                    app_dic['app_dir'] / app_dic['app_file']).as_posix()
                app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
                # Check if in DB
                # pylint: disable=E1101
                db_entry = StaticAnalyzerAndroid.objects.filter(
                    MD5=app_dic['md5'])
                if db_entry.exists() and not rescan:
                    context = get_context_from_db_entry(db_entry)
                else:
                    # ANALYSIS BEGINS
                    app_dic['size'] = str(
                        file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
                    app_dic['sha1'], app_dic[
                        'sha256'] = hash_gen(app_dic['app_path'])
                    app_dic['files'] = unzip(
                        app_dic['app_path'], app_dic['app_dir'])
                    logger.info('APK Extracted')
                    if not app_dic['files']:
                        # Can't Analyze APK, bail out.
                        return error_response(
                            request_data,
                            'APK file is invalid or corrupt',
                            api)
                    app_dic['certz'] = get_hardcoded_cert_keystore(app_dic[
                                                                   'files'])
                    # Manifest XML
                    mani_file, ns, mani_xml = get_manifest(
                        app_dic['app_path'],
                        app_dic['app_dir'],
                        app_dic['tools_dir'],
                        'apk',
                    )
                    app_dic['manifest_file'] = mani_file
                    app_dic['parsed_xml'] = mani_xml
                    # Parse APK with Androguard
                    apk = parse_apk(app_dic['app_path'])
                    # get app_name
                    app_dic['real_name'] = get_app_name(
                        apk,
                        app_dic['app_dir'],
                        True,
                    )

                    # Get icon
                    # apktool should run before this
                    get_icon_apk(apk, app_dic)

                    # Set Manifest link
                    app_dic['mani'] = (
                        f'../manifest_view/?md5={app_dic["md5"]}&type=apk')
                    man_data_dic = manifest_data(app_dic['parsed_xml'], ns)
                    app_dic['playstore'] = get_app_details(
                        man_data_dic['packagename'])
                    man_an_dic = manifest_analysis(
                        app_dic['parsed_xml'],
                        ns,
                        man_data_dic,
                        '',
                        app_dic['app_dir'],
                    )
                    elf_dict = library_analysis(app_dic['app_dir'], 'elf')
                    cert_dic = cert_info(
                        apk,
                        app_dic['app_path'],
                        app_dic['app_dir'],
                        man_data_dic)
                    apkid_results = apkid_analysis(app_dic[
                        'app_dir'], app_dic['app_path'], app_dic['app_name'])
                    tracker = Trackers.Trackers(
                        app_dic['app_dir'], app_dic['tools_dir'])
                    tracker_res = tracker.get_trackers()

                    apk_2_java(app_dic['app_path'], app_dic['app_dir'],
                               app_dic['tools_dir'])

                    dex_2_smali(app_dic['app_dir'], app_dic['tools_dir'])

                    code_an_dic = code_analysis(
                        app_dic['app_dir'],
                        'apk',
                        app_dic['manifest_file'])

                    quark_results = quark_analysis(
                        app_dic['app_dir'],
                        app_dic['app_path'])

                    # Get the strings and metadata
                    get_strings_metadata(
                        apk,
                        app_dic['app_dir'],
                        elf_dict['elf_strings'],
                        'apk',
                        ['.java'],
                        code_an_dic)

                    # Firebase DB Check
                    code_an_dic['firebase'] = firebase_analysis(
                        code_an_dic['urls_list'])
                    # Domain Extraction and Malware Check
                    logger.info(
                        'Performing Malware Check on extracted Domains')
                    code_an_dic['domains'] = MalwareDomainCheck().scan(
                        code_an_dic['urls_list'])

                    app_dic['zipped'] = 'apk'
                    context = save_get_ctx(
                        app_dic,
                        man_data_dic,
                        man_an_dic,
                        code_an_dic,
                        cert_dic,
                        elf_dict['elf_analysis'],
                        apkid_results,
                        quark_results,
                        tracker_res,
                        rescan,
                    )
                context['appsec'] = get_android_dashboard(context, True)
                context['average_cvss'] = get_avg_cvss(
                    context['code_analysis'])
                context['dynamic_analysis_done'] = is_file_exists(
                    os.path.join(app_dic['app_dir'], 'logcat.txt'))
                context['virus_total'] = None
                if settings.VT_ENABLED:
                    vt = VirusTotal.VirusTotal()
                    context['virus_total'] = vt.get_result(
                        app_dic['app_path'],
                        app_dic['md5'])
                context['template'] = \
                    'static_analysis/android_binary_analysis.html'
                logger.info('Scan complete')
                return context
            elif typ == 'jar':
                return jar_analysis(request_data, app_dic, rescan, api)
            elif typ == 'aar':
                return aar_analysis(request_data, app_dic, rescan, api)
            elif typ == 'so':
                return so_analysis(request_data, app_dic, rescan, api)
            elif typ == 'zip':
                ret = (
                    '/static_analyzer_ios/?file_name='
                    + app_dic['app_name']
                    + '&scan_type=ios&hash='
                    + app_dic['md5']
                )
                # Check if in DB
                # pylint: disable=E1101
                cert_dic = {
                    'certificate_info': '',
                    'certificate_status': '',
                    'description': '',
                }
                app_dic['strings'] = []
                app_dic['secrets'] = []
                app_dic['zipped'] = ''
                # Above fields are only available for APK and not ZIP
                app_dic['app_file'] = app_dic['md5'] + '.zip'  # NEW FILENAME
                app_dic['app_path'] = (
                    app_dic['app_dir'] / app_dic['app_file']).as_posix()
                app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
                db_entry = StaticAnalyzerAndroid.objects.filter(
                    MD5=app_dic['md5'])
                ios_db_entry = StaticAnalyzerIOS.objects.filter(
                    MD5=app_dic['md5'])
                if db_entry.exists() and not rescan:
                    context = get_context_from_db_entry(db_entry)
                elif ios_db_entry.exists() and not rescan:
                    if api:
                        return {'type': 'ios'}
                    else:
                        return HttpResponseRedirect(ret)
                else:
                    logger.info('Extracting ZIP')
                    app_dic['files'] = unzip(
                        app_dic['app_path'], app_dic['app_dir'])
                    # Check if Valid Directory Structure and get ZIP Type
                    pro_type, valid = valid_source_code(app_dic['app_dir'])
                    logger.info('Source code type - %s', pro_type)
                    if valid and pro_type == 'ios':
                        logger.info('Redirecting to iOS Source Code Analyzer')
                        if api:
                            return {'type': 'ios'}
                        else:
                            ret += f'&rescan={str(int(rescan))}'
                            return HttpResponseRedirect(ret)
                    app_dic['certz'] = get_hardcoded_cert_keystore(
                        app_dic['files'])
                    app_dic['zipped'] = pro_type
                    if valid and (pro_type in ['eclipse', 'studio']):
                        # ANALYSIS BEGINS
                        app_dic['size'] = str(
                            file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
                        app_dic['sha1'], app_dic[
                            'sha256'] = hash_gen(app_dic['app_path'])

                        # Manifest XML
                        mani_file, ns, mani_xml = get_manifest(
                            '',
                            app_dic['app_dir'],
                            app_dic['tools_dir'],
                            pro_type,
                        )
                        app_dic['manifest_file'] = mani_file
                        app_dic['parsed_xml'] = mani_xml

                        # get app_name
                        app_dic['real_name'] = get_app_name(
                            app_dic['app_path'],
                            app_dic['app_dir'],
                            False,
                        )

                        # Set manifest view link
                        app_dic['mani'] = (
                            f'../manifest_view/?md5={app_dic["md5"]}'
                            f'&type={pro_type}')
                        man_data_dic = manifest_data(app_dic['parsed_xml'], ns)
                        app_dic['playstore'] = get_app_details(
                            man_data_dic['packagename'])
                        man_an_dic = manifest_analysis(
                            app_dic['parsed_xml'],
                            ns,
                            man_data_dic,
                            pro_type,
                            app_dic['app_dir'],
                        )
                        # Get icon
                        eclipse_res_path = os.path.join(
                            app_dic['app_dir'], 'res')
                        studio_res_path = os.path.join(
                            app_dic['app_dir'], 'app', 'src', 'main', 'res')
                        if os.path.exists(eclipse_res_path):
                            res_path = eclipse_res_path
                        elif os.path.exists(studio_res_path):
                            res_path = studio_res_path
                        else:
                            res_path = ''

                        app_dic['icon_hidden'] = man_an_dic['icon_hidden']
                        app_dic['icon_found'] = False
                        app_dic['icon_path'] = ''
                        if res_path:
                            app_dic['icon_path'] = find_icon_path_zip(
                                res_path, man_data_dic['icons'])
                            if app_dic['icon_path']:
                                app_dic['icon_found'] = True

                        if app_dic['icon_path']:
                            if os.path.exists(app_dic['icon_path']):
                                shutil.copy2(
                                    app_dic['icon_path'],
                                    os.path.join(
                                        settings.DWD_DIR,
                                        app_dic['md5'] + '-icon.png'))

                        code_an_dic = code_analysis(
                            app_dic['app_dir'],
                            pro_type,
                            app_dic['manifest_file'])

                        # Get the strings and metadata
                        get_strings_metadata(
                            None,
                            app_dic['app_dir'],
                            None,
                            pro_type,
                            ['.java', '.kt'],
                            code_an_dic)

                        # Firebase DB Check
                        code_an_dic['firebase'] = firebase_analysis(
                            code_an_dic['urls_list'])
                        # Domain Extraction and Malware Check
                        logger.info(
                            'Performing Malware Check on extracted Domains')
                        code_an_dic['domains'] = MalwareDomainCheck().scan(
                            code_an_dic['urls_list'])

                        # Extract Trackers from Domains
                        trk = Trackers.Trackers(
                            None, app_dic['tools_dir'])
                        trackers = trk.get_trackers_domains_or_deps(
                            code_an_dic['domains'], [])
                        context = save_get_ctx(
                            app_dic,
                            man_data_dic,
                            man_an_dic,
                            code_an_dic,
                            cert_dic,
                            [],
                            {},
                            [],
                            trackers,
                            rescan,
                        )
                    else:
                        error_result = {
                            'error': 'This ZIP format is not supported',
                            'template': 'general/zip.html',
                        }
                        logger.error(error_result['error'])
                        return error_result
                context['appsec'] = get_android_dashboard(context, True)
                context['average_cvss'] = get_avg_cvss(
                    context['code_analysis'])
                context['template'] = \
                    'static_analysis/android_source_analysis.html'
                logger.info('Scan complete')
                return context
            else:
                err = ('Only APK, JAR, AAR, SO and Zipped '
                       'Android/iOS Source code supported!')
                logger.error(err)
        else:
            msg = 'Hash match failed or invalid file extension or file type'
            return {'error': msg}

    except Exception as excep:
        logger.exception('Error Performing Static Analysis')
        msg = str(excep)
        return {'error': msg}


def is_android_source(app_dir):
    """Detect Android Source and IDE Type."""
    # Eclipse
    man = os.path.isfile(os.path.join(app_dir, 'AndroidManifest.xml'))
    src = os.path.exists(os.path.join(app_dir, 'src/'))
    if man and src:
        return 'eclipse', True
    # Studio
    man = os.path.isfile(
        os.path.join(app_dir, 'app/src/main/AndroidManifest.xml'),
    )
    java = os.path.exists(os.path.join(app_dir, 'app/src/main/java/'))
    kotlin = os.path.exists(os.path.join(app_dir, 'app/src/main/kotlin/'))
    if man and (java or kotlin):
        return 'studio', True
    return None, False


def valid_source_code(app_dir):
    """Test if this is an valid source code zip."""
    try:
        logger.info('Detecting source code type')
        ide, is_and = is_android_source(app_dir)
        if ide:
            return ide, is_and
        # Relaxed Android Source check, one level down
        for x in os.listdir(app_dir):
            obj = os.path.join(app_dir, x)
            if not is_dir_exists(obj):
                continue
            ide, is_and = is_android_source(obj)
            if ide:
                move_to_parent(obj, app_dir)
                return ide, is_and
        # iOS Source
        xcode = [f for f in os.listdir(app_dir) if f.endswith('.xcodeproj')]
        if xcode:
            return 'ios', True
        # Relaxed iOS Source Check
        for x in os.listdir(app_dir):
            obj = os.path.join(app_dir, x)
            if not is_dir_exists(obj):
                continue
            if [f for f in os.listdir(obj) if f.endswith('.xcodeproj')]:
                return 'ios', True
        return '', False
    except Exception:
        logger.exception('Identifying source code from zip')


def move_to_parent(inside, app_dir):
    """Move contents of inside to app dir."""
    for x in os.listdir(inside):
        full_path = os.path.join(inside, x)
        shutil.move(full_path, app_dir)
    shutil.rmtree(inside)
