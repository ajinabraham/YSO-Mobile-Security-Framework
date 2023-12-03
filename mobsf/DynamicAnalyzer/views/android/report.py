# -*- coding: utf_8 -*-
"""Dynamic Analyzer Reporting."""
import logging
import os

from django.conf import settings
from django.shortcuts import render
from django.template.defaulttags import register

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
from mobsf.DynamicAnalyzer.views.android.analysis import (
    generate_download,
    get_screenshots,
    run_analysis,
)
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
)
from mobsf.DynamicAnalyzer.views.android.tests_xposed import (
    droidmon_api_analysis,
)
from mobsf.DynamicAnalyzer.views.android.tests_frida import (
    apimon_analysis,
    dependency_analysis,
)
from mobsf.MobSF.utils import (
    is_file_exists,
    is_md5,
    key,
    print_n_send_error_response,
)


logger = logging.getLogger(__name__)
register.filter('key', key)


def view_report(request, checksum, api=False):
    """Dynamic Analysis Report Generation."""
    logger.info('Dynamic Analysis Report Generation')
    try:
        droidmon = {}
        apimon = {}
        b64_strings = []
        if not is_md5(checksum):
            # We need this check since checksum is not validated
            # in REST API
            return print_n_send_error_response(
                request,
                'Invalid Hash',
                api)
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Invalid Parameters',
                api)
        app_dir = os.path.join(settings.UPLD_DIR, checksum + '/')
        download_dir = settings.DWD_DIR
        tools_dir = settings.TOOLS_DIR
        if not is_file_exists(os.path.join(app_dir, 'logcat.txt')):
            msg = ('Dynamic Analysis report is not available '
                   'for this app. Perform Dynamic Analysis '
                   'and generate the report.')
            return print_n_send_error_response(request, msg, api)
        fd_log = os.path.join(app_dir, 'mobsf_frida_out.txt')
        droidmon = droidmon_api_analysis(app_dir, package)
        apimon, b64_strings = apimon_analysis(app_dir)
        deps = dependency_analysis(package, app_dir)
        analysis_result = run_analysis(app_dir, checksum, package)
        domains = analysis_result['domains']
        trk = Trackers.Trackers(app_dir, tools_dir)
        trackers = trk.get_trackers_domains_or_deps(domains, deps)
        generate_download(app_dir, checksum, download_dir, package)
        images = get_screenshots(checksum, download_dir)
        context = {'hash': checksum,
                   'emails': analysis_result['emails'],
                   'urls': analysis_result['urls'],
                   'domains': domains,
                   'clipboard': analysis_result['clipboard'],
                   'xml': analysis_result['xml'],
                   'sqlite': analysis_result['sqlite'],
                   'others': analysis_result['other_files'],
                   'tls_tests': analysis_result['tls_tests'],
                   'screenshots': images['screenshots'],
                   'activity_tester': images['activities'],
                   'exported_activity_tester': images['exported_activities'],
                   'droidmon': droidmon,
                   'apimon': apimon,
                   'base64_strings': b64_strings,
                   'trackers': trackers,
                   'frida_logs': is_file_exists(fd_log),
                   'runtime_dependencies': list(deps),
                   'package': package,
                   'version': settings.MOBSF_VER,
                   'title': 'Dynamic Analysis'}
        template = 'dynamic_analysis/android/dynamic_report.html'
        if api:
            return context
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis Report Generation')
        err = 'Error Generating Dynamic Analysis Report. ' + str(exp)
        return print_n_send_error_response(request, err, api)
