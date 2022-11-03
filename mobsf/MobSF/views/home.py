# -*- coding: utf_8 -*-
"""MobSF File Upload and Home Routes."""
import datetime
import json
import logging
import os
import platform
import re
import shutil
import time
import traceback as tb
from pathlib import Path
from wsgiref.util import FileWrapper

import boto3

from botocore.exceptions import ClientError

from django.conf import settings
from django.core.paginator import Paginator
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.template.defaulttags import register
from django.forms.models import model_to_dict
from django.utils import timezone

from mobsf.MobSF.forms import FormUtil, UploadFileForm
from mobsf.MobSF.utils import (
    api_key,
    error_response,
    is_admin,
    is_dir_exists,
    is_file_exists,
    is_safe_path,
    key,
    sso_email,
)
from mobsf.MobSF.views.scanning import Scanning
from mobsf.MobSF.views.apk_downloader import apk_download
from mobsf.StaticAnalyzer.models import (
    CyberspectScans,
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)

LINUX_PLATFORM = ['Darwin', 'Linux']
HTTP_BAD_REQUEST = 400
logger = logging.getLogger(__name__)
register.filter('key', key)


def index(request):
    """Index Route."""
    mimes = (settings.APK_MIME
             + settings.IPA_MIME
             + settings.ZIP_MIME
             + settings.APPX_MIME)
    context = {
        'version': settings.MOBSF_VER,
        'mimes': mimes,
        'tenant_static': settings.TENANT_STATIC_URL,
        'divisions': os.getenv('DIVISIONS'),
        'email': sso_email(request),
    }
    template = 'general/home.html'
    return render(request, template, context)


class Upload(object):
    """Handle File Upload based on App type."""

    def __init__(self, request):
        self.request = request
        self.form = UploadFileForm(request.POST, request.FILES)
        self.scan = Scanning(self.request)

    @staticmethod
    def as_view(request):
        upload = Upload(request)
        return upload.upload_html()

    def resp_json(self, data):
        resp = HttpResponse(json.dumps(data),
                            content_type='application/json; charset=utf-8')
        return resp

    def upload_html(self):
        logger.info('File uploaded via web UI by user %s',
                    sso_email(self.request))
        try:
            request = self.request
            response_data = {
                'description': '',
                'status': 'error',
            }
            if request.method != 'POST':
                msg = 'Method not Supported!'
                logger.error(msg)
                response_data['description'] = msg
                return self.resp_json(response_data)

            if not self.form.is_valid():
                msg = 'Invalid Form Data!'
                logger.error(msg)
                response_data['description'] = msg
                return self.resp_json(response_data)

            if not self.scan.file_type.is_allow_file():
                msg = 'File format not Supported!'
                logger.error(msg)
                response_data['description'] = msg
                return self.resp_json(response_data)

            if self.scan.file_type.is_ipa():
                if platform.system() not in LINUX_PLATFORM:
                    msg = 'Static Analysis of iOS IPA requires Mac or Linux'
                    logger.error(msg)
                    response_data['description'] = msg
                    return self.resp_json(response_data)

            start_time = timezone.now()
            response_data = self.upload()
            self.track_new_scan(False, start_time, response_data['hash'])
            self.write_to_s3(response_data)
            return self.resp_json(response_data)
        except Exception as ex:
            msg = getattr(ex, 'message', repr(ex))
            exmsg = ''.join(tb.format_exception(None, ex, ex.__traceback__))
            logger.error(exmsg)
            self.track_failure(msg)
            response_data['description'] = msg
            return self.resp_json(response_data)

    def upload_api(self):
        """API File Upload."""
        logger.info('Uploading through API')
        api_response = {}
        if not self.form.is_valid():
            api_response['error'] = FormUtil.errors_message(self.form)
            return api_response, HTTP_BAD_REQUEST
        self.scan.email = self.request.POST.get('email', '')
        if not self.scan.file_type.is_allow_file():
            api_response['error'] = 'File format not Supported!'
            return api_response, HTTP_BAD_REQUEST
        start_time = timezone.now()
        api_response = self.upload()
        self.track_new_scan(True, start_time, api_response['hash'])
        if (not self.request.GET.get('scan', '1') == '0'):
            self.write_to_s3(api_response)
        return api_response, 200

    def upload(self):
        content_type = self.scan.file.content_type
        file_name = self.scan.file.name
        logger.info('MIME Type: %s, File: %s', content_type, file_name)
        if self.scan.file_type.is_apk():
            return self.scan.scan_apk()
        elif self.scan.file_type.is_xapk():
            return self.scan.scan_xapk()
        elif self.scan.file_type.is_apks():
            return self.scan.scan_apks()
        elif self.scan.file_type.is_zip():
            return self.scan.scan_zip()
        elif self.scan.file_type.is_ipa():
            return self.scan.scan_ipa()
        elif self.scan.file_type.is_appx():
            return self.scan.scan_appx()

    def write_to_s3(self, api_response):
        if not settings.AWS_S3_BUCKET:
            logging.warning('Environment variable AWS_S3_BUCKET not set')
            return

        s3_client = boto3.client('s3')
        try:
            # Write minimal metadata to file
            prefix = os.path.join(settings.UPLD_DIR,
                                  api_response['hash'] + '/'
                                  + api_response['hash'] + '.')
            file_path = prefix + api_response['scan_type']
            metadata_filepath = file_path + '.json'
            metadata_file = open(metadata_filepath, 'w')
            metadata_file.write('{"user_app_name":"'
                                + self.scan.user_app_name + '",')
            metadata_file.write('"user_app_version":"'
                                + self.scan.user_app_version + '",')
            metadata_file.write('"email":"' + self.scan.email + '",')
            metadata_file.write('"hash":"' + api_response['hash'] + '",')
            metadata_file.write('"file_name":"'
                                + self.scan.file_name + '",')
            metadata_file.write('"short_hash":"' + api_response['short_hash']
                                + '",')
            metadata_file.write('"cyberspect_scan_id":"'
                                + str(self.scan.cyberspect_scan_id) + '"}')
            metadata_file.close()

            # Write uploaded files to S3 bucket
            logger.info('Writing files to S3 bucket: %s',
                        settings.AWS_S3_BUCKET)
            file_name = self.scan.file_name
            if (self.scan.source_file):
                source_filepath = file_path + '.src'
                s3_client.upload_file(source_filepath,
                                      settings.AWS_S3_BUCKET,
                                      'intake/' + file_name + '.src')
            s3_client.upload_file(file_path,
                                  settings.AWS_S3_BUCKET,
                                  'intake/' + file_name)
            s3_client.upload_file(metadata_filepath,
                                  settings.AWS_S3_BUCKET,
                                  'intake/' + file_name + '.json')

        except ClientError:
            msg = 'Unable to upload files to AWS S3'
            logging.error(msg)
            self.track_failure(self.scan, msg)
            return False
        return

    def track_new_scan(self, scheduled, start_time, md5):
        # Insert new record into CyberspectScans
        new_db_obj = CyberspectScans(
            SCHEDULED=scheduled,
            MOBSF_MD5=md5,
            INTAKE_START=start_time,
            FILE_SIZE_PACKAGE=self.scan.file_size,
            FILE_SIZE_SOURCE=self.scan.source_file_size,
        )
        new_db_obj.save()
        self.scan.cyberspect_scan_id = new_db_obj.ID
        logger.info('Hash: %s, Cyberspect Scan ID: %s', md5, new_db_obj.ID)

    def track_failure(self, error_message):
        if self.scan.cyberspect_scan_id == 0:
            return
        data = {
            'id': self.scan.cyberspect_scan_id,
            'success': False,
            'failure_source': 'SAST',
            'failure_message': error_message,
        }
        update_cyberspect_scan(data)


def api_docs(request):
    """Api Docs Route."""
    if (not is_admin(request)):
        return error_response(request, 'Unauthorized')

    context = {
        'title': 'REST API Docs',
        'api_key': api_key(),
        'version': settings.MOBSF_VER,
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/apidocs.html'
    return render(request, template, context)


def support(request):
    """Support Route."""
    context = {
        'title': 'Support',
        'version': settings.MOBSF_VER,
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/support.html'
    return render(request, template, context)


def about(request):
    """About Route."""
    context = {
        'title': 'About',
        'version': settings.MOBSF_VER,
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/about.html'
    return render(request, template, context)


def error(request):
    """Error Route."""
    context = {
        'title': 'Error',
        'version': settings.MOBSF_VER,
    }
    template = 'general/error.html'
    return render(request, template, context)


def zip_format(request):
    """Zip Format Message Route."""
    context = {
        'title': 'Zipped Source Instruction',
        'version': settings.MOBSF_VER,
    }
    template = 'general/zip.html'
    return render(request, template, context)


def not_found(request):
    """Not Found Route."""
    context = {
        'title': 'Not Found',
        'version': settings.MOBSF_VER,
    }
    template = 'general/not_found.html'
    return render(request, template, context)


def recent_scans(request):
    """Show Recent Scans Route."""
    entries = []
    db_obj = RecentScansDB.objects.all().order_by('-TIMESTAMP')
    isadmin = is_admin(request)
    if (not isadmin):
        email_filter = sso_email(request)
        if (not email_filter):
            email_filter = '@@'
        db_obj = db_obj.filter(EMAIL__contains=email_filter)

    recentscans = db_obj.values()
    android = StaticAnalyzerAndroid.objects.all()
    package_mapping = {}
    for item in android:
        package_mapping[item.MD5] = item.PACKAGE_NAME
    for entry in recentscans:
        if entry['MD5'] in package_mapping.keys():
            entry['PACKAGE'] = package_mapping[entry['MD5']]
        else:
            entry['PACKAGE'] = ''
        logcat = Path(settings.UPLD_DIR) / entry['MD5'] / 'logcat.txt'
        entry['DYNAMIC_REPORT_EXISTS'] = logcat.exists()
        entry['ERROR'] = (timezone.now()
                          > entry['TIMESTAMP']
                          + datetime.timedelta(minutes=15))
        entries.append(entry)
    context = {
        'title': 'Recent Scans',
        'entries': entries,
        'version': settings.MOBSF_VER,
        'is_admin': isadmin,
        'tenant_static': settings.TENANT_STATIC_URL,
        'dependency_track_url': settings.DEPENDENCY_TRACK_URL,
    }
    template = 'general/recent.html'
    return render(request, template, context)


def scan_metadata(md5):
    """Get scan metadata."""
    if re.match('[0-9a-f]{32}', md5):
        db_obj = RecentScansDB.objects.filter(MD5=md5).first()
        if db_obj:
            return model_to_dict(db_obj)
    return None


def update_cyberspect_scan(data):
    """Update Cyberspect scan record."""
    try:
        db_obj = CyberspectScans.objects.filter(ID=data['id']).first()
        if db_obj:
            if 'mobsf_md5' in data:
                db_obj.MOBSF_MD5 = data['mobsf_md5']
            if 'dt_project_id' in data and data['dt_project_id']:
                db_obj.DT_PROJECT_ID = data['dt_project_id']
            if 'intake_end' in data and data['intake_end']:
                db_obj.INTAKE_END = tz(data['intake_end'])
            if 'sast_start' in data and data['sast_start']:
                db_obj.SAST_START = tz(data['sast_start'])
            if 'sast_end' in data and data['sast_end']:
                db_obj.SAST_END = tz(data['sast_end'])
            if 'sbom_start' in data and data['sbom_start']:
                db_obj.SBOM_START = tz(data['sbom_start'])
            if 'sbom_end' in data and data['sbom_end']:
                db_obj.SBOM_END = tz(data['sbom_end'])
            if 'dependency_start' in data and data['dependency_start']:
                db_obj.DEPENDENCY_START = tz(data['dependency_start'])
            if 'dependency_end' in data and data['dependency_end']:
                db_obj.DEPENDENCY_END = tz(data['dependency_end'])
            if 'notification_start' in data and data['notification_start']:
                db_obj.NOTIFICATION_START = tz(data['notification_start'])
            if 'notification_end' in data and data['notification_end']:
                db_obj.NOTIFICATION_END = tz(data['notification_end'])
            if 'success' in data:
                db_obj.SUCCESS = data['success']
            if 'failure_source' in data and data['failure_source']:
                db_obj.FAILURE_SOURCE = data['failure_source']
            if 'failure_message' in data and data['failure_message']:
                db_obj.FAILURE_MESSAGE = data['failure_message']
            if 'file_size_package' in data and data['file_size_package']:
                db_obj.FILE_SIZE_PACKAGE = data['file_size_package']
            if 'file_size_source' in data and data['file_size_source']:
                db_obj.FILE_SIZE_SOURCE = data['file_size_source']
            if 'dependency_types' in data:
                db_obj.DEPENDENCY_TYPES = data['dependency_types']
            db_obj.save()
            return model_to_dict(db_obj)
        else:
            csid = data['id']
            return {'error': f'Scan ID {csid} not found'}
    except Exception as ex:
        exmsg = ''.join(tb.format_exception(None, ex, ex.__traceback__))
        logger.error(exmsg)
        return {'error': str(ex)}


def tz(value):
    # Parse string into date/time parts and build time zone aware datetime
    st = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%f')
    ts = time.mktime(st.timetuple()) + (st.microsecond / 1000000.0)
    dt = datetime.datetime.fromtimestamp(ts)
    return dt.replace(tzinfo=timezone.utc)


def logout_aws(request):
    """Remove AWS ALB session cookie."""
    resp = HttpResponse(
        '{}',
        content_type='application/json; charset=utf-8')
    for cookie in request.COOKIES:
        resp.set_cookie(cookie, None, -1, -1)
    return resp


def download_apk(request):
    """Download and APK by package name."""
    package = request.POST['package']
    # Package validated in apk_download()
    context = {
        'status': 'failed',
        'description': 'Unable to download APK',
    }
    res = apk_download(package)
    if res:
        context = res
        context['status'] = 'ok'
        context['package'] = package
    resp = HttpResponse(
        json.dumps(context),
        content_type='application/json; charset=utf-8')
    return resp


def search(request):
    """Search Scan by MD5 Route."""
    md5 = request.GET['md5']
    if re.match('[0-9a-f]{32}', md5):
        db_obj = RecentScansDB.objects.filter(MD5=md5)
        if db_obj.exists():
            e = db_obj[0]
            url = (f'/{e.ANALYZER }/?name={e.FILE_NAME}&'
                   f'checksum={e.MD5}&type={e.SCAN_TYPE}')
            return HttpResponseRedirect(url)
        else:
            return HttpResponseRedirect('/not_found/')
    return error_response(request,
                          'The Scan ID provided is invalid. Please provide a'
                          + ' valid 32 character alphanumeric value.')


def download(request):
    """Download from mobsf.MobSF Route."""
    if request.method == 'GET':
        root = settings.DWD_DIR
        allowed_exts = settings.ALLOWED_EXTENSIONS
        filename = request.path.replace('/download/', '', 1)
        dwd_file = os.path.join(root, filename)
        # Security Checks
        if '../' in filename or not is_safe_path(root, dwd_file):
            msg = 'Path Traversal Attack Detected'
            return error_response(request, msg)
        ext = os.path.splitext(filename)[1]
        if ext in allowed_exts:
            if os.path.isfile(dwd_file):
                wrapper = FileWrapper(
                    open(dwd_file, 'rb'))  # lgtm [py/path-injection]
                response = HttpResponse(
                    wrapper, content_type=allowed_exts[ext])
                response['Content-Length'] = os.path.getsize(dwd_file)
                return response
        if filename.endswith(('screen/screen.png', '-icon.png')):
            return HttpResponse('')
    return HttpResponse(status=404)


def delete_scan(request, api=False):
    """Delete Scan from DB and remove the scan related files."""
    try:
        if request.method == 'POST':
            if api:
                md5_hash = request.POST['hash']
            else:
                md5_hash = request.POST['md5']
            data = {'deleted': 'scan hash not found'}
            if re.match('[0-9a-f]{32}', md5_hash):
                # Delete DB Entries
                scan = RecentScansDB.objects.filter(MD5=md5_hash)
                if scan.exists():
                    RecentScansDB.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerAndroid.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerIOS.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerWindows.objects.filter(MD5=md5_hash).delete()
                    # Delete Upload Dir Contents
                    app_upload_dir = os.path.join(settings.UPLD_DIR, md5_hash)
                    if is_dir_exists(app_upload_dir):
                        shutil.rmtree(app_upload_dir)
                    # Delete Download Dir Contents
                    dw_dir = settings.DWD_DIR
                    for item in os.listdir(dw_dir):
                        item_path = os.path.join(dw_dir, item)
                        valid_item = item.startswith(md5_hash + '-')
                        # Delete all related files
                        if is_file_exists(item_path) and valid_item:
                            os.remove(item_path)
                        # Delete related directories
                        if is_dir_exists(item_path) and valid_item:
                            shutil.rmtree(item_path)
                    data = {'deleted': 'yes'}
            if api:
                return data
            else:
                ctype = 'application/json; charset=utf-8'
                return HttpResponse(json.dumps(data), content_type=ctype)
    except Exception as exp:
        msg = str(exp)
        exp_doc = exp.__doc__
        if api:
            return error_response(request, msg, True, exp_doc)
        else:
            return error_response(request, msg, False, exp_doc)


def health(request):
    """Check MobSF system health."""
    # Ensure database access is good
    RecentScansDB.objects.all().first()
    data = {'status': 'OK'}
    return HttpResponse(json.dumps(data),
                        content_type='application/json; charset=utf-8')


class RecentScans(object):

    def __init__(self, request):
        self.request = request

    def recent_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        result = RecentScansDB.objects.all().values().order_by('-TIMESTAMP')
        try:
            paginator = Paginator(result, page_size)
            content = paginator.page(page)
            data = {
                'content': list(content),
                'count': paginator.count,
                'num_pages': paginator.num_pages,
            }
        except Exception as exp:
            data = {'error': str(exp)}
        return data

    def cyberspect_recent_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        cs_scans = CyberspectScans.objects.all()
        result = cs_scans.values().order_by('-INTAKE_START')
        try:
            paginator = Paginator(result, page_size)
            content = paginator.page(page)
            data = {
                'content': list(content),
                'count': paginator.count,
                'num_pages': paginator.num_pages,
            }
        except Exception as exp:
            data = {'error': str(exp)}
        return data
