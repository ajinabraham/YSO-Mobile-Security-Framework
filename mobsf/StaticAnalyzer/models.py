from datetime import datetime

from django.db import models
# Create your models here.


class RecentScansDB(models.Model):
    ANALYZER = models.CharField(max_length=50, default='')
    SCAN_TYPE = models.CharField(max_length=10, default='')
    FILE_NAME = models.CharField(max_length=260, default='')
    APP_NAME = models.CharField(max_length=260, default='')
    PACKAGE_NAME = models.CharField(max_length=260, default='')
    VERSION_NAME = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='', primary_key=True)
    TIMESTAMP = models.DateTimeField(default=datetime.now)
    USER_APP_NAME = models.CharField(max_length=260, default='')
    USER_APP_VERSION = models.CharField(max_length=50, default='')
    DIVISION = models.CharField(max_length=260, default='')
    ENVIRONMENT = models.CharField(max_length=50, default='')
    EMAIL = models.CharField(max_length=260, default='')
    USER_GROUPS = models.CharField(max_length=260, default='')
    RELEASE = models.BooleanField(default=False)
    COUNTRY = models.CharField(max_length=260, default='')
    DATA_PRIVACY_CLASSIFICATION = models.CharField(max_length=100, default='')
    DATA_PRIVACY_ATTRIBUTES = models.CharField(max_length=100, default='')


class StaticAnalyzerAndroid(models.Model):
    FILE_NAME = models.CharField(max_length=260, default='')
    APP_NAME = models.CharField(max_length=255, default='')
    APP_TYPE = models.CharField(max_length=20, default='')
    SIZE = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='', primary_key=True)
    SHA1 = models.CharField(max_length=40, default='')
    SHA256 = models.CharField(max_length=64, default='')
    PACKAGE_NAME = models.TextField(default='')
    MAIN_ACTIVITY = models.TextField(default='')
    EXPORTED_ACTIVITIES = models.TextField(default='')
    BROWSABLE_ACTIVITIES = models.TextField(default={})
    ACTIVITIES = models.TextField(default=[])
    RECEIVERS = models.TextField(default=[])
    PROVIDERS = models.TextField(default=[])
    SERVICES = models.TextField(default=[])
    LIBRARIES = models.TextField(default=[])
    TARGET_SDK = models.CharField(max_length=50, default='')
    MAX_SDK = models.CharField(max_length=50, default='')
    MIN_SDK = models.CharField(max_length=50, default='')
    VERSION_NAME = models.CharField(max_length=100, default='')
    VERSION_CODE = models.CharField(max_length=50, default='')
    ICON_HIDDEN = models.BooleanField(default=False)
    ICON_FOUND = models.BooleanField(default=False)
    PERMISSIONS = models.TextField(default={})
    CERTIFICATE_ANALYSIS = models.TextField(default={})
    MANIFEST_ANALYSIS = models.TextField(default=[])
    BINARY_ANALYSIS = models.TextField(default=[])
    FILE_ANALYSIS = models.TextField(default=[])
    ANDROID_API = models.TextField(default={})
    CODE_ANALYSIS = models.TextField(default={})
    NIAP_ANALYSIS = models.TextField(default={})
    URLS = models.TextField(default=[])
    DOMAINS = models.TextField(default={})
    EMAILS = models.TextField(default=[])
    STRINGS = models.TextField(default={})
    FIREBASE_URLS = models.TextField(default=[])
    FILES = models.TextField(default=[])
    EXPORTED_COUNT = models.TextField(default={})
    APKID = models.TextField(default={})
    QUARK = models.TextField(default=[])
    TRACKERS = models.TextField(default={})
    PLAYSTORE_DETAILS = models.TextField(default={})
    NETWORK_SECURITY = models.TextField(default=[])
    SECRETS = models.TextField(default=[])


class StaticAnalyzerIOS(models.Model):
    FILE_NAME = models.CharField(max_length=255, default='')
    APP_NAME = models.CharField(max_length=255, default='')
    APP_TYPE = models.CharField(max_length=20, default='')
    SIZE = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='', primary_key=True)
    SHA1 = models.CharField(max_length=40, default='')
    SHA256 = models.CharField(max_length=64, default='')
    BUILD = models.TextField(default='')
    APP_VERSION = models.CharField(max_length=100, default='')
    SDK_NAME = models.CharField(max_length=50, default='')
    PLATFORM = models.CharField(max_length=50, default='')
    MIN_OS_VERSION = models.CharField(max_length=50, default='')
    BUNDLE_ID = models.TextField(default='')
    BUNDLE_URL_TYPES = models.TextField(default=[])
    BUNDLE_SUPPORTED_PLATFORMS = models.CharField(max_length=50, default=[])
    ICON_FOUND = models.BooleanField(default=False)
    INFO_PLIST = models.TextField(default='')
    BINARY_INFO = models.TextField(default={})
    PERMISSIONS = models.TextField(default={})
    ATS_ANALYSIS = models.TextField(default=[])
    BINARY_ANALYSIS = models.TextField(default=[])
    MACHO_ANALYSIS = models.TextField(default={})
    DYLIB_ANALYSIS = models.TextField(default=[])
    IOS_API = models.TextField(default={})
    CODE_ANALYSIS = models.TextField(default={})
    FILE_ANALYSIS = models.TextField(default=[])
    LIBRARIES = models.TextField(default=[])
    FILES = models.TextField(default=[])
    URLS = models.TextField(default=[])
    DOMAINS = models.TextField(default={})
    EMAILS = models.TextField(default=[])
    STRINGS = models.TextField(default=[])
    FIREBASE_URLS = models.TextField(default=[])
    APPSTORE_DETAILS = models.TextField(default={})
    SECRETS = models.TextField(default=[])
    TRACKERS = models.TextField(default={})


class StaticAnalyzerWindows(models.Model):
    FILE_NAME = models.CharField(max_length=260, default='')
    APP_NAME = models.CharField(max_length=260, default='')
    PUBLISHER_NAME = models.TextField(default='')
    SIZE = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='', primary_key=True)
    SHA1 = models.CharField(max_length=40, default='')
    SHA256 = models.CharField(max_length=64, default='')
    APP_VERSION = models.TextField(default='')
    ARCHITECTURE = models.TextField(default='')
    COMPILER_VERSION = models.TextField(default='')
    VISUAL_STUDIO_VERSION = models.TextField(default='')
    VISUAL_STUDIO_EDITION = models.TextField(default='')
    TARGET_OS = models.TextField(default='')
    APPX_DLL_VERSION = models.TextField(default='')
    PROJ_GUID = models.TextField(default='')
    OPTI_TOOL = models.TextField(default='')
    TARGET_RUN = models.TextField(default='')
    FILES = models.TextField(default=[])
    STRINGS = models.TextField(default=[])
    BINARY_ANALYSIS = models.TextField(default=[])
    BINARY_WARNINGS = models.TextField(default=[])


class SuppressFindings(models.Model):
    PACKAGE_NAME = models.CharField(max_length=260, default='')
    SUPPRESS_RULE_ID = models.TextField(default=[])
    SUPPRESS_FILES = models.TextField(default={})
    SUPPRESS_TYPE = models.TextField(default='')


class CyberspectScans(models.Model):
    ID = models.BigAutoField(primary_key=True)
    MOBSF_MD5 = models.CharField(max_length=32, null=True)
    DT_PROJECT_ID = models.UUIDField(null=True)
    SCHEDULED = models.BooleanField(null=False, default=False)
    INTAKE_START = models.DateTimeField(null=False)
    INTAKE_END = models.DateTimeField(null=True)
    SAST_START = models.DateTimeField(null=True)
    SAST_END = models.DateTimeField(null=True)
    SBOM_START = models.DateTimeField(null=True)
    SBOM_END = models.DateTimeField(null=True)
    DEPENDENCY_START = models.DateTimeField(null=True)
    DEPENDENCY_END = models.DateTimeField(null=True)
    NOTIFICATION_START = models.DateTimeField(null=True)
    NOTIFICATION_END = models.DateTimeField(null=True)
    SUCCESS = models.BooleanField(null=True)
    FAILURE_SOURCE = models.CharField(max_length=50, null=True)
    FAILURE_MESSAGE = models.TextField(null=True)
    FILE_SIZE_PACKAGE = models.IntegerField(null=True)
    FILE_SIZE_SOURCE = models.IntegerField(null=True)
    DEPENDENCY_TYPES = models.CharField(max_length=50, null=True)
    EMAIL = models.CharField(max_length=260, null=True)


class ApiKeys(models.Model):

    class Role(models.IntegerChoices):
        """API Key role options."""

        UPLOAD_ONLY = 1
        READ_ONLY = 2
        FULL_ACCESS = 3

    ID = models.AutoField(primary_key=True)
    KEY_HASH = models.CharField(max_length=64, default='')
    KEY_PREFIX = models.CharField(max_length=5, default='')
    DESCRIPTION = models.CharField(max_length=100, default='')
    EMAIL = models.CharField(max_length=260, default='')
    ROLE = models.IntegerField(choices=Role.choices, default=Role.UPLOAD_ONLY)
    CREATE_DATE = models.DateTimeField(default=datetime.now)
    EXPIRE_DATE = models.DateTimeField(default=datetime.now)
    REVOKED_DATE = models.DateTimeField(null=True)
