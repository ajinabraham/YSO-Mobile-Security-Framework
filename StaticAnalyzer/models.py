from django.db import models
# Create your models here.

class RecentScansDB(models.Model):
    NAME = models.CharField(max_length=260)
    MD5 = models.CharField(max_length=32)
    URL = models.URLField()
    TS = models.DateTimeField()

class StaticAnalyzerAndroid(models.Model):
    TITLE = models.CharField(max_length=50)
    APP_NAME = models.CharField(max_length=260)
    SIZE = models.CharField(max_length=50)
    MD5 = models.CharField(max_length=32)
    SHA1 = models.CharField(max_length=40)
    SHA256 = models.CharField(max_length=64)
    PACKAGENAME = models.CharField(max_length=200)
    MAINACTIVITY = models.CharField(max_length=300)
    TARGET_SDK = models.CharField(max_length=50)
    MAX_SDK = models.CharField(max_length=50)
    MIN_SDK = models.CharField(max_length=50)
    ANDROVERNAME = models.CharField(max_length=100)
    ANDROVER = models.CharField(max_length=50)
    MANIFEST_ANAL = models.TextField()
    PERMISSIONS = models.TextField()
    BIN_ANALYSIS = models.TextField()
    FILES = models.TextField()
    CERTZ = models.TextField()
    ICON_HIDDEN = models.BooleanField(default=False)
    ICON_FOUND = models.BooleanField(default=False)
    ACTIVITIES = models.TextField()
    RECEIVERS = models.TextField()
    PROVIDERS = models.TextField()
    SERVICES = models.TextField()
    LIBRARIES = models.TextField()
    BROWSABLE = models.TextField()
    CNT_ACT = models.CharField(max_length=50)
    CNT_PRO = models.CharField(max_length=50)
    CNT_SER = models.CharField(max_length=50)
    CNT_BRO = models.CharField(max_length=50)
    CERT_INFO = models.TextField()
    ISSUED = models.CharField(max_length=10)
    SHA256DIGEST = models.BooleanField(default=False)
    API = models.TextField()
    DANG = models.TextField()
    URLS = models.TextField()
    DOMAINS = models.TextField()
    EMAILS = models.TextField()
    STRINGS = models.TextField()
    ZIPPED = models.TextField()
    MANI = models.TextField()
    EXPORTED_ACT = models.TextField()
    E_ACT = models.CharField(max_length=50)
    E_SER = models.CharField(max_length=50)
    E_BRO = models.CharField(max_length=50)
    E_CNT = models.CharField(max_length=50)
    APK_ID = models.TextField()


class StaticAnalyzerIPA(models.Model):
    TITLE = models.CharField(max_length=50)
    FILE_NAME = models.CharField(max_length=255)
    SIZE = models.CharField(max_length=50)
    MD5 = models.CharField(max_length=32)
    SHA1 = models.CharField(max_length=40)
    SHA256 = models.CharField(max_length=64)
    INFOPLIST = models.TextField()
    BINNAME = models.CharField(max_length=260)
    IDF = models.TextField()
    BUILD = models.TextField()
    VERSION = models.CharField(max_length=100)
    SDK = models.CharField(max_length=50)
    PLTFM = models.CharField(max_length=50)
    MINX = models.CharField(max_length=50)
    BIN_ANAL = models.TextField()
    LIBS = models.TextField()
    FILES = models.TextField()
    SFILESX = models.TextField()
    STRINGS = models.TextField()
    PERMISSIONS = models.TextField()
    INSECCON = models.TextField()
    BUNDLE_NAME = models.CharField(max_length=155)
    BUNDLE_URL_TYPES = models.TextField()
    BUNDLE_SUPPORTED_PLATFORMS = models.CharField(max_length=50)
    BUNDLE_LOCALIZATIONS = models.TextField()


class StaticAnalyzerIOSZIP(models.Model):
    TITLE = models.CharField(max_length=50)
    FILE_NAME = models.CharField(max_length=260)
    SIZE = models.CharField(max_length=50)
    MD5 = models.CharField(max_length=32)
    SHA1 = models.CharField(max_length=40)
    SHA256 = models.CharField(max_length=64)
    INFOPLIST = models.TextField()
    BINNAME = models.CharField(max_length=260)
    IDF = models.TextField()
    BUILD = models.TextField()
    VERSION = models.CharField(max_length=100)
    SDK = models.CharField(max_length=50)
    PLTFM = models.CharField(max_length=50)
    MINX = models.CharField(max_length=50)
    BIN_ANAL = models.TextField()
    LIBS = models.TextField()
    FILES = models.TextField()
    SFILESX = models.TextField()
    API = models.TextField()
    CODEANAL = models.TextField()
    URLnFile = models.TextField()
    DOMAINS = models.TextField()
    EmailnFile = models.TextField()
    PERMISSIONS = models.TextField()
    INSECCON = models.TextField()
    BUNDLE_NAME = models.CharField(max_length=155)
    BUNDLE_URL_TYPES = models.TextField()
    BUNDLE_SUPPORTED_PLATFORMS = models.CharField(max_length=50)
    BUNDLE_LOCALIZATIONS = models.TextField()


class StaticAnalyzerWindows(models.Model):
    TITLE = models.CharField(max_length=260)
    APP_NAME = models.CharField(max_length=260)
    PUB_NAME = models.TextField()
    SIZE = models.CharField(max_length=50)
    MD5 = models.CharField(max_length=32)
    SHA1 = models.CharField(max_length=40)
    SHA256 = models.CharField(max_length=64)
    BINNAME = models.CharField(max_length=260)
    VERSION = models.TextField()
    ARCH = models.TextField()
    COMPILER_VERSION = models.TextField()
    VISUAL_STUDIO_VERSION = models.TextField()
    VISUAL_STUDIO_EDITION = models.TextField()
    TARGET_OS = models.TextField()
    APPX_DLL_VERSION = models.TextField()
    PROJ_GUID = models.TextField()
    OPTI_TOOL = models.TextField()
    TARGET_RUN = models.TextField()
    FILES = models.TextField()
    STRINGS = models.TextField()
    BIN_AN_RESULTS = models.TextField()
    BIN_AN_WARNINGS = models.TextField()
