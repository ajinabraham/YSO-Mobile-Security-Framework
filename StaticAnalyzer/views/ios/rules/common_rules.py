"""
This file contains common iOS security rules used in source code analysis.

Rule Format.

1. desc - Description of the findings

2. type
   a. string
   b. regex

3. match
   a. single_regex - if re.findall(regex1, input)
   b .regex_and - if re.findall(regex1, input) and re.findall(regex2, input)
   c. regex_or - if re.findall(regex1, input) or re.findall(regex2, input)
   d. single_string - if string1 in input
   e. string_and - if (string1 in input) and (string2 in input)
   f. string_or - if (string1 in input) or (string2 in input)
   g. string_and_or -  if (string1 in input) and ((string_or1 in input)
                       or (string_or2 in input))
   h. string_or_and - if (string1 in input) or ((string_and1 in input)
                      and (string_and2 in input))

4. level
   a. high
   b. warning
   c. info
   d. good

5. input_case
   a. upper
   b. lower
   c. exact

6. others
   a. string<no> - string1, string2, string3, string_or1, string_and1
   b. regex<no> - regex1, regex2, regex3

"""

from StaticAnalyzer.views.matchers import (
    SingleRegex,
    StringAnd,
    StringOr,
)
from StaticAnalyzer.views.rules_properties import (
    InputCase,
    Level,
)
from StaticAnalyzer.views.standards import (
    CWE,
    OWASP,
    OWASP_MSTG,
)

COMMON_RULES = [
    {
        'desc': 'IP Address disclosure',
        'type': SingleRegex.__name__,
        'match': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'level': Level.warning,
        'input_case': InputCase.exact,
        'cvss': 4.3,
        'cwe': CWE['CWE-200'],
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['code-2'],
    },
    {
        'desc': ('Files may contain hardcoded sensitive'
                 ' informations like usernames, passwords, keys etc.'),
        'type': SingleRegex.__name__,
        'match': (r'(password\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                  r'(pass\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                  r'(username\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                  r'(secret\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                  r'(key\s*=\s*[\'|\"].+[\'|\"]\s{0,5})'),
        'level': Level.high,
        'input_case': InputCase.lower,
        'cvss': 7.4,
        'cwe': CWE['CWE-312'],
        'owasp': OWASP['m9'],
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': ('App uses SQLite Database. '
                 'Sensitive Information should be encrypted.'),
        'type': StringOr.__name__,
        'match': ['sqlite3_exec', 'sqlite3_finalize'],
        'level': Level.info,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': ('User input in "loadHTMLString" '
                 'will result in JavaScript Injection.'),
        'type': StringAnd.__name__,
        'match': ['loadHTMLString', 'webView'],
        'level': Level.warning,
        'input_case': InputCase.exact,
        'cvss': 8.8,
        'cwe': CWE['CWE-95'],
        'owasp': OWASP['m7'],
        'owasp-mstg': OWASP_MSTG['platform-5'],
    },
    {
        'desc': 'This App may have Jailbreak detection capabilities.',
        'type': StringOr.__name__,
        'match': ['/Applications/Cydia.app',
                  '/Library/MobileSubstrate/MobileSubstrate.dylib',
                  '/usr/sbin/sshd',
                  '/etc/apt',
                  'cydia://',
                  '/var/lib/cydia',
                  '/Applications/FakeCarrier.app',
                  '/Applications/Icy.app',
                  '/Applications/IntelliScreen.app',
                  '/Applications/SBSettings.app',
                  ('/Library/MobileSubstrate/DynamicLibraries/'
                   'LiveClock.plist'),
                  '/System/Library/LaunchDaemons/com.ikey.bbot.plist',
                  ('/System/Library/LaunchDaemons/'
                   'com.saurik.Cydia.Startup.plist'),
                  '/etc/ssh/sshd_config',
                  '/private/var/tmp/cydia.log',
                  '/usr/libexec/ssh-keysign',
                  '/Applications/MxTube.app',
                  '/Applications/RockApp.app',
                  '/Applications/WinterBoard.app',
                  '/Applications/blackra1n.app',
                  '/Library/MobileSubstrate/DynamicLibraries/Veency.plist',
                  '/private/var/lib/apt',
                  '/private/var/lib/cydia',
                  '/private/var/mobile/Library/SBSettings/Themes',
                  '/private/var/stash',
                  '/usr/bin/sshd',
                  '/usr/libexec/sftp-server',
                  '/var/cache/apt',
                  '/var/lib/apt',
                  '/usr/sbin/frida-server',
                  '/usr/bin/cycript',
                  '/usr/local/bin/cycript',
                  '/usr/lib/libcycript.dylib',
                  'frida-server',
                  '/etc/apt/sources.list.d/electra.list',
                  '/etc/apt/sources.list.d/sileo.sources',
                  '/.bootstrapped_electra',
                  '/usr/lib/libjailbreak.dylib',
                  '/jb/lzma',
                  '/.cydia_no_stash',
                  '/.installed_unc0ver',
                  '/jb/offsets.plist',
                  '/usr/share/jailbreak/injectme.plist',
                  '/Library/MobileSubstrate/MobileSubstrate.dylib',
                  '/usr/libexec/cydia/firmware.sh',
                  '/private/var/cache/apt/',
                  '/Library/MobileSubstrate/CydiaSubstrate.dylib'],
        'level': Level.good,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-1'],
    },
]
