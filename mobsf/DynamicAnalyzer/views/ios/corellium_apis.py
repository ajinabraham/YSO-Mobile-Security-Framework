# -*- coding: utf_8 -*-
"""Corellium APIs."""
import logging
import os
from copy import deepcopy
from socket import gethostname

from django.conf import settings

import requests

from mobsf.MobSF.utils import is_number
from mobsf.MobSF.proxy import upstream_proxy


SUCCESS_RESP = (200, 204)
ERROR_RESP = (400, 403, 404, 409)
OK = 'ok'
CORELLIUM_DEFAULT = 'https://app.corellium.com'
CORELLIUM_API_DOMAIN = getattr(
    settings,
    'CORELLIUM_API_DOMAIN',
    CORELLIUM_DEFAULT)
if not CORELLIUM_API_DOMAIN:
    CORELLIUM_API_DOMAIN = CORELLIUM_DEFAULT
CORELLIUM_API_KEY = getattr(
    settings,
    'CORELLIUM_API_KEY', '')
logger = logging.getLogger(__name__)
TIMEOUT = 20


class CorelliumInit:

    def __init__(self) -> None:
        self.api = f'{CORELLIUM_API_DOMAIN}/api/v1'
        self.api_key = CORELLIUM_API_KEY
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}',
        }
        self.proxies, self.verify = upstream_proxy('https')


class CorelliumAPI(CorelliumInit):

    def __init__(self, project_id) -> None:
        super().__init__()
        self.project_id = project_id

    def api_ready(self):
        """Check API Availability."""
        try:
            r = requests.get(f'{self.api}/ready',
                             timeout=TIMEOUT,
                             proxies=self.proxies,
                             verify=self.verify)
            if r.status_code in SUCCESS_RESP:
                return True
            else:
                logger.error('Corellium API is not ready.'
                             ' Status code: %s', r.status_code)
        except Exception:
            logger.error('Network unreachable.')
            return False
        return False

    def api_auth(self):
        """Check Corellium API Auth."""
        if not self.api_key:
            logger.error('Corellium API key is not set')
            return False
        r = requests.get(
            f'{self.api}/projects',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in ERROR_RESP:
            return False
        return True

    def get_projects(self):
        """Get Projects."""
        logger.info('Getting Corellium project id')
        if self.project_id:
            return True
        else:
            ids = []
            r = requests.get(
                f'{self.api}/projects?ids_only=true',
                timeout=TIMEOUT,
                headers=self.headers,
                proxies=self.proxies,
                verify=self.verify)
            if r.status_code in SUCCESS_RESP:
                for i in r.json():
                    ids.append(i['id'])
            if ids:
                self.project_id = ids[0]
                return True
        return False

    def get_authorized_keys(self):
        """Get SSH public keys associated with a project."""
        r = requests.get(
            f'{self.api}/projects/{self.project_id}/keys',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return r.json()
        return False

    def add_authorized_key(self, key):
        """Add SSH public key to the Project."""
        logger.info('Adding SSH public key to Corellium project')
        extras = ''
        if os.getenv('MOBSF_PLATFORM') == 'docker':
            extras = ' - (docker)'
        data = {
            'kind': 'ssh',
            'label': f'MobSF SSH Key - {gethostname()}{extras}',
            'key': key,
        }
        r = requests.post(
            f'{self.api}/projects/{self.project_id}/keys',
            timeout=TIMEOUT,
            headers=self.headers,
            json=data,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return r.json()['identifier']
        return False

    def delete_authorized_key(self, key_id):
        """Delete SSH public key from the Project."""
        r = requests.delete(
            f'{self.api}/projects/{self.project_id}/keys/{key_id}',
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return OK
        return False

    def get_instances(self):
        """Get Instances."""
        logger.info('Getting iOS instances')
        instances = []
        r = requests.get(
            f'{self.api}/instances',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            for i in r.json():
                if i['type'] == 'ios' and 'jailbroken' in i['patches']:
                    instances.append(i)
        return instances

    def create_ios_instance(self, name, flavor, version):
        """Create a Jailbroken iOS instance."""
        data = {
            'project': self.project_id,
            'name': f'{name} - {flavor.upper()}',
            'flavor': flavor,
            'os': version,
        }
        r = requests.post(
            f'{self.api}/instances',
            timeout=TIMEOUT,
            headers=self.headers,
            json=data,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return r.json()['id']
        return False


class CorelliumModelsAPI(CorelliumInit):

    def get_models(self):
        r = requests.get(
            f'{self.api}/models',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return r.json()
        return False

    def get_supported_os(self, model):
        models = self.get_models()
        if not models:
            return False
        allowed = False
        for i in models:
            if i['type'] == 'ios' and model == i['model']:
                allowed = True
                break
        if not allowed:
            return False
        r = requests.get(
            f'{self.api}/models/{model}/software',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return r.json()
        elif r.status_code in ERROR_RESP:
            return r.json()['error']
        return False


class CorelliumInstanceAPI(CorelliumInit):

    def __init__(self, instance_id) -> None:
        super().__init__()
        self.instance_id = instance_id

    def start_instance(self):
        """Start instance."""
        data = {'paused': False}
        r = requests.post(
            f'{self.api}/instances/{self.instance_id}/start',
            timeout=TIMEOUT,
            headers=self.headers,
            json=data,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return OK
        elif r.status_code in ERROR_RESP:
            return r.json()['error']
        return False

    def stop_instance(self):
        """Stop instance."""
        data = {'soft': True}
        r = requests.post(
            f'{self.api}/instances/{self.instance_id}/stop',
            timeout=TIMEOUT,
            headers=self.headers,
            json=data,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return OK
        elif r.status_code in ERROR_RESP:
            return r.json()['error']
        return False

    def unpause_instance(self):
        """Unpause instance."""
        r = requests.post(
            f'{self.api}/instances/{self.instance_id}/unpause',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return OK
        elif r.status_code in ERROR_RESP:
            return r.json()['error']
        return False

    def reboot_instance(self):
        """Reboot instance."""
        r = requests.post(
            f'{self.api}/instances/{self.instance_id}/reboot',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return OK
        elif r.status_code in ERROR_RESP:
            return r.json()['error']
        return False

    def remove_instance(self):
        """Remove instance."""
        r = requests.delete(
            f'{self.api}/instances/{self.instance_id}',
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return OK
        elif r.status_code in ERROR_RESP:
            return r.json()['error']
        return False

    def poll_instance(self):
        """Check instance status."""
        r = requests.get(
            f'{self.api}/instances/{self.instance_id}',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return r.json()
        return False

    def screenshot(self):
        """Take screenshot inside VM."""
        r = None
        err = ''
        try:
            r = requests.get(
                (f'{self.api}/instances/{self.instance_id}'
                 '/screenshot.png?scale=1'),
                timeout=TIMEOUT,
                headers=self.headers,
                stream=True,
                proxies=self.proxies,
                verify=self.verify)
            if r.status_code == 200:
                return r.content
        except Exception:
            if r and r.json().get('error'):
                err = r.json()['error']
            logger.error('Failed to take a screenshot. %s', err)
        return False

    def start_network_capture(self):
        """Start network capture."""
        r = requests.post(
            f'{self.api}/instances/{self.instance_id}/sslsplit/enable',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return OK
        err = r.json()['error']
        if 'network monitoring enabled' in err:
            return OK
        logger.error(
            'Failed to enable network monitoring. %s', err)
        return r.json()['error']

    def stop_network_capture(self):
        """Stop network capture."""
        r = requests.post(
            f'{self.api}/instances/{self.instance_id}/sslsplit/disable',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return OK
        logger.error(
            'Failed to disable network monitoring. %s', r.json()['error'])
        return r.json()['error']

    def download_network_capture(self):
        """Download network capture."""
        r = requests.get(
            f'{self.api}/instances/{self.instance_id}/networkMonitor.pcap',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return r.content
        logger.error(
            'Failed to download pcap. %s', r.json()['error'])
        return None

    def console_log(self):
        """Get Console Log."""
        r = requests.get(
            f'{self.api}/instances/{self.instance_id}/consoleLog',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return r.content.decode('utf-8', 'ignore')
        logger.error(
            'Failed to disable network monitoring. %s', r.json()['error'])
        return r.json()['error']

    def get_ssh_connection_string(self):
        """Get SSH connection string."""
        r = requests.get(
            f'{self.api}/instances/{self.instance_id}/quickConnectCommand',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return r.text
        logger.error(
            'Failed to get SSH connection string %s', r.json()['error'])
        return r.json()['error']

    def device_input(self, event, x, y, max_x, max_y):
        """Provide touch/button event to VM."""
        if event == 'text':
            data = [{
                'text': x,
            }]
        else:
            if (not is_number(x)
                    or not is_number(y)
                    or not is_number(max_x)
                    or not is_number(max_y)):
                return 'Invalid coordinates'
            # Should not be greater than max screen size
            swipe_x = min(int(x) + 200, int(max_x))
            swipe_y = min(int(y) + 400, int(max_y))
            # Just to prevent linter complaining
            # Make use of these variables in future
            swipe_x = swipe_y
            swipe_y = swipe_x
            if event == 'home':
                data = [{
                    'buttons': ['holdButton'],
                }]
            elif event == 'enter':
                data = [{
                    'buttons': ['enter'],
                }]
            elif event == 'backspace':
                data = [{
                    'buttons': ['backspace'],
                }]
            elif event == 'left':
                data = [{
                    'buttons': ['left'],
                }]
            elif event == 'right':
                data = [{
                    'buttons': ['right'],
                }]
            elif event == 'swipe_up':
                data = [{
                    'startButtons': ['finger'],
                    'start': [[x, 600]],
                    'end': [[400, y]],
                    'duration': 200,
                }]
            elif event == 'swipe_down':
                data = [{
                    'startButtons': ['finger'],
                    'start': [[300, 600]],
                    'bezierPoints': [[[700, 350]], [[850, 375]]],
                    'end': [[950, 400]],
                    'duration': 200,
                }]
            elif event == 'swipe_left':
                data = [{
                    'startButtons': ['finger'],
                    'start': [[100, 900]],
                    'bezierPoints': [[[700, 350]], [[850, 375]]],
                    'end': [[900, 100]],
                    'duration': 200,
                }]
            elif event == 'swipe_right':
                data = [{
                    'startButtons': ['finger'],
                    'start': [[700, 100]],
                    'bezierPoints': [[[350, 750]], [[375, 875]]],
                    'end': [[100, 700]],
                    'duration': 200,
                }]
            else:
                data = [
                    {'buttons': ['finger'],
                     'position': [[x, y]],
                     'wait': 0},
                    {'buttons': [], 'wait': 100}]
        r = requests.post(
            f'{self.api}/instances/{self.instance_id}/input',
            timeout=TIMEOUT,
            headers=self.headers,
            json=data,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return OK
        logger.error(
            'Failed to send touch event. %s', r.json()['error'])
        return r.json()['error']


class CorelliumAgentAPI(CorelliumInit):

    def __init__(self, instance_id) -> None:
        super().__init__()
        self.instance_id = instance_id

    def agent_ready(self):
        """Agent ready."""
        r = requests.get(
            f'{self.api}/instances/{self.instance_id}/agent/v1/app/ready',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            logger.info('Corellium Agent is Ready!')
            return r.json()['ready']
        elif r.status_code in ERROR_RESP:
            logger.error('Corellium Agent is not Ready, Please Wait!')
            return r.json()['error']
        return False

    def unlock_device(self):
        """Unlock iOS device."""
        r = requests.post(
            f'{self.api}/instances/{self.instance_id}/agent/v1/system/unlock',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            logger.info('Device unlocked')
            return OK
        elif r.status_code in ERROR_RESP:
            logger.error('Failed to unlock device')
            return r.json()['error']
        return False

    def upload_ipa(self, ipa_file):
        """Upload IPA."""
        logger.info('Uploading IPA to iOS instance...')
        headers = deepcopy(self.headers)
        headers['Content-Type'] = 'application/octet-stream'
        r = requests.put(
            (f'{self.api}/instances/{self.instance_id}'
             f'/agent/v1/file/device/%2Ftmp%2Fapp.ipa'),
            data=open(ipa_file, 'rb').read(),
            headers=headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            logger.info('IPA uploaded to instance')
            return OK
        logger.error('Failed to upload IPA %s', r.json()['error'])
        return r.json()['error']

    def install_ipa(self):
        """Install IPA."""
        r = requests.post(
            f'{self.api}/instances/{self.instance_id}/agent/v1/app/install',
            timeout=TIMEOUT,
            headers=self.headers,
            json={'path': '/tmp/app.ipa'},
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            logger.info('App installed')
            return OK
        logger.error('Failed to install the IPA. %s', r.json()['error'])
        return r.json()['error']

    def run_app(self, bundle_id):
        """Run an App."""
        r = requests.post(
            (f'{self.api}/instances/{self.instance_id}'
             f'/agent/v1/app/apps/{bundle_id}/run'),
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            logger.info('App Started')
            return OK
        logger.error('Failed to start the app. %s', r.json()['error'])
        return r.json()['error']

    def stop_app(self, bundle_id):
        """Stop an App."""
        r = requests.post(
            (f'{self.api}/instances/{self.instance_id}'
             f'/agent/v1/app/apps/{bundle_id}/kill'),
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            logger.info('App Killed')
            return OK
        logger.error('Failed to stop the app. %s', r.json()['error'])
        return r.json()['error']

    def remove_app(self, bundle_id):
        """Remove an app from VM."""
        r = requests.post(
            (f'{self.api}/instances/{self.instance_id}'
             f'/agent/v1/app/apps/{bundle_id}/uninstall'),
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            logger.info('App Removed')
            return OK
        logger.error('Failed to remove the app. %s', r.json()['error'])
        return r.json()['error']

    def list_apps(self):
        """List all apps installed."""
        r = requests.get(
            f'{self.api}/instances/{self.instance_id}/agent/v1/app/apps',
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return r.json()
        elif r.status_code in ERROR_RESP:
            return r.json()
        return False

    def get_icons(self, bundleids):
        """Get app icons by bundleId."""
        r = requests.get(
            (f'{self.api}/instances/{self.instance_id}'
             f'/agent/v1/app/icons?{bundleids}'),
            timeout=TIMEOUT,
            headers=self.headers,
            proxies=self.proxies,
            verify=self.verify)
        if r.status_code in SUCCESS_RESP:
            return r.json()
        elif r.status_code in ERROR_RESP:
            return r.json()
        return False
