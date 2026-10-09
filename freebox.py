# Thanks to https://www.manatlan.com/blog/freeboxv6_api_v3_avec_python
# and https://github.com/supermat/PluginDomoticzFreebox
# Code under GPLv3
# AUTHOR : supermat & ilionel
# CONTRIBUTOR : https://github.com/ilionel/PluginDomoticzFreebox/graphs/contributors
# Please not that supermat don't maintain this software anymore

"""
freebox.py is used by plugin.py
"""


import hashlib
import hmac
import json
import os
import re
import ssl
import time
import urllib.request
from urllib.request import urlopen, Request
from socket import timeout
import Domoticz

# Globals CONSTANT
HOST = 'https://mafreebox.freebox.fr'   # FQDN of freebox
API_VER = '8'                           # API version
TV_API_VER = '8'                        # TV Player API version
REGISTER_TMOUT = 30                     # Timout in sec (for Obtain an app_token)
API_TMOUT = 4                           # Timout in sec (for API response)
CA_FILE = 'freebox_certificates.pem'


class FbxCnx:
    """
    FbxCnx describes methods to communicate with Freebox
    """

    def __init__(self, host=HOST, api=API_VER):
        self.host = host
        self.api_ver = int(float(api))
        self.info = None
        self.secure = ssl.create_default_context()
        # Python 3.13+ enables VERIFY_X509_STRICT by default, which rejects the
        # certificates served by the Freebox (no Authority Key Identifier).
        # Keep chain/hostname verification but disable this strict check.
        self.secure.verify_flags &= ~getattr(ssl, 'VERIFY_X509_STRICT', 0)
        cert_path = os.path.join(os.path.dirname(__file__), CA_FILE)
        request = Request(host + '/api_version')
        try:
            self.secure.load_verify_locations(cafile=cert_path)
            response = urlopen(request, timeout=API_TMOUT,
                               context=self.secure).read()
            self.info = json.loads(response.decode())
            Domoticz.Debug(f"Supported API version: {self.info['api_version']}")
            Domoticz.Debug(f"Freebox model: {self.info['box_model']}")
        except (urllib.error.HTTPError, urllib.error.URLError) as error:
            Domoticz.Error(f"Init error ('/api_version'): {error}")
        except timeout:
            Domoticz.Error('Timeout when call ("/api_version")')
        if self.info is None:
            Domoticz.Error(
                'Fatal error: Unable to initialize Freebox connection!')
        elif int(float(self.info['api_version'])) < self.api_ver:
            Domoticz.Error(f"You need to upgrade Freebox's firmware to use at last API version \
                           {self.api_ver} (current API version: {self.info['api_version']}).")

    def _request(self, path, method='GET', headers=None, data=None):
        """ Send a request to Freebox API

        Args:
            path (str): api_url
            method (str, optional): method used for each request GET|POST|PUT. Defaults to 'GET'.
            headers (dict of str: str, optional): HTTP HEADERS. Defaults to None.
            data (dict of str: str, optional): POST or PUT datas. Defaults to None.

        Returns:
            (dict of str: str): Freebox API Response as dictionary
        """
        url = self.host + '/api/v' + str(self.api_ver) + '/' + path
        Domoticz.Debug('API REQUEST - URL: ' + url)
        Domoticz.Debug('API REQUEST - Method: ' + method)
        Domoticz.Debug('API REQUEST - Headers: ' + f"{headers}")
        Domoticz.Debug('API REQUEST - Data: ' + f"{data}")
        if data is not None:
            data = json.dumps(data)
            data = data.encode()
        request = Request(url=url, data=data, method=method)
        if headers is not None:
            request.headers.update(headers)
        api_response = urlopen(request, timeout=API_TMOUT,
                               context=self.secure).read()
        Domoticz.Debug(f"<- API Response: {api_response}")
        dict_response = json.loads(api_response.decode())
        return dict_response

    def register(self, app_id, app_name, version, device_name, wait=REGISTER_TMOUT):
        """
        register method is used to obtain a "app_token" (ak. grant access to Freebox)

        You must gain access to Freebox API before being able to use the api.

        This is the first step, the app will ask for an app_token using the following call.
        A message will be displayed on the Freebox LCD asking the user to grant/deny access
        to the requesting app.
        Once the app has obtained a valid app_token, it will not have to do this procedure again
        unless the user revokes the app_token.

        Args:
            app_id (str): A unique application identifier string
            app_name (str): A descriptive application name (will be displayed on lcd)
            version (str): app version
            device_name (str): The name of the device on which the app will be used
            wait (int, optional): seconds before timeout. Defaults to REGISTER_TMOUT.

        Returns:
            str: "app_token" if success else empty string
        """
        data = {
            'app_id': app_id,
            'app_name': app_name,
            'app_version': version,
            'device_name': device_name
        }
        response = self._request('login/authorize/', 'POST', None, data)
        status = 'pending'
        if not response['success'] and response['msg']:
            Domoticz.Error(f"Registration error: {response['msg']}")
        else :
            track_id, app_token = response['result']['track_id'], response['result']['app_token']
            while status != 'granted' and wait != 0:
                status = self._request(f"login/authorize/{track_id}")
                status = status['result']['status']
                wait = wait - 1
                time.sleep(1)
        if status == 'granted':
            return app_token
        return ""

    def _mksession(self, app_id, app_token):
        """
        Create a new session (to make an authenticated call to the API)

        To protect the "app_token" secret, it will never be used directly to authenticate
        the application, instead the API will provide a challenge the app will combine to
        its "app_token" to open a session and get a "session_token"

        The app will then have to include the session_token in the HTTP headers of the
        following requests

        Args:
            app_id (str): A unique application identifier string
            app_token (str): Secret application token

        Returns:
            str: "session_token"
        """
        challenge = self._request('login/')['result']['challenge']
        Domoticz.Debug('Challenge: ' + challenge)
        data = {
            "app_id": app_id,
            "password": hmac.new(app_token.encode(), challenge.encode(), hashlib.sha1).hexdigest()
        }
        session_token = self._request(
            'login/session/', 'POST', None, data)['result']['session_token']
        Domoticz.Debug('Session Token obtained')
        return session_token

    def _disconnect(self, session_token):
        """
        Closing the current session

        Returns:
            (dict of str: str): Freebox API Response as dictionary
        """
        result = self._request(
            'login/logout/',
            'POST',
            {'Content-Type': 'application/json', 'X-Fbx-App-Auth': session_token})
        Domoticz.Debug(f"Disconnect: {result}")
        return result


class FbxApp(FbxCnx):
    """
    FbxApp describe methodes to call specified Freebox API

    Args:
        FbxCnx (FbxCnx): Freebox connection
    """
    tv_player = None

    def __init__(self, app_id, app_token, host=HOST, session_token=None):
        FbxCnx.__init__(self, host)
        self.app_id, self.app_token = app_id, app_token
        self.session_token = self._mksession(
            app_id, app_token) if session_token is None else session_token
        self.system = self.create_system()
        self.players = None  # Server may be connected to a Freebox TV Player
        if self.tv_player is None:
            self.create_players()

    def __del__(self):
        # Safety net only: the owner should call close() explicitly
        self.close()

    def close(self):
        """
        Close the current session (logout), never raise.
        The instance must not be used afterwards.
        """
        session_token = getattr(self, 'session_token', None)
        if session_token is None:
            return  # Session was never opened (or already closed)
        self.session_token = None
        try:
            self._disconnect(session_token)
        except (urllib.error.HTTPError, urllib.error.URLError, timeout, OSError, ValueError) as error:
            Domoticz.Debug(f"Disconnect error: {error}")

    def _is_auth_error(self, error):
        """
        Is HTTP error due to an expired or invalid session token

        Args:
            error (urllib.error.HTTPError): error raised by an API request

        Returns:
            bool: True if a new session must be opened
        """
        if error.code != 403:
            return False
        try:
            body = json.loads(error.read().decode())
        except (ValueError, OSError, AttributeError):
            return False
        return isinstance(body, dict) and body.get('error_code') in ('auth_required', 'invalid_token')

    def _auth_request(self, path, method='GET', data=None):
        """
        Authenticated request to API: if the session has expired,
        open a new session once and retry the request once

        Args:
            path (str): api_url
            method (str, optional): GET|POST|PUT. Defaults to 'GET'.
            data (dict of str: str, optional): POST or PUT datas. Defaults to None.

        Returns:
            (dict of str: str): Freebox API Response as dictionary
        """
        try:
            return self._request(path, method, {"X-Fbx-App-Auth": self.session_token}, data)
        except urllib.error.HTTPError as error:
            if not self._is_auth_error(error):
                raise
        Domoticz.Debug('Session expired: opening a new session')
        self.session_token = self._mksession(self.app_id, self.app_token)
        return self._request(path, method, {"X-Fbx-App-Auth": self.session_token}, data)

    def post(self, path, data=None):
        """
        HTTP POST Request to API

        Args:
            path (str): api_url
            data (dict of str: str, optional): _description_. Defaults to None.

        Returns:
            (dict of str: str): Freebox API Response as dictionary
        """
        return self._auth_request(path, 'POST', data)

    def put(self, path, data=None):
        """
        HTTP PUT Request to API

        Args:
            path (str): api_url
            data (dict of str: str, optional): _description_. Defaults to None.

        Returns:
            (dict of str: str): Freebox API Response as dictionary
        """
        return self._auth_request(path, 'PUT', data)

    def get(self, path):
        """
        HTTP GET Request to API

        Args:
            path (str): api_url

        Returns:
            (dict of str: str): Freebox API Response as dictionary
        """
        return self._auth_request(path, 'GET')

    def call(self, path):
        """
        Call Freebox API

        Args:
            path (str): api_url

        Returns:
            (dict of str: str): Freebox API Response as dictionary
        """
        result = {}
        try:
            api_result = self.get(path)
            if api_result['success'] and 'result' in api_result:
                result = api_result['result']
        except (urllib.error.HTTPError, urllib.error.URLError) as error:
            Domoticz.Error(f"API Error ('{path}'): {error}")
        except timeout:
            Domoticz.Error(f"Timeout when call ('{path}')")
        return result

    def percent(self, value, total, around=2):
        """
        Formula of percentage : value / total * 100

        Args:
            value (int): numerator
            total (int): denominator
            around (int, optional): decimal precision. Defaults to 2.

        Returns:
            float: calculated percent
        """
        percent = 0
        if (total > 0) :
            percent = value / total * 100
        return round(percent, around)

    def ls_devices(self):
        """
        List of devices connected to the Freebox server

        Returns:
            (dict of str: str): {device: values}
        """
        return self.call('lan/browser/pub/')

    def ls_storage(self):
        """
        List storages attached to the Freebox server

        Returns:
            (dict of str: str): {disk_label: % of usage}
        """
        result = {}
        ls_disk = self.call('storage/disk/')
        for disk in ls_disk:
            if not 'partitions' in disk:  # /!\ If disk don't have any partition
                continue
            for partition in disk['partitions']:
                label = partition['label']
                used = partition['used_bytes']
                total = partition['total_bytes']
                percent = self.percent(used, total)
                Domoticz.Debug(f"Usage of disk '{label}': {used}/{total} bytes ({percent}%)")
                result.update({str(label): str(self.percent(used, total))})
        return result

    def get_name_from_macaddress(self, p_macaddress, devices=None):
        """
        Find device name by his mac-address

        Args:
            p_macaddress (str): @mac type 01:02:03:04:05:06
            devices (list, optional): result of ls_devices() (fetched if None). Defaults to None.

        Returns:
            str: device name if @mac is know or None
        """
        result = None
        ls_devices = self.ls_devices() if devices is None else devices
        for device in ls_devices:
            macaddress = device['id']
            if ("ETHER-" + p_macaddress.upper()) == macaddress.upper():
                result = device['primary_name']
        return result

    def reachable_macaddress(self, p_macaddress, devices=None):
        """
        Check if device is reachable by his mac-address

        Args:
            p_macaddress (str): @mac type 01:02:03:04:05:06
            devices (list, optional): result of ls_devices() (fetched if None). Defaults to None.

        Returns:
            bool: True if reachable else False
        """
        result = False
        ls_devices = self.ls_devices() if devices is None else devices
        for device in ls_devices:
            macaddress = device['id']
            if ("ETHER-" + p_macaddress.upper()) == macaddress.upper():
                reachable = device['reachable']
                if reachable:
                    result = True
                    break
        return result

    def online_devices(self):
        """
        Get online devices

        Returns:
            (dict of str: str): {macaddress: name}
        """
        result = {}
        ls_devices = self.ls_devices()
        for device in ls_devices:
            name = device['primary_name']
            reachable = device['reachable']
            macaddress = device['id']
            if reachable:
                result.update({macaddress: name})
        return result

    def alarminfo(self):  # Only on Freebox Delta
        """
        _summary_

        Returns:
            _type_: _description_
        """
        result = {}
        prerequisite_pattern = '^fbxgw7-r[0-9]+/full$'
        if self.info is None or re.match(prerequisite_pattern, self.info['box_model']) is None:
            return result  # Return an empty list if model of Freebox isn't compatible with alarm
        nodes = self.call('home/tileset/all')
        for node in nodes:
            device = {}
            label = ''
            if node.get("type") == "alarm_control":
                device.update({"type": str(node["type"])})
                for data in node.get("data", []):
                    if data.get("ep_id") == 11:
                        label = data.get("label", '')
                        if data.get('value') == 'alarm1_armed':
                            value = 1
                            device.update(
                                {"alarm1_status": str(value)})
                        elif data.get('value') == 'alarm1_arming':
                            value = -1
                            device.update(
                                {"alarm1_status": str(value)})
                        else:
                            value = 0
                            device.update(
                                {"alarm1_status": str(value)})
                        if data.get('value') == 'alarm2_armed':
                            value = 1
                            device.update(
                                {"alarm2_status": str(value)})
                        elif data.get('value') == 'alarm2_arming':
                            value = -1
                            device.update(
                                {"alarm2_status": str(value)})
                        else:
                            value = 0
                            device.update(
                                {"alarm2_status": str(value)})
                        device.update({"label": str(label)})
                    elif data.get("ep_id") == 13:  # error
                        status_error = data.get("value")
                        device.update(
                            {"status_error": str(status_error)})
                    elif data.get("name") == 'battery_warning':
                        battery = data.get("value")
                        device.update({"battery": str(battery)})
                # Build alarm devices once all endpoints (and thus the label) are known
                if 'alarm1_status' in device:
                    device1 = device.copy()
                    device1['value'] = device1['alarm1_status']
                    device1['label'] = device1.get('label', '') + '1'
                    result.update({device1['label']: device1})
                if 'alarm2_status' in device:
                    device2 = device.copy()
                    device2['value'] = device2['alarm2_status']
                    device2['label'] = device2.get('label', '') + '2'
                    result.update({device2['label']: device2})

        if nodes:  # Sensors are only read when tileset is available (one call)
            home_nodes = self.call("home/nodes")
            for home_node in home_nodes:
                device = {}
                label = ''
                if home_node.get("category") in ("pir", "dws"):
                    label = home_node.get("label", '')
                    device.update({"label": str(label)})
                    device.update({"type": str(home_node["category"])})
                    for endpoint in home_node.get("show_endpoints", []):
                        if endpoint.get("name") == 'battery':
                            battery = endpoint.get("value")
                            device.update({"battery": str(battery)})
                        elif endpoint.get("name") == 'trigger':
                            if endpoint.get("value"):
                                device.update({"value": 0})
                            else:
                                device.update({"value": 1})
                        result.update({label: device})
        return result

    def connection_rate(self, connection=None):
        """
        Get upload and download speed rate (of WAN Interface)

        Args:
            connection (dict, optional): result of call('connection/') (fetched if None). Defaults to None.

        Returns:
            (dict of str: str): {rate_down: rate, rate_up: rate} (ko/s)
        """
        result = {}
        if connection is None:
            connection = self.call('connection/')
        if connection.get('rate_down') is not None:
            result.update({str('rate_down'): str(connection['rate_down']/1024)})
        if connection.get('rate_up') is not None:
            result.update({str('rate_up'): str(connection['rate_up']/1024)})
        return result

    def wan_state(self, connection=None):
        """
        Is WAN link UP or DOWN

        Args:
            connection (dict, optional): result of call('connection/') (fetched if None). Defaults to None.

        Returns:
            bool: True if "UP" else False (None if state is unavailable)
        """
        state = None
        if connection is None:
            connection = self.call('connection/')
        if connection.get('state') is None:
            Domoticz.Debug('Connection state is unavailable')
        elif connection['state'] == 'up':
            Domoticz.Debug('Connection is UP')
            state = True
        else:
            Domoticz.Debug('Connection is DOWN')
            state = False
        return state

    def wifi_state(self):
        """
        Is WLAN state UP or DOWN

        Returns:
            bool: True if "UP" else False (None if state is unavailable)
        """
        enabled = None
        wifi = self.call('wifi/config/')
        if wifi.get('enabled') is None:
            Domoticz.Debug('Wifi state is unavailable')
        elif wifi['enabled']:
            Domoticz.Debug('Wifi interface is UP')
            enabled = True
        else:
            Domoticz.Debug('Wifi interface is DOWN')
            enabled = False
        return enabled

    def wifi_enable(self, switch_on):
        """
        Switch wifi ON or OFF

        Args:
            switch_on (bool): True to switch ON or False du switch OFF

        Raises:
            timeout: Catch error if you are disconnected due to wifi switch OFF

        Returns:
            bool: wifi state
        """
        status = None
        if switch_on:
            data = {'enabled': True}
        else:
            data = {'enabled': False}
        try:
            response = self.put("wifi/config/", data)
            status = False
            if response['success']:
                if response['result']['enabled']:
                    status = True
                    Domoticz.Debug('Wifi is now ON')
                else:
                    Domoticz.Debug('Wifi is now OFF')
        except (urllib.error.HTTPError, urllib.error.URLError) as error:
            if not switch_on and isinstance(getattr(error, 'reason', None), (timeout, TimeoutError)):
                # Connect timeout is wrapped in URLError: same as the timeout case below
                Domoticz.Log('Wifi disabled')
                status = False
            else:
                Domoticz.Error(f"API Error ('wifi/config/'): {error}")
        except timeout as exc:
            if not switch_on:
                # If we are connected using wifi, disabling wifi will close connection
                # thus PUT response will never be received: a timeout is expected
                Domoticz.Log('Wifi disabled')
                status = False
            else:
                # Forward timeout exception as should not occur
                raise timeout from exc
        return status

    def reboot(self):
        """
        Reboot the Freebox server
        """
        Domoticz.Debug('Try to reboot')
        response = self.post("system/reboot")
        if response['success']:
            Domoticz.Debug('Reboot initiated')
        else:
            Domoticz.Error('Error: You must grant reboot permission')

    def next_pvr_precord_timestamp(self, relative=True):
        """
        Next schedule / programmed PVR record
        
        Args:
            relative (bool, optional): if True time result is relative else absolute. Defaults to True.
        
        Returns:
            int: start_timestamp
        """
        precord = False
        now = int(time.time())
        next_recording = now -1 # -1 if none programmed PVR record
        result = self.call('/pvr/programmed')
        Domoticz.Debug(f"PVR Programmed List: {result}")
        for pvr in result:
            if pvr['state'] == 'waiting_start_time':
                recording_start = int(float(pvr['start']))
                if not precord:
                    next_recording = recording_start
                    precord = True
                next_recording = recording_start if recording_start < next_recording else next_recording
            elif pvr['state'] == 'starting' or pvr['state'] == 'running' or pvr['state'] == 'running_error':
                next_recording = now
                break
        return (next_recording - now) if relative else next_recording

    def create_system(self):
        """
        Create system information

        Returns:
            System: Freebox System Object 
        """
        self.system = FbxApp.System(self)
        return self.system

    def create_players(self):
        """
        Create sub-objet TV Players

        Returns:
            Players: Freebox TV Players Object
        """
        self.players = FbxApp.Players(self)
        return self.players

    class System:
        """
        Class and method about System (°temp_sensor,...)
        """
        def __init__(self, fbxapp):
            self.server = fbxapp  # to access Outer's class instance "FbxApp" from System Objet
            self.info = self.getinfo()

        def getinfo(self):
            result = self.server.call('/system')
            Domoticz.Debug(f"Freebox Server Infos: {result}")
            return result

        def sensors(self):
            result = {}
            self.info = self.getinfo()  # Fetch fresh values (instance is long-lived)
            if self.info and self.info.get("sensors"):
                result = self.info["sensors"]
            return result


    class Players:
        """
        Class and method for Freebox TV Player
        """

        def __init__(self, fbxapp):
            self.server = fbxapp  # to access Outer's class instance "FbxApp" from Players
            self.info = self.getinfo()

        def getinfo(self):
            result = self.server.call('/player')
            if result:
                self.server.tv_player = True
                Domoticz.Debug('Player(s) are registered on the local network')
                Domoticz.Debug(f"Player(s) Infos: {result}")
            else:
                self.server.tv_player = False
                Domoticz.Error('Error: You must grant Player Control permission')
            return result

        def ls_uid(self):
            result = []
            players = self.info
            for player in players:
                result.append(player['id'])
                Domoticz.Debug(f"Player(s) Id: {result}")
            return result

        def state(self, uid):
            status = None
            try:
                response = self.server.get(
                    f"/player/{uid}/api/v{TV_API_VER}/status")
            except (urllib.error.HTTPError, urllib.error.URLError) as error:
                # If player is shutdown : Error="Gateway Time-out"
                if getattr(error, 'code', None) == 504:  # error != 'Gateway Time-out'
                    status = False
                else:
                    Domoticz.Error(
                        f"API Error ('/player/{uid}/api/v{TV_API_VER}/status'):  {error}")
            except timeout:
                Domoticz.Error('Timeout')
            else:
                power_state = (response.get('result') or {}).get('power_state')
                if response.get('success') and power_state:
                    status = True if power_state == 'running' else False
            Domoticz.Debug(f"Is watching TV{uid}? : {status}")
            return status

        def remote(self, uid, remote_code, key, long=False):
            url = f"http://hd{uid}.freebox.fr/pub/remote_control?code={remote_code}&key={key}"
            url = url + '&long=true' if long else url
            response = None
            try:
                request = Request(url)
                response = urlopen(request, timeout=API_TMOUT).read()
            except (urllib.error.HTTPError, urllib.error.URLError) as error:
                Domoticz.Error(f"TV Remote error ('{url}'): {error}")
            except timeout:
                Domoticz.Error('Timeout')  # None if Error occurred
            return response

        def shutdown(self, uid, remote_code):
            ## To Do http://hd{uid}.freebox.fr/pub/remote_control?code={remote_code}&key=power
            return self.remote(uid, remote_code, "power")
