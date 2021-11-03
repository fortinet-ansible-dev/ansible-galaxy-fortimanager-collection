# Copyright (c) 2018-2021 Fortinet and/or its affiliates.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
author:
    - Link Zheng (@chillancezen)
    - Luke Weighall (@lweighall)
    - Andrew Welsh (@Ghilli3)
    - Jim Huber (@p4r4n0y1ng)
httpapi : fortimanager
short_description: HttpApi Plugin for Fortinet FortiManager Appliance or VM.
description:
  - This HttpApi plugin provides methods to connect to Fortinet FortiManager Appliance or VM via JSON RPC API.
version_added: "2.8"

"""

import time
import json
import traceback
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.basic import to_text
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import BASE_HEADERS
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGBaseException
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGRCommon
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGRMethods
from datetime import datetime


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)
        self._req_id = 0
        self._sid = None
        self._url = "/jsonrpc"
        self._host = None
        self._tools = FMGRCommon
        self._debug = False
        self._connected_fmgr = None
        self._last_response_msg = None
        self._last_response_code = None
        self._last_data_payload = None
        self._last_url = None
        self._last_response_raw = None
        self._locked_adom_list = list()
        self._locked_adoms_by_user = dict()
        self._uses_workspace = False
        self._uses_adoms = False
        self._adom_list = list()
        self._logged_in_user = None
        self._logged = False
        self._log = None
        self._prelocking_user_params = list()

    def get_forticloud_access_token(self):
        try:
            token = self.connection.get_option('forticloud_access_token')
            return token
        except Exception as e:
            return None

    def log(self, msg):
        log_enabled = self.connection.get_option('enable_log')
        if not log_enabled:
            return
        if not self._log:
            self._log = open("/tmp/fortimanager.ansible.log", "a")
        log_message = str(datetime.now())
        log_message += ": " + str(msg) + '\n'
        self._log.write(log_message)
        self._log.flush()

    def set_become(self, become_context):
        """
        ELEVATION IS NOT REQUIRED ON FORTINET DEVICES - SKIPPED
        :param become_context: Unused input.
        :return: None
        """
        return None

    def update_auth(self, response, response_data):
        """
        TOKENS ARE NOT USED SO NO NEED TO UPDATE AUTH
        :param response: Unused input.
        :param response_data Unused_input.
        :return: None
        """
        return None

    def forticloud_login(self):
        login_data = '{"access_token": "%s"}' % (self.get_forticloud_access_token())
        try:
            response, response_data = self.connection.send(path=to_text('/p/forticloud_jsonrpc_login/'),
                                                           data=to_text(login_data),
                                                           headers=BASE_HEADERS)
            result = json.loads(to_text(response_data.getvalue()))
            self.log('forticloud login response: %s' % (str(self._jsonize(result))))
            return self._set_sid(result)
        except Exception as e:
            raise FMGBaseException(err)

    def login(self, username, password):
        """
        This function will log the plugin into FortiManager, and return the results.
        :param username: Username of FortiManager Admin
        :param password: Password of FortiManager Admin

        :return: Dictionary of status, if it logged in or not.
        """
        self.log("login begin, user: %s" % (username))
        self._logged_in_user = username
        forticloud_access_token = self.get_forticloud_access_token()
        self.log('forticloud access token: %s' % (forticloud_access_token if forticloud_access_token else '(not set)'))
        if not forticloud_access_token:
            self.send_request(FMGRMethods.EXEC, self._tools.format_request(FMGRMethods.EXEC, "sys/login/user",
                                                                           passwd=password, user=username,))
        else:
            self.forticloud_login()

        self.log(self)
        if "FortiManager object connected to FortiManager" in self.__str__():
            # If Login worked, then inspect the FortiManager for Workspace Mode, and it's system information.
            self.inspect_fmgr()
            self._logged = True
            for param in self._prelocking_user_params:
                self.process_workspace_locking_internal(param)
        else:
            raise FMGBaseException(msg="Unknown error while logging in...connection was lost during login operation...."
                                       " Exiting")

    def inspect_fmgr(self):
        # CHECK FOR WORKSPACE MODE TO SEE IF WE HAVE TO ENABLE ADOM LOCKS
        status = self.get_system_status()
        self.log('system status:\n' + json.dumps(status, indent=4))
        if status[0] == -11:
            # THE CONNECTION GOT LOST SOMEHOW, REMOVE THE SID AND REPORT BAD LOGIN
            self.logout()
            raise FMGBaseException(msg="Error -11 -- the Session ID was likely malformed somehow. Contact authors."
                                       " Exiting")
        elif status[0] == 0:
            try:
                self.check_mode()
                if self._uses_adoms:
                    self.get_adom_list()
                if self._uses_workspace:
                    self.get_locked_adom_list()
                self._connected_fmgr = status[1]
                self._host = self._connected_fmgr['data']["Hostname"]
            except Exception as e:
                self.log('inspect_fmgr exception: %s' % (e))
                self.log(traceback.format_exc())

    def logout(self):
        """
        This function will logout of the FortiManager.
        """
        self.log("log out, using workspace:%s user: %s sid: %s" % (
                 self._uses_workspace,
                 self._logged_in_user,
                 self.sid))
        if self.sid:
            # IF WE WERE USING WORKSPACES, THEN CLEAN UP OUR LOCKS IF THEY STILL EXIST
            if self._uses_workspace:
                # self.get_lock_info()
                self.run_unlock()
            ret_code, response = self.send_request(FMGRMethods.EXEC,
                                                   self._tools.format_request(FMGRMethods.EXEC, "sys/logout"))
            self.sid = None
            return ret_code, response

    def send_request(self, method, params):
        """
        Responsible for actual sending of data to the connection httpapi base plugin. Does some formatting as well.
        :param params: A formatted dictionary that was returned by self.common_datagram_params()
        before being called here.
        :param method: The preferred API Request method (GET, ADD, POST, etc....)
        :type method: basestring

        :return: Dictionary of status, if it logged in or not.
        """
        try:
            if self.sid is None and params[0]["url"] != "sys/login/user":
                if not self.connection._connected:
                    self.connection._connect()
        except IndexError:
            raise FMGBaseException("An attempt was made at communicating with a FMG with "
                                   "no valid session and an incorrectly formatted request.")
        except Exception:
            raise FMGBaseException("An attempt was made at communicating with a FMG with "
                                   "no valid session and an unexpected error was discovered.")

        self._update_request_id()
        json_request = {
            "method": method,
            "params": params,
            "session": self.sid,
            "id": self.req_id,
            "verbose": 1
        }
        data = json.dumps(json_request, ensure_ascii=False).replace('\\\\', '\\')
        self.log('request: %s' % (data))
        try:
            # Sending URL and Data in Unicode, per Ansible Specifications for Connection Plugins
            response, response_data = self.connection.send(path=to_text(self._url), data=to_text(data),
                                                           headers=BASE_HEADERS)
            # Get Unicode Response - Must convert from StringIO to unicode first so we can do a replace function below
            result = json.loads(to_text(response_data.getvalue()))
            self.log('response: %s' % (str(self._jsonize(result))))
            self._update_self_from_response(result, self._url, data)
            return self._handle_response(result)
        except Exception as err:
            raise FMGBaseException(err)

    def _jsonize(self, data):
        ret = None
        try:
            ret = json.dumps(data, indent=3)
        except Exception as e:
            pass
        return ret

    def _handle_response(self, response):
        self._set_sid(response)
        if isinstance(response["result"], list):
            result = response["result"][0]
        else:
            result = response["result"]
        return result["status"]["code"], result

    def _update_self_from_response(self, response, url, data):
        self._last_response_raw = response
        if isinstance(response["result"], list):
            result = response["result"][0]
        else:
            result = response["result"]
        if "status" in result:
            self._last_response_code = result["status"]["code"]
            self._last_response_msg = result["status"]["message"]
            self._last_url = url
            self._last_data_payload = data

    def _set_sid(self, response):
        if self.sid is None and "session" in response:
            self.sid = response["session"]

    def return_connected_fmgr(self):
        """
        Returns the data stored under self._connected_fmgr

        :return: dict
        """
        try:
            if self._connected_fmgr:
                return self._connected_fmgr
        except Exception:
            raise FMGBaseException("Couldn't Retrieve Connected FMGR Stats")

    def get_system_status(self):
        """
        Returns the system status page from the FortiManager, for logging and other uses.
        return: status
        """
        status = self.send_request(FMGRMethods.GET, self._tools.format_request(FMGRMethods.GET, "sys/status"))
        return status

    def process_workspace_locking_internal(self, param):
        if not self._uses_workspace or not self.sid:
            return
        if 'workspace_locking_adom' not in param or not param['workspace_locking_adom']:
            # The FortiManager is running in workspace mode, please `workspace_locking_adom` in your playbook
            # FIXME:by default, users have to know whether their fmg devices are running in worksapce mode and
            # specify the paramters in plaubook, we will find a better way to notify the users of this error
            return
        adom_to_lock = param['workspace_locking_adom']
        adom_to_lock_timeout = param['workspace_locking_timeout']
        self.log('trying to acquire lock for adom: %s within %s seconds by user: %s' % (
                 adom_to_lock,
                 adom_to_lock_timeout,
                 self._logged_in_user))
        if adom_to_lock in self._locked_adoms_by_user and self._locked_adoms_by_user[adom_to_lock] == self._logged_in_user:
            # XXX: here is a situation where user can still has no permission to access resources:
            # indeed the worksapce lock is acquired by the user himself, but the lock is not
            # associated with this session.
            self.log('adom: %s has already been acquired by user: %s' % (adom_to_lock, self._logged_in_user))
        elif adom_to_lock in self._locked_adoms_by_user and self._locked_adoms_by_user[adom_to_lock] != self._logged_in_user:
            total_wait_time = 0
            while total_wait_time < adom_to_lock_timeout:
                code, dummy = self.lock_adom(adom_to_lock)
                self.log("waiting adom:%s lock to be released by %s, total time spent:%s seconds status:%s" % (
                         adom_to_lock,
                         self._locked_adoms_by_user[adom_to_lock],
                         total_wait_time,
                         "success" if code == 0 else "failure"))
                if code == 0:
                    self._locked_adoms_by_user[adom_to_lock] = self._logged_in_user
                    break
                time.sleep(5)
                total_wait_time += 5
        else:
            code, dummy = self.lock_adom(adom_to_lock)
            self.log('adom:%s locked by user: %s status:%s' % (adom_to_lock, self._logged_in_user, "success" if code == 0 else "failure"))
            if code == 0:
                self._locked_adoms_by_user[adom_to_lock] = self._logged_in_user

    def process_workspace_locking(self, param):
        # XXX:defer the lock acquisition process after login is done
        # it requires that the first task specify the workspace locking adom
        # if it's really executed in lock context
        if not self._logged:
            self._prelocking_user_params.append(param)
        else:
            self.process_workspace_locking_internal(param)

    @property
    def debug(self):
        return self._debug

    @debug.setter
    def debug(self, val):
        self._debug = val

    @property
    def req_id(self):
        return self._req_id

    @req_id.setter
    def req_id(self, val):
        self._req_id = val

    def _update_request_id(self, reqid=0):
        self.req_id = reqid if reqid != 0 else self.req_id + 1

    @property
    def sid(self):
        return self._sid

    @sid.setter
    def sid(self, val):
        self._sid = val

    def __str__(self):
        if self.sid is not None and self.connection._url is not None:
            return "FortiManager object connected to FortiManager: " + to_text(self.connection._url)
        return "FortiManager object with no valid connection to a FortiManager appliance."

    ##################################
    # BEGIN DATABASE LOCK CONTEXT CODE
    ##################################

    @property
    def uses_workspace(self):
        return self._uses_workspace

    @uses_workspace.setter
    def uses_workspace(self, val):
        self._uses_workspace = val

    @property
    def uses_adoms(self):
        return self._uses_adoms

    @uses_adoms.setter
    def uses_adoms(self, val):
        self._uses_adoms = val

    def add_adom_to_lock_list(self, adom):
        if adom not in self._locked_adom_list:
            self._locked_adom_list.append(adom)

    def remove_adom_from_lock_list(self, adom):
        if adom in self._locked_adom_list:
            self._locked_adom_list.remove(adom)

    def check_mode(self):
        """
        Checks FortiManager for the use of Workspace mode
        """
        url = "/cli/global/system/global"
        code, resp_obj = self.send_request(FMGRMethods.GET, self._tools.format_request(FMGRMethods.GET, url,
                                                                                       fields=["workspace-mode",
                                                                                               "adom-status"]))
        try:
            if resp_obj['data']["workspace-mode"] in ["workflow", "normal"]:
                self._uses_workspace = True
            else:
                self._uses_workspace = False
        except KeyError:
            raise FMGBaseException(msg="Couldn't determine workspace-mode in the plugin")
        try:
            if resp_obj['data']["adom-status"] in [1, 'enable']:
                self._uses_adoms = True
            else:
                self._uses_adoms = False
        except KeyError:
            raise FMGBaseException(msg="Couldn't determine adom-status in the plugin")
        self.log("workspace-mode: %s adom-status: %s" % (self._uses_workspace, self._uses_adoms))

    def run_unlock(self):
        """
        Checks for ADOM status, if locked, it will unlock
        """
        for adom_locked in self._locked_adoms_by_user:
            locked_user = self._locked_adoms_by_user[adom_locked]
            if locked_user == self._logged_in_user:
                self.commit_changes(adom_locked)
                self.unlock_adom(adom_locked)
                self.log('unlock adom: %s with session_id:%s' % (adom_locked, self.sid))

    def lock_adom(self, adom=None, *args, **kwargs):
        """
        Locks an ADOM for changes
        """
        if adom:
            if adom.lower() == "global":
                url = "/dvmdb/global/workspace/lock/"
            else:
                url = "/dvmdb/adom/{adom}/workspace/lock/".format(adom=adom)
        else:
            url = "/dvmdb/adom/root/workspace/lock"
        code, respobj = self.send_request(FMGRMethods.EXEC, self._tools.format_request(FMGRMethods.EXEC, url))
        if code == 0 and respobj["status"]["message"].lower() == "ok":
            self.add_adom_to_lock_list(adom)
        return code, respobj

    def unlock_adom(self, adom=None, *args, **kwargs):
        """
        Unlocks an ADOM after changes
        """
        if adom:
            if adom.lower() == "global":
                url = "/dvmdb/global/workspace/unlock/"
            else:
                url = "/dvmdb/adom/{adom}/workspace/unlock/".format(adom=adom)
        else:
            url = "/dvmdb/adom/root/workspace/unlock"
        code, respobj = self.send_request(FMGRMethods.EXEC, self._tools.format_request(FMGRMethods.EXEC, url))
        if code == 0 and respobj["status"]["message"].lower() == "ok":
            self.remove_adom_from_lock_list(adom)
        return code, respobj

    def commit_changes(self, adom=None, aux=False, *args, **kwargs):
        """
        Commits changes to an ADOM
        """
        if adom:
            if aux:
                url = "/pm/config/adom/{adom}/workspace/commit".format(adom=adom)
            else:
                if adom.lower() == "global":
                    url = "/dvmdb/global/workspace/commit/"
                else:
                    url = "/dvmdb/adom/{adom}/workspace/commit".format(adom=adom)
        else:
            url = "/dvmdb/adom/root/workspace/commit"
        return self.send_request(FMGRMethods.EXEC, self._tools.format_request(FMGRMethods.EXEC, url))

    def get_lock_info(self, adom=None):
        """
        Gets ADOM lock info so it can be displayed with the error messages. Or if determined to be locked by ansible
        for some reason, then unlock it.
        """
        if not adom or adom == "root":
            url = "/dvmdb/adom/root/workspace/lockinfo"
        else:
            if adom.lower() == "global":
                url = "/dvmdb/global/workspace/lockinfo/"
            else:
                url = "/dvmdb/adom/{adom}/workspace/lockinfo/".format(adom=adom)
        datagram = {}
        data = self._tools.format_request(FMGRMethods.GET, url, **datagram)
        resp_obj = self.send_request(FMGRMethods.GET, data)
        code = resp_obj[0]
        if code != 0:
            self._module.fail_json(msg=("An error occurred trying to get the ADOM Lock Info. "
                                        "Error: " + to_text(resp_obj)))
        elif code == 0:
            try:
                if resp_obj[1]["status"]["message"] == "OK":
                    self._lock_info = None
            except Exception:
                self._lock_info = resp_obj[1]
        return resp_obj

    def get_adom_list(self):
        """
        Gets the list of ADOMs for the FortiManager
        """
        if self._uses_adoms:
            url = "/dvmdb/adom"
            datagram = {}
            data = self._tools.format_request(FMGRMethods.GET, url, **datagram)
            resp_obj = self.send_request(FMGRMethods.GET, data)
            code = resp_obj[0]
            if code != 0:
                self._module.fail_json(msg=("An error occurred trying to get the ADOM Info. "
                                            "Error: " + to_text(resp_obj)))
            elif code == 0:
                num_of_adoms = len(resp_obj[1]['data'])
                append_list = ['root', 'global']
                for adom in resp_obj[1]['data']:
                    if adom["tab_status"] != "":
                        append_list.append(to_text(adom["name"]))
                self._adom_list = append_list
            self.log('adom list: %s' % (str(self._adom_list)))
            return resp_obj

    def get_locked_adom_list(self):
        """
        Gets the list of locked adoms
        """
        try:
            locked_list = list()
            locked_by_user_list = dict()
            for adom in self._adom_list:
                adom_lock_info = self.get_lock_info(adom=adom)
                self.log('lockinfo for adom:%s' % (adom))
                self.log(json.dumps(adom_lock_info, indent=4))
                if adom_lock_info[1]['status']['code'] != 0:
                    continue
                # if 'data' is not in the response, the adom is locked by no one
                if 'data' not in adom_lock_info[1]:
                    continue
                locked_list.append(to_text(adom))
                locked_by_user_list[to_text(adom)] = to_text(adom_lock_info[1]['data'][0]['lock_user'])

            self._locked_adom_list = locked_list
            self._locked_adoms_by_user = locked_by_user_list
            self.log('locked adom list: %s' % (self._locked_adom_list))
            self.log('locked adom and user list: %s' % (self._locked_adoms_by_user))

        except Exception as err:
            raise FMGBaseException(msg=("An error occurred while trying to get the locked adom list. Error: "
                                        + to_text(err)))

    ################################
    # END DATABASE LOCK CONTEXT CODE
    ################################
