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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
name: fortimanager
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Link Zheng (@chillancezen)
    - Luke Weighall (@lweighall)
    - Andrew Welsh (@Ghilli3)
    - Jim Huber (@p4r4n0y1ng)
short_description: HttpApi Plugin for Fortinet FortiManager Appliance or VM.
description:
  - This HttpApi plugin provides methods to connect to Fortinet FortiManager Appliance or VM via JSON RPC API.
version_added: "1.0.0"

"""

import time
import json
import os
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.common.text.converters import to_text
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGBaseException
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGRCommon
from datetime import datetime

ENABLE_LOG = os.getenv("ANSIBLE_FORTIMANAGER_ENABLE_LOG", "false").lower() in ["true", "1", "yes", "y", "t"]


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)
        self._req_id = 0
        self._sid = None
        self._url = "/jsonrpc"
        self._tools = FMGRCommon
        self._adoms_locked_by_user = []
        self._uses_workspace = False
        self._uses_adoms = False
        self._inspected_fmgr = False
        self._log_file = None
        self._login_method = None
        self._status = {}
        self._customer_options = {}

    def set_customer_option(self, key, value):
        self._customer_options[key] = value

    def get_customer_option(self, key, default=None):
        return self._customer_options.get(key, default)

    def log(self, msg):
        if not (self.get_customer_option("enable_log", False) or ENABLE_LOG):
            return
        if not self._log_file:
            self._log_file = open("/tmp/fortimanager.ansible.log", "a")
        log_message = to_text(datetime.now())
        log_message += ": " + to_text(msg) + "\n"
        self._log_file.write(log_message)
        self._log_file.flush()

    def log_request(self, json_request):
        if not (self.get_customer_option("enable_log", False) or ENABLE_LOG):
            return
        params = json_request["params"]
        # Don't log sensitive information
        if params[0]["url"] == "sys/login/user" and "data" in params[0] and "passwd" in params[0]["data"]:
            params[0]["data"]["passwd"] = "******"
        if "session" in params[0]:
            params[0]["session"] = "******"
        log_data = json.dumps(json_request, ensure_ascii=False)
        self.log("request: %s" % (log_data))

    def log_response(self, response):
        if not (self.get_customer_option("enable_log", False) or ENABLE_LOG):
            return
        log_data = self._jsonize(response)
        if log_data:
            self.log("response: %s" % (log_data))
        else:
            self.log("response: %s" % (to_text(response)))

    def set_become(self, become_context):
        """
        ELEVATION IS NOT REQUIRED ON FORTINET DEVICES - SKIPPED
        :param become_context: Unused input.
        :return: None
        """
        return None

    def update_auth(self, response, response_text):
        """
        TOKENS ARE NOT USED SO NO NEED TO UPDATE AUTH
        :param response: Unused input.
        :param response_data Unused_input.
        :return: None
        """
        return None

    def forticloud_login(self):
        login_data = '{"access_token": "%s"}' % (self.get_customer_option("forticloud_access_token", None))
        try:
            response, response_data = self.connection.send(
                path="/p/forticloud_jsonrpc_login/",
                data=login_data,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            result = json.loads(to_text(response_data.getvalue()))
            self.log("forticloud login response: %s" % (self._jsonize(result)))
            return self._set_sid(result)
        except Exception as e:
            raise FMGBaseException(e)

    def login(self, username, password):
        """
        This function will log the plugin into FortiManager, and return the results.
        :param username: Username of FortiManager Admin
        :param password: Password of FortiManager Admin

        :return: Dictionary of status, if it logged in or not.
        """
        self.log("login begin, user: %s" % (username))
        forticloud_access_token = self.get_customer_option("forticloud_access_token", None)
        access_token = self.get_customer_option("access_token", None)
        if username is not None and password is not None:
            self._login_method = "username_password"
            json_request = {
                "method": "exec",
                "params": [{"url": "sys/login/user", "data": {"passwd": to_text(password), "user": to_text(username)}}],
                "session": self._sid,
                "id": self._update_request_id(),
                "verbose": 1,
            }
            data = json.dumps(json_request, ensure_ascii=False)
            self.log_request(json_request)
            header_data = {"Content-Type": "application/json", "Accept": "application/json"}
            response, response_data = self.connection.send(
                path=self._url, data=data, headers=header_data
            )
            response_text = to_text(response_data.getvalue())
            result = ""
            try:
                result = json.loads(response_text)
            except Exception as e:
                raise FMGBaseException(msg="Got unexpected result: %s" % (response_text))
            self.log_response(result)
            self._set_sid(result)
            self._handle_response(result)
        elif access_token:
            self._login_method = "access_token"
            self.connection._auth = {'Authorization': f'Bearer {access_token}'}
        elif forticloud_access_token:
            self._login_method = "forticloud"
            self.forticloud_login()
        else:
            err_msg = "Please check whether you provide the correct information."
            raise AssertionError(err_msg)
        self.log("login method: " + self._login_method)
        if (not self._sid and not access_token) or self.connection._url is None:
            err_msg = "Can't login. Your login method is %s. " % (self._login_method)
            err_msg += "Please check whether you provide the correct information or have necessary permissions."
            raise FMGBaseException(msg=err_msg)

    def inspect_fmgr(self):
        self._inspected_fmgr = True
        # CHECK FOR WORKSPACE MODE TO SEE IF WE HAVE TO ENABLE ADOM LOCKS
        rc, status = self.get_system_status()
        if rc == -11:
            # THE CONNECTION GOT LOST SOMEHOW, REMOVE THE SID AND REPORT BAD LOGIN
            self.logout()
            raise FMGBaseException(msg="Error -11 -- Failed to get the FMG system status. Exiting")
        elif rc == 0:
            try:
                self.check_mode()
            except Exception as e:
                self.log("inspect_fmgr exception: %s" % (e))

    def logout(self):
        """
        This function will logout of the FortiManager.
        """
        self.log(
            "log out, using workspace:%s sid: %s"
            % (self._uses_workspace, self._sid)
        )
        # IF WE WERE USING WORKSPACES, THEN CLEAN UP OUR LOCKS IF THEY STILL EXIST
        if self._uses_workspace:
            self.run_unlock()
        if self._sid:
            rc, response = self.send_request("exec", self._tools.format_request("exec", "sys/logout"))
            self._sid = None
            return rc, response

    def send_request(self, method, params):
        """
        Responsible for actual sending of data to the connection httpapi base plugin. Does some formatting as well.
        :param params: A formatted dictionary that was returned by self.common_datagram_params()
        before being called here.
        :param method: The preferred API Request method (GET, ADD, POST, etc....)
        :type method: basestring

        :return: Dictionary of status, if it logged in or not.
        """
        # Must do a connection check here to get _sid before sending request
        if not self.connection._connected:
            self.connection._connect()
        if not self._inspected_fmgr:
            self.inspect_fmgr()
        json_request = {
            "method": method,
            "params": params,
            "session": self._sid,
            "id": self._update_request_id(),
            "verbose": 1,
        }
        data = json.dumps(json_request, ensure_ascii=False)

        header_data = {"Content-Type": "application/json", "Accept": "application/json"}
        response, response_data = self.connection.send(
            path=self._url, data=data, headers=header_data
        )
        self.log_request(json_request)
        response_text = to_text(response_data.getvalue())
        result = ""
        try:
            result = json.loads(response_text)
        except Exception as e:
            raise FMGBaseException(msg="Got unexpected result: %s" % (response_text))
        self.log_response(result)
        return self._handle_response(result)

    def _jsonize(self, data):
        ret = None
        try:
            ret = json.dumps(data, indent=2)
        except Exception as e:
            pass
        return ret

    def _handle_response(self, response):
        if isinstance(response["result"], list):
            result = response["result"][0]
        else:
            result = response["result"]
        return result["status"]["code"], result

    def _set_sid(self, response):
        if self._sid is None and "session" in response:
            self._sid = response["session"]

    def get_system_status(self):
        """
        Returns the system status page from the FortiManager, for logging and other uses.
        return: status
        """
        if self._status:
            return 0, self._status
        rc, self._status = self.send_request("get", self._tools.format_request("get", "/sys/status"))
        if rc == -11:
            rc, self._status = self.send_request("get", self._tools.format_request("get", "/cli/global/system/status"))
        return rc, self._status

    def process_workspace_locking(self, param):
        if not self._inspected_fmgr:
            self.inspect_fmgr()
        if not self._uses_workspace:
            return
        if "workspace_locking_adom" not in param or not param["workspace_locking_adom"]:
            # The FortiManager is running in workspace mode, please specify `workspace_locking_adom` in your playbook
            # FIXME:by default, users have to know whether their fmg devices are running in worksapce mode and
            # specify the paramters in playbook, we will find a better way to notify the users of this error
            return
        adom_to_lock = param["workspace_locking_adom"]
        if adom_to_lock in self._adoms_locked_by_user:
            self.log("adom: %s has already been acquired by the user" % (adom_to_lock))
            return
        total_wait_time = 0
        while total_wait_time < param["workspace_locking_timeout"]:
            code, resp_obj = self.lock_adom(adom_to_lock)
            if code == 0:
                self.log("adom:%s locked status: success" % (adom_to_lock))
                self._adoms_locked_by_user.append(adom_to_lock)
                return
            self.log(
                "waiting adom:%s lock to be released by other user, total time spent:%s seconds status:%s"
                % (adom_to_lock, total_wait_time, "success" if code == 0 else "failure")
            )
            time.sleep(5)
            total_wait_time += 5

    def _update_request_id(self, reqid=0):
        self._req_id = reqid if reqid != 0 else self._req_id + 1
        return self._req_id

    def __str__(self):
        if self.connection._url is not None:
            return "FortiManager object connected to FortiManager: " + self.connection._url
        return "FortiManager object with no valid connection to a FortiManager appliance."

    ##################################
    # BEGIN DATABASE LOCK CONTEXT CODE
    ##################################

    def check_mode(self):
        """
        Checks FortiManager for the use of Workspace mode
        """
        url = "/cli/global/system/global"
        rc, resp_obj = self.send_request("get", self._tools.format_request("get", url, fields=["workspace-mode", "adom-status"]))
        # Skip this step if user is not permitted to access this resource
        if rc == -11:
            self.log("Skip workspace-mode check due to no permission to access /cli/global/system/global")
        if "data" in resp_obj and isinstance(resp_obj["data"], dict):
            if resp_obj["data"].get("adom-status", "") in [1, "enable"]:
                self._uses_adoms = True
            if resp_obj["data"].get("workspace-mode", "") in ["workflow", "normal", "per-adom"]:
                self._uses_workspace = True
        self.log("workspace-mode: %s adom-status: %s" % (self._uses_workspace, self._uses_adoms))

    def run_unlock(self):
        """
        Checks for ADOM status, if locked, it will unlock
        """
        for adom_locked in self._adoms_locked_by_user:
            self.commit_changes(adom_locked)
            self.unlock_adom(adom_locked)
            self.log("unlock adom: %s with session_id:%s" % (adom_locked, self._sid))

    def lock_adom(self, adom=None):
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
        code, respobj = self.send_request("exec", self._tools.format_request("exec", url))
        if code == 0 and respobj["status"]["message"].lower() == "ok":
            pass
        return code, respobj

    def unlock_adom(self, adom=None):
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
        code, respobj = self.send_request("exec", self._tools.format_request("exec", url))
        if code == 0 and respobj["status"]["message"].lower() == "ok":
            pass
        return code, respobj

    def commit_changes(self, adom=None, aux=False):
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
        return self.send_request("exec", self._tools.format_request("exec", url))

    def get_lock_info(self, adom=None):
        """
        Gets ADOM lock info so it can be displayed with the error messages. Or if determined to be locked by ansible
        for some reason, then unlock it.
        """
        url = "/dvmdb/adom/root/workspace/lockinfo"
        if adom:
            if adom.lower() == "global":
                url = "/dvmdb/global/workspace/lockinfo"
            else:
                url = "/dvmdb/adom/{adom}/workspace/lockinfo".format(adom=adom)
        rc, resp_obj = self.send_request("get", self._tools.format_request("get", url))
        # rc=-9: current adom is not in the workspace mode.
        return rc, resp_obj

    def get_adom_lock_user(self, adom):
        self.log("lockinfo for adom:%s" % (adom))
        rc, adom_lock_info = self.get_lock_info(adom=adom)
        if adom_lock_info["status"]["code"] != 0:
            return None
        # if "data" is not in the response, the adom is locked by no one
        if "data" not in adom_lock_info:
            return None
        lock_data = adom_lock_info["data"]
        if isinstance(lock_data, list):
            lock_data = lock_data[0]
        return lock_data["lock_user"]

    ################################
    # END DATABASE LOCK CONTEXT CODE
    ################################
