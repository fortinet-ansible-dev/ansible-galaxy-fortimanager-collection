#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2021 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_system_replacemsggroup
short_description: Configure replacement message groups.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    system_replacemsggroup:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            admin:
                description: 'Admin.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            alertmail:
                description: 'Alertmail.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            auth:
                description: 'Auth.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            comment:
                type: str
                description: 'Comment.'
            custom-message:
                description: 'Custom-Message.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            device-detection-portal:
                description: 'Device-Detection-Portal.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            ec:
                description: no description
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            fortiguard-wf:
                description: 'Fortiguard-Wf.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            ftp:
                description: 'Ftp.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            group-type:
                type: str
                description: 'Group type.'
                choices:
                    - 'default'
                    - 'utm'
                    - 'auth'
                    - 'ec'
                    - 'captive-portal'
            http:
                description: 'Http.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            icap:
                description: 'Icap.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            mail:
                description: 'Mail.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            mm1:
                description: 'Mm1.'
                type: list
                suboptions:
                    add-smil:
                        type: str
                        description: 'add message encapsulation'
                        choices:
                            - 'disable'
                            - 'enable'
                    charset:
                        type: str
                        description: 'character encoding used for replacement message'
                        choices:
                            - 'us-ascii'
                            - 'utf-8'
                    class:
                        type: str
                        description: 'message class'
                        choices:
                            - 'personal'
                            - 'advertisement'
                            - 'information'
                            - 'automatic'
                            - 'not-included'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    from:
                        type: str
                        description: 'from address'
                    from-sender:
                        type: str
                        description: 'notification message sent from recipient'
                        choices:
                            - 'disable'
                            - 'enable'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    image:
                        type: str
                        description: 'Message string.'
                    message:
                        type: str
                        description: 'message text'
                    msg-type:
                        type: str
                        description: 'Message type.'
                    priority:
                        type: str
                        description: 'message priority'
                        choices:
                            - 'low'
                            - 'normal'
                            - 'high'
                            - 'not-included'
                    rsp-status:
                        type: str
                        description: 'response status code'
                        choices:
                            - 'ok'
                            - 'err-unspecified'
                            - 'err-srv-denied'
                            - 'err-msg-fmt-corrupt'
                            - 'err-snd-addr-unresolv'
                            - 'err-msg-not-found'
                            - 'err-net-prob'
                            - 'err-content-not-accept'
                            - 'err-unsupp-msg'
                    rsp-text:
                        type: str
                        description: 'response text'
                    sender-visibility:
                        type: str
                        description: 'sender visibility'
                        choices:
                            - 'hide'
                            - 'show'
                            - 'not-specified'
                    smil-part:
                        type: str
                        description: 'message encapsulation text'
                    subject:
                        type: str
                        description: 'subject text string'
            mm3:
                description: 'Mm3.'
                type: list
                suboptions:
                    add-html:
                        type: str
                        description: 'add message encapsulation'
                        choices:
                            - 'disable'
                            - 'enable'
                    charset:
                        type: str
                        description: 'character encoding used for replacement message'
                        choices:
                            - 'us-ascii'
                            - 'utf-8'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    from:
                        type: str
                        description: 'from address'
                    from-sender:
                        type: str
                        description: 'notification message sent from recipient'
                        choices:
                            - 'disable'
                            - 'enable'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    html-part:
                        type: str
                        description: 'message encapsulation text'
                    image:
                        type: str
                        description: 'Message string.'
                    message:
                        type: str
                        description: 'message text'
                    msg-type:
                        type: str
                        description: 'Message type.'
                    priority:
                        type: str
                        description: 'message priority'
                        choices:
                            - 'low'
                            - 'normal'
                            - 'high'
                            - 'not-included'
                    subject:
                        type: str
                        description: 'subject text string'
            mm4:
                description: 'Mm4.'
                type: list
                suboptions:
                    add-smil:
                        type: str
                        description: 'add message encapsulation'
                        choices:
                            - 'disable'
                            - 'enable'
                    charset:
                        type: str
                        description: 'character encoding used for replacement message'
                        choices:
                            - 'us-ascii'
                            - 'utf-8'
                    class:
                        type: str
                        description: 'message class'
                        choices:
                            - 'personal'
                            - 'advertisement'
                            - 'informational'
                            - 'auto'
                            - 'not-included'
                    domain:
                        type: str
                        description: 'from address domain'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    from:
                        type: str
                        description: 'from address'
                    from-sender:
                        type: str
                        description: 'notification message sent from recipient'
                        choices:
                            - 'disable'
                            - 'enable'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    image:
                        type: str
                        description: 'Message string.'
                    message:
                        type: str
                        description: 'message text'
                    msg-type:
                        type: str
                        description: 'Message type.'
                    priority:
                        type: str
                        description: 'message priority'
                        choices:
                            - 'low'
                            - 'normal'
                            - 'high'
                            - 'not-included'
                    rsp-status:
                        type: str
                        description: 'response status'
                        choices:
                            - 'ok'
                            - 'err-unspecified'
                            - 'err-srv-denied'
                            - 'err-msg-fmt-corrupt'
                            - 'err-snd-addr-unresolv'
                            - 'err-net-prob'
                            - 'err-content-not-accept'
                            - 'err-unsupp-msg'
                    smil-part:
                        type: str
                        description: 'message encapsulation text'
                    subject:
                        type: str
                        description: 'subject text string'
            mm7:
                description: 'Mm7.'
                type: list
                suboptions:
                    add-smil:
                        type: str
                        description: 'add message encapsulation'
                        choices:
                            - 'disable'
                            - 'enable'
                    addr-type:
                        type: str
                        description: 'from address type'
                        choices:
                            - 'rfc2822-addr'
                            - 'number'
                            - 'short-code'
                    allow-content-adaptation:
                        type: str
                        description: 'allow content adaptations'
                        choices:
                            - 'disable'
                            - 'enable'
                    charset:
                        type: str
                        description: 'character encoding used for replacement message'
                        choices:
                            - 'us-ascii'
                            - 'utf-8'
                    class:
                        type: str
                        description: 'message class'
                        choices:
                            - 'personal'
                            - 'advertisement'
                            - 'informational'
                            - 'auto'
                            - 'not-included'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    from:
                        type: str
                        description: 'from address'
                    from-sender:
                        type: str
                        description: 'notification message sent from recipient'
                        choices:
                            - 'disable'
                            - 'enable'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    image:
                        type: str
                        description: 'Message string.'
                    message:
                        type: str
                        description: 'message text'
                    msg-type:
                        type: str
                        description: 'Message type.'
                    priority:
                        type: str
                        description: 'message priority'
                        choices:
                            - 'low'
                            - 'normal'
                            - 'high'
                            - 'not-included'
                    rsp-status:
                        type: str
                        description: 'response status'
                        choices:
                            - 'success'
                            - 'partial-success'
                            - 'client-err'
                            - 'oper-restrict'
                            - 'addr-err'
                            - 'addr-not-found'
                            - 'content-refused'
                            - 'msg-id-not-found'
                            - 'link-id-not-found'
                            - 'msg-fmt-corrupt'
                            - 'app-id-not-found'
                            - 'repl-app-id-not-found'
                            - 'srv-err'
                            - 'not-possible'
                            - 'msg-rejected'
                            - 'multiple-addr-not-supp'
                            - 'app-addr-not-supp'
                            - 'gen-service-err'
                            - 'improper-ident'
                            - 'unsupp-ver'
                            - 'unsupp-oper'
                            - 'validation-err'
                            - 'service-err'
                            - 'service-unavail'
                            - 'service-denied'
                            - 'app-denied'
                    smil-part:
                        type: str
                        description: 'message encapsulation text'
                    subject:
                        type: str
                        description: 'subject text string'
            mms:
                description: 'Mms.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    charset:
                        type: str
                        description: 'character encoding used for replacement message'
                        choices:
                            - 'us-ascii'
                            - 'utf-8'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    image:
                        type: str
                        description: 'Message string.'
                    msg-type:
                        type: str
                        description: 'Message type.'
            nac-quar:
                description: 'Nac-Quar.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            name:
                type: str
                description: 'Group name.'
            nntp:
                description: 'Nntp.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            spam:
                description: 'Spam.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            sslvpn:
                description: 'Sslvpn.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            traffic-quota:
                description: 'Traffic-Quota.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            utm:
                description: 'Utm.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            webproxy:
                description: 'Webproxy.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                            - 'wml'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'
            automation:
                description: 'Automation.'
                type: list
                suboptions:
                    buffer:
                        type: str
                        description: 'Message string.'
                    format:
                        type: str
                        description: 'Format flag.'
                        choices:
                            - 'none'
                            - 'text'
                            - 'html'
                    header:
                        type: str
                        description: 'Header flag.'
                        choices:
                            - 'none'
                            - 'http'
                            - '8bit'
                    msg-type:
                        type: str
                        description: 'Message type.'

'''

EXAMPLES = '''
 - hosts: fortimanager00
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Configure replacement message groups.
      fmgr_system_replacemsggroup:
         bypass_validation: False
         adom: ansible
         state: present
         system_replacemsggroup:
            comment: ansible-comment
            name: ansible-test

 - name: gathering fortimanager facts
   hosts: fortimanager00
   gather_facts: no
   connection: httpapi
   collections:
     - fortinet.fortimanager
   vars:
     ansible_httpapi_use_ssl: True
     ansible_httpapi_validate_certs: False
     ansible_httpapi_port: 443
   tasks:
    - name: retrieve all the replacement message groups
      fmgr_fact:
        facts:
            selector: 'system_replacemsggroup'
            params:
                adom: 'ansible'
                replacemsg-group: ''
'''

RETURN = '''
request_url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
response_code:
    description: The status of api request
    returned: always
    type: int
    sample: 0
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/system/replacemsg-group',
        '/pm/config/global/obj/system/replacemsg-group'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}',
        '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'system_replacemsggroup': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True
            },
            'options': {
                'admin': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'alertmail': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'auth': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'comment': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'custom-message': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'device-detection-portal': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': False
                            },
                            'type': 'str'
                        }
                    }
                },
                'ec': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': False,
                                '6.2.3': False,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': False,
                                '6.2.3': False,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': False,
                                '6.2.3': False,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': False,
                                '6.2.3': False,
                                '6.2.5': False,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        }
                    }
                },
                'fortiguard-wf': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'ftp': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'group-type': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'default',
                        'utm',
                        'auth',
                        'ec',
                        'captive-portal'
                    ],
                    'type': 'str'
                },
                'http': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'icap': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'mail': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'mm1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'options': {
                        'add-smil': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'charset': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'us-ascii',
                                'utf-8'
                            ],
                            'type': 'str'
                        },
                        'class': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'personal',
                                'advertisement',
                                'information',
                                'automatic',
                                'not-included'
                            ],
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'from': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'from-sender': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'image': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'message': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'priority': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'low',
                                'normal',
                                'high',
                                'not-included'
                            ],
                            'type': 'str'
                        },
                        'rsp-status': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'ok',
                                'err-unspecified',
                                'err-srv-denied',
                                'err-msg-fmt-corrupt',
                                'err-snd-addr-unresolv',
                                'err-msg-not-found',
                                'err-net-prob',
                                'err-content-not-accept',
                                'err-unsupp-msg'
                            ],
                            'type': 'str'
                        },
                        'rsp-text': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'sender-visibility': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'hide',
                                'show',
                                'not-specified'
                            ],
                            'type': 'str'
                        },
                        'smil-part': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'subject': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        }
                    }
                },
                'mm3': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'options': {
                        'add-html': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'charset': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'us-ascii',
                                'utf-8'
                            ],
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'from': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'from-sender': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'html-part': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'image': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'message': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'priority': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'low',
                                'normal',
                                'high',
                                'not-included'
                            ],
                            'type': 'str'
                        },
                        'subject': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        }
                    }
                },
                'mm4': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'options': {
                        'add-smil': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'charset': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'us-ascii',
                                'utf-8'
                            ],
                            'type': 'str'
                        },
                        'class': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'personal',
                                'advertisement',
                                'informational',
                                'auto',
                                'not-included'
                            ],
                            'type': 'str'
                        },
                        'domain': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'from': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'from-sender': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'image': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'message': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'priority': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'low',
                                'normal',
                                'high',
                                'not-included'
                            ],
                            'type': 'str'
                        },
                        'rsp-status': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'ok',
                                'err-unspecified',
                                'err-srv-denied',
                                'err-msg-fmt-corrupt',
                                'err-snd-addr-unresolv',
                                'err-net-prob',
                                'err-content-not-accept',
                                'err-unsupp-msg'
                            ],
                            'type': 'str'
                        },
                        'smil-part': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'subject': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        }
                    }
                },
                'mm7': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'options': {
                        'add-smil': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'addr-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'rfc2822-addr',
                                'number',
                                'short-code'
                            ],
                            'type': 'str'
                        },
                        'allow-content-adaptation': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'charset': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'us-ascii',
                                'utf-8'
                            ],
                            'type': 'str'
                        },
                        'class': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'personal',
                                'advertisement',
                                'informational',
                                'auto',
                                'not-included'
                            ],
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'from': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'from-sender': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'image': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'message': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'priority': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'low',
                                'normal',
                                'high',
                                'not-included'
                            ],
                            'type': 'str'
                        },
                        'rsp-status': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'success',
                                'partial-success',
                                'client-err',
                                'oper-restrict',
                                'addr-err',
                                'addr-not-found',
                                'content-refused',
                                'msg-id-not-found',
                                'link-id-not-found',
                                'msg-fmt-corrupt',
                                'app-id-not-found',
                                'repl-app-id-not-found',
                                'srv-err',
                                'not-possible',
                                'msg-rejected',
                                'multiple-addr-not-supp',
                                'app-addr-not-supp',
                                'gen-service-err',
                                'improper-ident',
                                'unsupp-ver',
                                'unsupp-oper',
                                'validation-err',
                                'service-err',
                                'service-unavail',
                                'service-denied',
                                'app-denied'
                            ],
                            'type': 'str'
                        },
                        'smil-part': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'subject': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        }
                    }
                },
                'mms': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'charset': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'us-ascii',
                                'utf-8'
                            ],
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'image': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        }
                    }
                },
                'nac-quar': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'nntp': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': False
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': False
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': False
                            },
                            'type': 'str'
                        }
                    }
                },
                'spam': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'sslvpn': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'traffic-quota': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'utm': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'webproxy': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html',
                                'wml'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'automation': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'buffer': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'format': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'text',
                                'html'
                            ],
                            'type': 'str'
                        },
                        'header': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'http',
                                '8bit'
                            ],
                            'type': 'str'
                        },
                        'msg-type': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_replacemsggroup'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
