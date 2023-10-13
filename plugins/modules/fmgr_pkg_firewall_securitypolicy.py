#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2023 Fortinet, Inc.
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
module: fmgr_pkg_firewall_securitypolicy
short_description: Configure NGFW IPv4/IPv6 application policies.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
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
    access_token:
        description: The token to access FortiManager without using username and password.
        required: false
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        required: false
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        required: false
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        required: false
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        required: false
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        required: false
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        required: false
        type: int
        default: 300
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    pkg:
        description: the parameter (pkg) in requested url
        type: str
        required: true
    pkg_firewall_securitypolicy:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Policy action
                choices:
                    - 'deny'
                    - 'accept'
            app-category:
                type: raw
                description: (list or str) Application category ID list.
            app-group:
                type: raw
                description: (list or str) Application group names.
            application:
                type: raw
                description: (list) Application ID list.
            application-list:
                type: str
                description: Name of an existing Application list.
            av-profile:
                type: str
                description: Name of an existing Antivirus profile.
            cifs-profile:
                type: str
                description: Name of an existing CIFS profile.
            comments:
                type: str
                description: Comment.
            dlp-sensor:
                type: str
                description: Name of an existing DLP sensor.
            dnsfilter-profile:
                type: str
                description: Name of an existing DNS filter profile.
            dstaddr4:
                type: raw
                description: (list or str) Destination IPv4 address name and address group names.
            dstaddr6:
                type: raw
                description: (list or str) Destination IPv6 address name and address group names.
            dstintf:
                type: raw
                description: (list or str) Outgoing
            emailfilter-profile:
                type: str
                description: Name of an existing email filter profile.
            enforce-default-app-port:
                type: str
                description: Enable/disable default application port enforcement for allowed applications.
                choices:
                    - 'disable'
                    - 'enable'
            groups:
                type: raw
                description: (list or str) Names of user groups that can authenticate with this policy.
            icap-profile:
                type: str
                description: Name of an existing ICAP profile.
            internet-service:
                type: str
                description: Enable/disable use of Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-custom:
                type: raw
                description: (list or str) Custom Internet Service name.
            internet-service-custom-group:
                type: raw
                description: (list or str) Custom Internet Service group name.
            internet-service-group:
                type: raw
                description: (list or str) Internet Service group name.
            internet-service-id:
                type: raw
                description: (list or str) Internet Service ID.
            internet-service-negate:
                type: str
                description: When enabled internet-service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src:
                type: str
                description: Enable/disable use of Internet Services in source for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src-custom:
                type: raw
                description: (list or str) Custom Internet Service source name.
            internet-service-src-custom-group:
                type: raw
                description: (list or str) Custom Internet Service source group name.
            internet-service-src-group:
                type: raw
                description: (list or str) Internet Service source group name.
            internet-service-src-id:
                type: raw
                description: (list or str) Internet Service source ID.
            internet-service-src-negate:
                type: str
                description: When enabled internet-service-src specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            ips-sensor:
                type: str
                description: Name of an existing IPS sensor.
            logtraffic:
                type: str
                description: Enable or disable logging.
                choices:
                    - 'disable'
                    - 'all'
                    - 'utm'
            logtraffic-start:
                type: str
                description: Record logs when a session starts.
                choices:
                    - 'disable'
                    - 'enable'
            mms-profile:
                type: str
                description: Name of an existing MMS profile.
            name:
                type: str
                description: Policy name.
                required: true
            policyid:
                type: int
                description: Policy ID.
            profile-group:
                type: str
                description: Name of profile group.
            profile-protocol-options:
                type: str
                description: Name of an existing Protocol options profile.
            profile-type:
                type: str
                description: Determine whether the firewall policy allows security profile groups or single profiles only.
                choices:
                    - 'single'
                    - 'group'
            schedule:
                type: str
                description: Schedule name.
            service:
                type: raw
                description: (list or str) Service and service group names.
            service-negate:
                type: str
                description: When enabled service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr4:
                type: raw
                description: (list or str) Source IPv4 address name and address group names.
            srcaddr6:
                type: raw
                description: (list or str) Source IPv6 address name and address group names.
            srcintf:
                type: raw
                description: (list or str) Incoming
            ssh-filter-profile:
                type: str
                description: Name of an existing SSH filter profile.
            ssl-ssh-profile:
                type: str
                description: Name of an existing SSL SSH profile.
            status:
                type: str
                description: Enable or disable this policy.
                choices:
                    - 'disable'
                    - 'enable'
            url-category:
                type: raw
                description: (list or str) URL category ID list.
            users:
                type: raw
                description: (list or str) Names of individual users that can authenticate with this policy.
            utm-status:
                type: str
                description: Enable security profiles.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            voip-profile:
                type: str
                description: Name of an existing VoIP profile.
            webfilter-profile:
                type: str
                description: Name of an existing Web filter profile.
            fsso-groups:
                type: raw
                description: (list or str) Names of FSSO groups.
            global-label:
                type: str
                description: Label for the policy that appears when the GUI is in Global View mode.
            send-deny-packet:
                type: str
                description: Enable to send a reply when a session is denied or blocked by a firewall policy.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: raw
                description: (list or str) Destination IPv4 address name and address group names.
            internet-service-name:
                type: raw
                description: (list or str) Internet Service name.
            internet-service-src-name:
                type: raw
                description: (list or str) Internet Service source name.
            srcaddr:
                type: raw
                description: (list or str) Source IPv4 address name and address group names.
            dstaddr-negate:
                type: str
                description: When enabled dstaddr/dstaddr6 specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            file-filter-profile:
                type: str
                description: Name of an existing file-filter profile.
            srcaddr-negate:
                type: str
                description: When enabled srcaddr/srcaddr6 specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            learning-mode:
                type: str
                description: Enable to allow everything, but log all of the meaningful data for security information gathering.
                choices:
                    - 'disable'
                    - 'enable'
            videofilter-profile:
                type: str
                description: Name of an existing VideoFilter profile.
            _policy_block:
                type: int
                description: Assigned policy block.
            dlp-profile:
                type: str
                description: Name of an existing DLP profile.
            nat46:
                type: str
                description: Enable/disable NAT46.
                choices:
                    - 'disable'
                    - 'enable'
            nat64:
                type: str
                description: Enable/disable NAT64.
                choices:
                    - 'disable'
                    - 'enable'
            sctp-filter-profile:
                type: str
                description: Name of an existing SCTP filter profile.
            internet-service6:
                type: str
                description: Enable/disable use of IPv6 Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service6-custom:
                type: raw
                description: (list) no description
            internet-service6-custom-group:
                type: raw
                description: (list) no description
            internet-service6-group:
                type: raw
                description: (list) no description
            internet-service6-name:
                type: raw
                description: (list) no description
            internet-service6-negate:
                type: str
                description: When enabled internet-service6 specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service6-src:
                type: str
                description: Enable/disable use of IPv6 Internet Services in source for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service6-src-custom:
                type: raw
                description: (list) no description
            internet-service6-src-custom-group:
                type: raw
                description: (list) no description
            internet-service6-src-group:
                type: raw
                description: (list) no description
            internet-service6-src-name:
                type: raw
                description: (list) no description
            internet-service6-src-negate:
                type: str
                description: When enabled internet-service6-src specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'

'''

EXAMPLES = '''
- hosts: fortimanager-inventory
  collections:
    - fortinet.fortimanager
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: True
    ansible_httpapi_validate_certs: False
    ansible_httpapi_port: 443
  tasks:
    - name: Configure NGFW IPv4/IPv6 application policies.
      fmgr_pkg_firewall_securitypolicy:
        bypass_validation: False
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        rc_succeeded: [0, -2, -3, ...]
        rc_failed: [-2, -3, ...]
        adom: <your own value>
        pkg: <your own value>
        state: <value in [present, absent]>
        pkg_firewall_securitypolicy:
          action: <value in [deny, accept]>
          app-category: <list or string>
          app-group: <list or string>
          application: <list or integer>
          application-list: <string>
          av-profile: <string>
          cifs-profile: <string>
          comments: <string>
          dlp-sensor: <string>
          dnsfilter-profile: <string>
          dstaddr4: <list or string>
          dstaddr6: <list or string>
          dstintf: <list or string>
          emailfilter-profile: <string>
          enforce-default-app-port: <value in [disable, enable]>
          groups: <list or string>
          icap-profile: <string>
          internet-service: <value in [disable, enable]>
          internet-service-custom: <list or string>
          internet-service-custom-group: <list or string>
          internet-service-group: <list or string>
          internet-service-id: <list or string>
          internet-service-negate: <value in [disable, enable]>
          internet-service-src: <value in [disable, enable]>
          internet-service-src-custom: <list or string>
          internet-service-src-custom-group: <list or string>
          internet-service-src-group: <list or string>
          internet-service-src-id: <list or string>
          internet-service-src-negate: <value in [disable, enable]>
          ips-sensor: <string>
          logtraffic: <value in [disable, all, utm]>
          logtraffic-start: <value in [disable, enable]>
          mms-profile: <string>
          name: <string>
          policyid: <integer>
          profile-group: <string>
          profile-protocol-options: <string>
          profile-type: <value in [single, group]>
          schedule: <string>
          service: <list or string>
          service-negate: <value in [disable, enable]>
          srcaddr4: <list or string>
          srcaddr6: <list or string>
          srcintf: <list or string>
          ssh-filter-profile: <string>
          ssl-ssh-profile: <string>
          status: <value in [disable, enable]>
          url-category: <list or string>
          users: <list or string>
          utm-status: <value in [disable, enable]>
          uuid: <string>
          voip-profile: <string>
          webfilter-profile: <string>
          fsso-groups: <list or string>
          global-label: <string>
          send-deny-packet: <value in [disable, enable]>
          dstaddr: <list or string>
          internet-service-name: <list or string>
          internet-service-src-name: <list or string>
          srcaddr: <list or string>
          dstaddr-negate: <value in [disable, enable]>
          file-filter-profile: <string>
          srcaddr-negate: <value in [disable, enable]>
          learning-mode: <value in [disable, enable]>
          videofilter-profile: <string>
          _policy_block: <integer>
          dlp-profile: <string>
          nat46: <value in [disable, enable]>
          nat64: <value in [disable, enable]>
          sctp-filter-profile: <string>
          internet-service6: <value in [disable, enable]>
          internet-service6-custom: <list or string>
          internet-service6-custom-group: <list or string>
          internet-service6-group: <list or string>
          internet-service6-name: <list or string>
          internet-service6-negate: <value in [disable, enable]>
          internet-service6-src: <value in [disable, enable]>
          internet-service6-src-custom: <list or string>
          internet-service6-src-custom-group: <list or string>
          internet-service6-src-group: <list or string>
          internet-service6-src-name: <list or string>
          internet-service6-src-negate: <value in [disable, enable]>

'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy/{security-policy}'
    ]

    url_params = ['adom', 'pkg']
    module_primary_key = 'name'
    module_arg_spec = {
        'access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
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
        'rc_succeeded': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'rc_failed': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'pkg': {
            'required': True,
            'type': 'str'
        },
        'pkg_firewall_securitypolicy': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.2.11': True,
                '6.2.12': True,
                '6.4.0': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '6.4.6': True,
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '6.4.12': True,
                '6.4.13': True,
                '7.0.0': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.0.8': True,
                '7.0.9': True,
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.2.3': True,
                '7.2.4': True,
                '7.4.0': True,
                '7.4.1': True
            },
            'options': {
                'action': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'deny',
                        'accept'
                    ],
                    'type': 'str'
                },
                'app-category': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'app-group': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'application': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'application-list': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'av-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'cifs-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'comments': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'dlp-sensor': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'dnsfilter-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'dstaddr4': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'dstaddr6': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'dstintf': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'emailfilter-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'enforce-default-app-port': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'groups': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'icap-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'internet-service': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'internet-service-custom': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'internet-service-custom-group': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'internet-service-group': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'internet-service-id': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'internet-service-negate': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'internet-service-src': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'internet-service-src-custom': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'internet-service-src-custom-group': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'internet-service-src-group': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'internet-service-src-id': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'internet-service-src-negate': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ips-sensor': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'logtraffic': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'all',
                        'utm'
                    ],
                    'type': 'str'
                },
                'logtraffic-start': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': False,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'policyid': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'int'
                },
                'profile-group': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'profile-protocol-options': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'str'
                },
                'profile-type': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'single',
                        'group'
                    ],
                    'type': 'str'
                },
                'schedule': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'service': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'service-negate': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'srcaddr4': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'srcaddr6': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'srcintf': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'ssh-filter-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'ssl-ssh-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'url-category': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'users': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'utm-status': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'uuid': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'voip-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'webfilter-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'fsso-groups': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'raw'
                },
                'global-label': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'send-deny-packet': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dstaddr': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'internet-service-name': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'internet-service-src-name': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'srcaddr': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'dstaddr-negate': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.1': False,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'file-filter-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'str'
                },
                'srcaddr-negate': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.1': False,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'learning-mode': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '6.4.12': False,
                        '6.4.13': False,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'videofilter-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '6.4.12': False,
                        '6.4.13': False,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'str'
                },
                '_policy_block': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '6.4.12': False,
                        '6.4.13': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'int'
                },
                'dlp-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '6.4.12': False,
                        '6.4.13': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.0.8': False,
                        '7.0.9': False,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'str'
                },
                'nat46': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '6.4.12': False,
                        '6.4.13': False,
                        '7.0.1': False,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'nat64': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '6.4.12': False,
                        '6.4.13': False,
                        '7.0.1': False,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sctp-filter-profile': {
                    'required': False,
                    'revision': {
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.2.11': False,
                        '6.2.12': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '6.4.12': False,
                        '6.4.13': False,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'str'
                },
                'internet-service6': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'internet-service6-custom': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'internet-service6-custom-group': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'internet-service6-group': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'internet-service6-name': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'internet-service6-negate': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'internet-service6-src': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'internet-service6-src-custom': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'internet-service6-src-custom-group': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'internet-service6-src-group': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'internet-service6-src-name': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'type': 'raw'
                },
                'internet-service6-src-negate': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': False,
                        '7.2.3': False,
                        '7.2.4': True,
                        '7.4.0': False,
                        '7.4.1': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_securitypolicy'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('access_token', module.params['access_token'] if 'access_token' in module.params else None)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
