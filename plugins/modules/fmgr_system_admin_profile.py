#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2020 Fortinet, Inc.
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
module: fmgr_system_admin_profile
short_description: Admin profile.
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
    system_admin_profile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            adom-lock:
                type: str
                description:
                 - 'ADOM locking'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            adom-policy-packages:
                type: str
                description:
                 - 'ADOM policy packages.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            adom-switch:
                type: str
                description:
                 - 'Administrator domain.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            app-filter:
                type: str
                description:
                 - 'App filter.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            assignment:
                type: str
                description:
                 - 'Assignment permission.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            change-password:
                type: str
                description:
                 - 'Enable/disable restricted user to change self password.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            config-retrieve:
                type: str
                description:
                 - 'Configuration retrieve.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            config-revert:
                type: str
                description:
                 - 'Revert Configuration from Revision History'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            consistency-check:
                type: str
                description:
                 - 'Consistency check.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            datamask:
                type: str
                description:
                 - 'Enable/disable data masking.'
                 - 'disable - Disable data masking.'
                 - 'enable - Enable data masking.'
                choices:
                    - 'disable'
                    - 'enable'
            datamask-custom-fields:
                description: no description
                type: list
                suboptions:
                    field-category:
                        description: no description
                        type: list
                        choices:
                         - log
                         - fortiview
                         - alert
                         - ueba
                         - all
                    field-name:
                        type: str
                        description: 'Field name.'
                    field-status:
                        type: str
                        description:
                         - 'Field status.'
                         - 'disable - Disable field.'
                         - 'enable - Enable field.'
                        choices:
                            - 'disable'
                            - 'enable'
                    field-type:
                        type: str
                        description:
                         - 'Field type.'
                         - 'string - String.'
                         - 'ip - IP.'
                         - 'mac - MAC address.'
                         - 'email - Email address.'
                         - 'unknown - Unknown.'
                        choices:
                            - 'string'
                            - 'ip'
                            - 'mac'
                            - 'email'
                            - 'unknown'
            datamask-custom-priority:
                type: str
                description:
                 - 'Prioritize custom fields.'
                 - 'disable - Disable custom field search priority.'
                 - 'enable - Enable custom field search priority.'
                choices:
                    - 'disable'
                    - 'enable'
            datamask-fields:
                description: no description
                type: list
                choices:
                 - user
                 - srcip
                 - srcname
                 - srcmac
                 - dstip
                 - dstname
                 - email
                 - message
                 - domain
            datamask-key:
                description: no description
                type: str
            deploy-management:
                type: str
                description:
                 - 'Install to devices.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            description:
                type: str
                description: 'Description.'
            device-ap:
                type: str
                description:
                 - 'Manage AP.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-config:
                type: str
                description:
                 - 'Manage device configurations.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-forticlient:
                type: str
                description:
                 - 'Manage FortiClient.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-fortiswitch:
                type: str
                description:
                 - 'Manage FortiSwitch.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-manager:
                type: str
                description:
                 - 'Device manager.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-op:
                type: str
                description:
                 - 'Device add/delete/edit.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-policy-package-lock:
                type: str
                description:
                 - 'Device/Policy Package locking'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-profile:
                type: str
                description:
                 - 'Device profile permission.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-revision-deletion:
                type: str
                description:
                 - 'Delete device revision.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            device-wan-link-load-balance:
                type: str
                description:
                 - 'Manage WAN link load balance.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            event-management:
                type: str
                description:
                 - 'Event management.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fgd-center-advanced:
                type: str
                description:
                 - 'FortiGuard Center Advanced.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fgd-center-fmw-mgmt:
                type: str
                description:
                 - 'FortiGuard Center Firmware Management.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fgd-center-licensing:
                type: str
                description:
                 - 'FortiGuard Center Licensing.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fgd_center:
                type: str
                description:
                 - 'FortiGuard Center.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            global-policy-packages:
                type: str
                description:
                 - 'Global policy packages.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            import-policy-packages:
                type: str
                description:
                 - 'Import Policy Package.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            intf-mapping:
                type: str
                description:
                 - 'Interface Mapping'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            ips-filter:
                type: str
                description:
                 - 'IPS filter.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            log-viewer:
                type: str
                description:
                 - 'Log viewer.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            policy-objects:
                type: str
                description:
                 - 'Policy objects permission.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            profileid:
                type: str
                description: 'Profile ID.'
            read-passwd:
                type: str
                description:
                 - 'View password in clear text.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            realtime-monitor:
                type: str
                description:
                 - 'Realtime monitor.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            report-viewer:
                type: str
                description:
                 - 'Report viewer.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            scope:
                type: str
                description:
                 - 'Scope.'
                 - 'global - Global scope.'
                 - 'adom - ADOM scope.'
                choices:
                    - 'global'
                    - 'adom'
            set-install-targets:
                type: str
                description:
                 - 'Edit installation targets.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            system-setting:
                type: str
                description:
                 - 'System setting.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            term-access:
                type: str
                description:
                 - 'Terminal access.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            type:
                type: str
                description:
                 - 'profile type.'
                 - 'system - System admin.'
                 - 'restricted - Restricted admin.'
                choices:
                    - 'system'
                    - 'restricted'
            vpn-manager:
                type: str
                description:
                 - 'VPN manager.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            web-filter:
                type: str
                description:
                 - 'Web filter.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
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
    - name: Admin profile.
      fmgr_system_admin_profile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         state: <value in [present, absent]>
         system_admin_profile:
            adom-lock: <value in [none, read, read-write]>
            adom-policy-packages: <value in [none, read, read-write]>
            adom-switch: <value in [none, read, read-write]>
            app-filter: <value in [disable, enable]>
            assignment: <value in [none, read, read-write]>
            change-password: <value in [disable, enable]>
            config-retrieve: <value in [none, read, read-write]>
            config-revert: <value in [none, read, read-write]>
            consistency-check: <value in [none, read, read-write]>
            datamask: <value in [disable, enable]>
            datamask-custom-fields:
              -
                  field-category:
                    - log
                    - fortiview
                    - alert
                    - ueba
                    - all
                  field-name: <value of string>
                  field-status: <value in [disable, enable]>
                  field-type: <value in [string, ip, mac, ...]>
            datamask-custom-priority: <value in [disable, enable]>
            datamask-fields:
              - user
              - srcip
              - srcname
              - srcmac
              - dstip
              - dstname
              - email
              - message
              - domain
            datamask-key: <value of string>
            deploy-management: <value in [none, read, read-write]>
            description: <value of string>
            device-ap: <value in [none, read, read-write]>
            device-config: <value in [none, read, read-write]>
            device-forticlient: <value in [none, read, read-write]>
            device-fortiswitch: <value in [none, read, read-write]>
            device-manager: <value in [none, read, read-write]>
            device-op: <value in [none, read, read-write]>
            device-policy-package-lock: <value in [none, read, read-write]>
            device-profile: <value in [none, read, read-write]>
            device-revision-deletion: <value in [none, read, read-write]>
            device-wan-link-load-balance: <value in [none, read, read-write]>
            event-management: <value in [none, read, read-write]>
            fgd-center-advanced: <value in [none, read, read-write]>
            fgd-center-fmw-mgmt: <value in [none, read, read-write]>
            fgd-center-licensing: <value in [none, read, read-write]>
            fgd_center: <value in [none, read, read-write]>
            global-policy-packages: <value in [none, read, read-write]>
            import-policy-packages: <value in [none, read, read-write]>
            intf-mapping: <value in [none, read, read-write]>
            ips-filter: <value in [disable, enable]>
            log-viewer: <value in [none, read, read-write]>
            policy-objects: <value in [none, read, read-write]>
            profileid: <value of string>
            read-passwd: <value in [none, read, read-write]>
            realtime-monitor: <value in [none, read, read-write]>
            report-viewer: <value in [none, read, read-write]>
            scope: <value in [global, adom]>
            set-install-targets: <value in [none, read, read-write]>
            system-setting: <value in [none, read, read-write]>
            term-access: <value in [none, read, read-write]>
            type: <value in [system, restricted]>
            vpn-manager: <value in [none, read, read-write]>
            web-filter: <value in [disable, enable]>

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
        '/cli/global/system/admin/profile'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/admin/profile/{profile}'
    ]

    url_params = []
    module_primary_key = 'profileid'
    module_arg_spec = {
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
        'system_admin_profile': {
            'required': False,
            'type': 'dict',
            'options': {
                'adom-lock': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'adom-policy-packages': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'adom-switch': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'app-filter': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'assignment': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'change-password': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'config-retrieve': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'config-revert': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'consistency-check': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'datamask': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'datamask-custom-fields': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'field-category': {
                            'required': False,
                            'type': 'list',
                            'choices': [
                                'log',
                                'fortiview',
                                'alert',
                                'ueba',
                                'all'
                            ]
                        },
                        'field-name': {
                            'required': False,
                            'type': 'str'
                        },
                        'field-status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'field-type': {
                            'required': False,
                            'choices': [
                                'string',
                                'ip',
                                'mac',
                                'email',
                                'unknown'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'datamask-custom-priority': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'datamask-fields': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'user',
                        'srcip',
                        'srcname',
                        'srcmac',
                        'dstip',
                        'dstname',
                        'email',
                        'message',
                        'domain'
                    ]
                },
                'datamask-key': {
                    'required': False,
                    'type': 'str'
                },
                'deploy-management': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'description': {
                    'required': False,
                    'type': 'str'
                },
                'device-ap': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-config': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-forticlient': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-fortiswitch': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-manager': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-op': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-policy-package-lock': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-profile': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-revision-deletion': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-wan-link-load-balance': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'event-management': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'fgd-center-advanced': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'fgd-center-fmw-mgmt': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'fgd-center-licensing': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'fgd_center': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'global-policy-packages': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'import-policy-packages': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'intf-mapping': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'ips-filter': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'log-viewer': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'policy-objects': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'profileid': {
                    'required': True,
                    'type': 'str'
                },
                'read-passwd': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'realtime-monitor': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'report-viewer': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'scope': {
                    'required': False,
                    'choices': [
                        'global',
                        'adom'
                    ],
                    'type': 'str'
                },
                'set-install-targets': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'system-setting': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'term-access': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'type': {
                    'required': False,
                    'choices': [
                        'system',
                        'restricted'
                    ],
                    'type': 'str'
                },
                'vpn-manager': {
                    'required': False,
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'web-filter': {
                    'required': False,
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_profile'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
