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
    system_admin_profile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            adom-lock:
                type: str
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'disable'
                description:
                 - 'App filter.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            assignment:
                type: str
                default: 'none'
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
                default: 'disable'
                description:
                 - 'Enable/disable restricted user to change self password.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            config-retrieve:
                type: str
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'disable'
                description:
                 - 'Enable/disable data masking.'
                 - 'disable - Disable data masking.'
                 - 'enable - Enable data masking.'
                choices:
                    - 'disable'
                    - 'enable'
            datamask-custom-fields:
                description: 'Datamask-Custom-Fields.'
                type: list
                suboptions:
                    field-category:
                        description: 'Field categories.'
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
                        default: 'enable'
                        description:
                         - 'Field status.'
                         - 'disable - Disable field.'
                         - 'enable - Enable field.'
                        choices:
                            - 'disable'
                            - 'enable'
                    field-type:
                        type: str
                        default: 'string'
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
                default: 'disable'
                description:
                 - 'Prioritize custom fields.'
                 - 'disable - Disable custom field search priority.'
                 - 'enable - Enable custom field search priority.'
                choices:
                    - 'disable'
                    - 'enable'
            datamask-fields:
                description: 'Data masking fields.'
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
                description: 'Data masking encryption key.'
                type: str
            deploy-management:
                type: str
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'disable'
                description:
                 - 'IPS filter.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            log-viewer:
                type: str
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'global'
                description:
                 - 'Scope.'
                 - 'global - Global scope.'
                 - 'adom - ADOM scope.'
                choices:
                    - 'global'
                    - 'adom'
            set-install-targets:
                type: str
                default: 'none'
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
                default: 'none'
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
                default: 'none'
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
                default: 'system'
                description:
                 - 'profile type.'
                 - 'system - System admin.'
                 - 'restricted - Restricted admin.'
                choices:
                    - 'system'
                    - 'restricted'
            vpn-manager:
                type: str
                default: 'none'
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
                default: 'disable'
                description:
                 - 'Web filter.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            datamask-unmasked-time:
                type: int
                default: 0
                description: 'Time in days without data masking.'
            super-user-profile:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable super user profile'
                 - 'disable - Disable super user profile'
                 - 'enable - Enable super user profile'
                choices:
                    - 'disable'
                    - 'enable'
            allow-to-install:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable the restricted user to install objects to the devices.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            extension-access:
                type: str
                default: 'none'
                description:
                 - 'Manage extension access.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fabric-viewer:
                type: str
                default: 'none'
                description:
                 - 'Fabric viewer.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            run-report:
                type: str
                default: 'none'
                description:
                 - 'Run reports.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            script-access:
                type: str
                default: 'none'
                description:
                 - 'Script access.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            triage-events:
                type: str
                default: 'none'
                description:
                 - 'Triage events.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            update-incidents:
                type: str
                default: 'none'
                description:
                 - 'Create/update incidents.'
                 - 'none - No permission.'
                 - 'read - Read permission.'
                 - 'read-write - Read-write permission.'
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'

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
    - name: Admin profile.
      fmgr_system_admin_profile:
         bypass_validation: False
         state: present
         system_admin_profile:
            description: ansible-test-description
            profileid: ansible-test-profile
            scope: adom #<value in [global, adom]>
            type: system #<value in [system, restricted]>

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
    - name: retrieve all the admin profiles
      fmgr_fact:
        facts:
            selector: 'system_admin_profile'
            params:
                profile: ''
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
                'adom-lock': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'adom-policy-packages': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'adom-switch': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'app-filter': {
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
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'assignment': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'change-password': {
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
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'config-retrieve': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'config-revert': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'consistency-check': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'datamask': {
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
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'datamask-custom-fields': {
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
                        'field-category': {
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
                        'field-status': {
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
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'field-type': {
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
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'datamask-fields': {
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
                'deploy-management': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'description': {
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
                'device-ap': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-config': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-forticlient': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-fortiswitch': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-manager': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-op': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-policy-package-lock': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-profile': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-revision-deletion': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'device-wan-link-load-balance': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'event-management': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'fgd-center-advanced': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'fgd-center-fmw-mgmt': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'fgd-center-licensing': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'fgd_center': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'global-policy-packages': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'import-policy-packages': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'intf-mapping': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'ips-filter': {
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
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'log-viewer': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'policy-objects': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'profileid': {
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
                'read-passwd': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'realtime-monitor': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'report-viewer': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'scope': {
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
                        'global',
                        'adom'
                    ],
                    'type': 'str'
                },
                'set-install-targets': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'system-setting': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'term-access': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'type': {
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
                        'system',
                        'restricted'
                    ],
                    'type': 'str'
                },
                'vpn-manager': {
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
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'web-filter': {
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
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'datamask-unmasked-time': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'super-user-profile': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'allow-to-install': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'extension-access': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'fabric-viewer': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'run-report': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'script-access': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'triage-events': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
                    ],
                    'type': 'str'
                },
                'update-incidents': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'none',
                        'read',
                        'read-write'
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
