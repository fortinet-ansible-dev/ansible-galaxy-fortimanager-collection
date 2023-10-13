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
module: fmgr_system_npu_dswqueuedtsprofile
short_description: Configure NPU DSW Queue DTS profile.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    system_npu_dswqueuedtsprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            iport:
                type: str
                description: Set NPU DSW DTS in port.
                choices:
                    - 'EIF0'
                    - 'eif0'
                    - 'EIF1'
                    - 'eif1'
                    - 'EIF2'
                    - 'eif2'
                    - 'EIF3'
                    - 'eif3'
                    - 'EIF4'
                    - 'eif4'
                    - 'EIF5'
                    - 'eif5'
                    - 'EIF6'
                    - 'eif6'
                    - 'EIF7'
                    - 'eif7'
                    - 'HTX0'
                    - 'htx0'
                    - 'HTX1'
                    - 'htx1'
                    - 'SSE0'
                    - 'sse0'
                    - 'SSE1'
                    - 'sse1'
                    - 'SSE2'
                    - 'sse2'
                    - 'SSE3'
                    - 'sse3'
                    - 'RLT'
                    - 'rlt'
                    - 'DFR'
                    - 'dfr'
                    - 'IPSECI'
                    - 'ipseci'
                    - 'IPSECO'
                    - 'ipseco'
                    - 'IPTI'
                    - 'ipti'
                    - 'IPTO'
                    - 'ipto'
                    - 'VEP0'
                    - 'vep0'
                    - 'VEP2'
                    - 'vep2'
                    - 'VEP4'
                    - 'vep4'
                    - 'VEP6'
                    - 'vep6'
                    - 'IVS'
                    - 'ivs'
                    - 'L2TI1'
                    - 'l2ti1'
                    - 'L2TO'
                    - 'l2to'
                    - 'L2TI0'
                    - 'l2ti0'
                    - 'PLE'
                    - 'ple'
                    - 'SPATH'
                    - 'spath'
                    - 'QTM'
                    - 'qtm'
            name:
                type: str
                description: Name.
                required: true
            oport:
                type: str
                description: Set NPU DSW DTS out port.
                choices:
                    - 'EIF0'
                    - 'eif0'
                    - 'EIF1'
                    - 'eif1'
                    - 'EIF2'
                    - 'eif2'
                    - 'EIF3'
                    - 'eif3'
                    - 'EIF4'
                    - 'eif4'
                    - 'EIF5'
                    - 'eif5'
                    - 'EIF6'
                    - 'eif6'
                    - 'EIF7'
                    - 'eif7'
                    - 'HRX'
                    - 'hrx'
                    - 'SSE0'
                    - 'sse0'
                    - 'SSE1'
                    - 'sse1'
                    - 'SSE2'
                    - 'sse2'
                    - 'SSE3'
                    - 'sse3'
                    - 'RLT'
                    - 'rlt'
                    - 'DFR'
                    - 'dfr'
                    - 'IPSECI'
                    - 'ipseci'
                    - 'IPSECO'
                    - 'ipseco'
                    - 'IPTI'
                    - 'ipti'
                    - 'IPTO'
                    - 'ipto'
                    - 'VEP0'
                    - 'vep0'
                    - 'VEP2'
                    - 'vep2'
                    - 'VEP4'
                    - 'vep4'
                    - 'VEP6'
                    - 'vep6'
                    - 'IVS'
                    - 'ivs'
                    - 'L2TI1'
                    - 'l2ti1'
                    - 'L2TO'
                    - 'l2to'
                    - 'L2TI0'
                    - 'l2ti0'
                    - 'PLE'
                    - 'ple'
                    - 'SYNK'
                    - 'sync'
                    - 'NSS'
                    - 'nss'
                    - 'TSK'
                    - 'tsk'
                    - 'QTM'
                    - 'qtm'
                    - 'l2tO'
            profile-id:
                type: int
                description: Set NPU DSW DTS profile ID.
            queue-select:
                type: int
                description: Set NPU DSW DTS queue ID select

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
    - name: Configure NPU DSW Queue DTS profile.
      fmgr_system_npu_dswqueuedtsprofile:
        bypass_validation: False
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        rc_succeeded: [0, -2, -3, ...]
        rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: <value in [present, absent]>
        system_npu_dswqueuedtsprofile:
          iport: <value in [EIF0, eif0, EIF1, ...]>
          name: <string>
          oport: <value in [EIF0, eif0, EIF1, ...]>
          profile-id: <integer>
          queue-select: <integer>

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
        '/pm/config/adom/{adom}/obj/system/npu/dsw-queue-dts-profile',
        '/pm/config/global/obj/system/npu/dsw-queue-dts-profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/system/npu/dsw-queue-dts-profile/{dsw-queue-dts-profile}',
        '/pm/config/global/obj/system/npu/dsw-queue-dts-profile/{dsw-queue-dts-profile}'
    ]

    url_params = ['adom']
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
        'system_npu_dswqueuedtsprofile': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '6.4.12': True,
                '6.4.13': True,
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
                'iport': {
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
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
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
                        'EIF0',
                        'eif0',
                        'EIF1',
                        'eif1',
                        'EIF2',
                        'eif2',
                        'EIF3',
                        'eif3',
                        'EIF4',
                        'eif4',
                        'EIF5',
                        'eif5',
                        'EIF6',
                        'eif6',
                        'EIF7',
                        'eif7',
                        'HTX0',
                        'htx0',
                        'HTX1',
                        'htx1',
                        'SSE0',
                        'sse0',
                        'SSE1',
                        'sse1',
                        'SSE2',
                        'sse2',
                        'SSE3',
                        'sse3',
                        'RLT',
                        'rlt',
                        'DFR',
                        'dfr',
                        'IPSECI',
                        'ipseci',
                        'IPSECO',
                        'ipseco',
                        'IPTI',
                        'ipti',
                        'IPTO',
                        'ipto',
                        'VEP0',
                        'vep0',
                        'VEP2',
                        'vep2',
                        'VEP4',
                        'vep4',
                        'VEP6',
                        'vep6',
                        'IVS',
                        'ivs',
                        'L2TI1',
                        'l2ti1',
                        'L2TO',
                        'l2to',
                        'L2TI0',
                        'l2ti0',
                        'PLE',
                        'ple',
                        'SPATH',
                        'spath',
                        'QTM',
                        'qtm'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': True,
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
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
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
                'oport': {
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
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
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
                        'EIF0',
                        'eif0',
                        'EIF1',
                        'eif1',
                        'EIF2',
                        'eif2',
                        'EIF3',
                        'eif3',
                        'EIF4',
                        'eif4',
                        'EIF5',
                        'eif5',
                        'EIF6',
                        'eif6',
                        'EIF7',
                        'eif7',
                        'HRX',
                        'hrx',
                        'SSE0',
                        'sse0',
                        'SSE1',
                        'sse1',
                        'SSE2',
                        'sse2',
                        'SSE3',
                        'sse3',
                        'RLT',
                        'rlt',
                        'DFR',
                        'dfr',
                        'IPSECI',
                        'ipseci',
                        'IPSECO',
                        'ipseco',
                        'IPTI',
                        'ipti',
                        'IPTO',
                        'ipto',
                        'VEP0',
                        'vep0',
                        'VEP2',
                        'vep2',
                        'VEP4',
                        'vep4',
                        'VEP6',
                        'vep6',
                        'IVS',
                        'ivs',
                        'L2TI1',
                        'l2ti1',
                        'L2TO',
                        'l2to',
                        'L2TI0',
                        'l2ti0',
                        'PLE',
                        'ple',
                        'SYNK',
                        'sync',
                        'NSS',
                        'nss',
                        'TSK',
                        'tsk',
                        'QTM',
                        'qtm',
                        'l2tO'
                    ],
                    'type': 'str'
                },
                'profile-id': {
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
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
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
                'queue-select': {
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
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
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
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_dswqueuedtsprofile'),
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
