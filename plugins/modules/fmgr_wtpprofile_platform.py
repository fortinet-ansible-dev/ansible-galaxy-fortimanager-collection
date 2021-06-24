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
module: fmgr_wtpprofile_platform
short_description: WTP, FortiAP, or AP platform.
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
    wtp-profile:
        description: the parameter (wtp-profile) in requested url
        type: str
        required: true
    wtpprofile_platform:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            type:
                type: str
                description: 'WTP, FortiAP or AP platform type. There are built-in WTP profiles for all supported FortiAP models. You can select a built-in ...'
                choices:
                    - '30B-50B'
                    - '60B'
                    - '80CM-81CM'
                    - '220A'
                    - '220B'
                    - '210B'
                    - '60C'
                    - '222B'
                    - '112B'
                    - '320B'
                    - '11C'
                    - '14C'
                    - '223B'
                    - '28C'
                    - '320C'
                    - '221C'
                    - '25D'
                    - '222C'
                    - '224D'
                    - '214B'
                    - '21D'
                    - '24D'
                    - '112D'
                    - '223C'
                    - '321C'
                    - 'C220C'
                    - 'C225C'
                    - 'S321C'
                    - 'S323C'
                    - 'FWF'
                    - 'S311C'
                    - 'S313C'
                    - 'AP-11N'
                    - 'S322C'
                    - 'S321CR'
                    - 'S322CR'
                    - 'S323CR'
                    - 'S421E'
                    - 'S422E'
                    - 'S423E'
                    - '421E'
                    - '423E'
                    - 'C221E'
                    - 'C226E'
                    - 'C23JD'
                    - 'C24JE'
                    - 'C21D'
                    - 'U421E'
                    - 'U423E'
                    - '221E'
                    - '222E'
                    - '223E'
                    - 'S221E'
                    - 'S223E'
                    - 'U221EV'
                    - 'U223EV'
                    - 'U321EV'
                    - 'U323EV'
                    - '224E'
                    - 'U422EV'
                    - 'U24JEV'
                    - '321E'
                    - 'U431F'
                    - 'U433F'
                    - '231E'
                    - '431F'
                    - '433F'
                    - '231F'
                    - '432F'
                    - '234F'
                    - '23JF'
                    - 'U231F'
                    - '831F'
                    - 'U234F'
                    - 'U432F'
            mode:
                type: str
                description: 'Configure operation mode of 5G radios (default = dual-5G).'
                choices:
                    - 'dual-5G'
                    - 'single-5G'
            ddscan:
                type: str
                description: 'Enable/disable use of one radio for dedicated dual-band scanning to detect RF characterization and wireless threat management.'
                choices:
                    - 'disable'
                    - 'enable'
            _local_platform_str:
                type: str
                description: no description

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
    - name: WTP, FortiAP, or AP platform.
      fmgr_wtpprofile_platform:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         wtp-profile: <your own value>
         wtpprofile_platform:
            type: <value in [30B-50B, 60B, 80CM-81CM, ...]>
            mode: <value in [dual-5G, single-5G]>
            ddscan: <value in [disable, enable]>
            _local_platform_str: <value of string>

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
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/platform',
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/platform'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/platform/{platform}',
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/platform/{platform}'
    ]

    url_params = ['adom', 'wtp-profile']
    module_primary_key = None
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'wtp-profile': {
            'required': True,
            'type': 'str'
        },
        'wtpprofile_platform': {
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
                        '30B-50B',
                        '60B',
                        '80CM-81CM',
                        '220A',
                        '220B',
                        '210B',
                        '60C',
                        '222B',
                        '112B',
                        '320B',
                        '11C',
                        '14C',
                        '223B',
                        '28C',
                        '320C',
                        '221C',
                        '25D',
                        '222C',
                        '224D',
                        '214B',
                        '21D',
                        '24D',
                        '112D',
                        '223C',
                        '321C',
                        'C220C',
                        'C225C',
                        'S321C',
                        'S323C',
                        'FWF',
                        'S311C',
                        'S313C',
                        'AP-11N',
                        'S322C',
                        'S321CR',
                        'S322CR',
                        'S323CR',
                        'S421E',
                        'S422E',
                        'S423E',
                        '421E',
                        '423E',
                        'C221E',
                        'C226E',
                        'C23JD',
                        'C24JE',
                        'C21D',
                        'U421E',
                        'U423E',
                        '221E',
                        '222E',
                        '223E',
                        'S221E',
                        'S223E',
                        'U221EV',
                        'U223EV',
                        'U321EV',
                        'U323EV',
                        '224E',
                        'U422EV',
                        'U24JEV',
                        '321E',
                        'U431F',
                        'U433F',
                        '231E',
                        '431F',
                        '433F',
                        '231F',
                        '432F',
                        '234F',
                        '23JF',
                        'U231F',
                        '831F',
                        'U234F',
                        'U432F'
                    ],
                    'type': 'str'
                },
                'mode': {
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
                        'dual-5G',
                        'single-5G'
                    ],
                    'type': 'str'
                },
                'ddscan': {
                    'required': False,
                    'revision': {
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
                '_local_platform_str': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wtpprofile_platform'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
