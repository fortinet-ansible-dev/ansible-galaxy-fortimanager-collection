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
module: fmgr_firewall_mmsprofile_flood
short_description: Flood configuration.
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
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    mms-profile:
        description: the parameter (mms-profile) in requested url
        type: str
        required: true
    firewall_mmsprofile_flood:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            action1:
                description: no description
                type: list
                choices:
                 - log
                 - archive
                 - intercept
                 - block
                 - archive-first
                 - alert-notif
            action2:
                description: no description
                type: list
                choices:
                 - log
                 - archive
                 - intercept
                 - block
                 - archive-first
                 - alert-notif
            action3:
                description: no description
                type: list
                choices:
                 - log
                 - archive
                 - intercept
                 - block
                 - archive-first
                 - alert-notif
            block-time1:
                type: int
                description: 'Duration for which action takes effect (0 - 35791 min).'
            block-time2:
                type: int
                description: 'Duration for which action takes effect (0 - 35791 min).'
            block-time3:
                type: int
                description: 'Duration action takes effect (0 - 35791 min).'
            limit1:
                type: int
                description: 'Maximum number of messages allowed.'
            limit2:
                type: int
                description: 'Maximum number of messages allowed.'
            limit3:
                type: int
                description: 'Maximum number of messages allowed.'
            protocol:
                type: str
                description: 'Protocol.'
            status1:
                type: str
                description: 'Enable/disable status1 detection.'
                choices:
                    - 'disable'
                    - 'enable'
            status2:
                type: str
                description: 'Enable/disable status2 detection.'
                choices:
                    - 'disable'
                    - 'enable'
            status3:
                type: str
                description: 'Enable/disable status3 detection.'
                choices:
                    - 'disable'
                    - 'enable'
            window1:
                type: int
                description: 'Window to count messages over (1 - 2880 min).'
            window2:
                type: int
                description: 'Window to count messages over (1 - 2880 min).'
            window3:
                type: int
                description: 'Window to count messages over (1 - 2880 min).'

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
    - name: Flood configuration.
      fmgr_firewall_mmsprofile_flood:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         mms-profile: <your own value>
         firewall_mmsprofile_flood:
            action1:
              - log
              - archive
              - intercept
              - block
              - archive-first
              - alert-notif
            action2:
              - log
              - archive
              - intercept
              - block
              - archive-first
              - alert-notif
            action3:
              - log
              - archive
              - intercept
              - block
              - archive-first
              - alert-notif
            block-time1: <value of integer>
            block-time2: <value of integer>
            block-time3: <value of integer>
            limit1: <value of integer>
            limit2: <value of integer>
            limit3: <value of integer>
            protocol: <value of string>
            status1: <value in [disable, enable]>
            status2: <value in [disable, enable]>
            status3: <value in [disable, enable]>
            window1: <value of integer>
            window2: <value of integer>
            window3: <value of integer>

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
        '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/flood',
        '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/flood'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/flood/{flood}',
        '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/flood/{flood}'
    ]

    url_params = ['adom', 'mms-profile']
    module_primary_key = None
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'mms-profile': {
            'required': True,
            'type': 'str'
        },
        'firewall_mmsprofile_flood': {
            'required': False,
            'type': 'dict',
            'options': {
                'action1': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'log',
                        'archive',
                        'intercept',
                        'block',
                        'archive-first',
                        'alert-notif'
                    ]
                },
                'action2': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'log',
                        'archive',
                        'intercept',
                        'block',
                        'archive-first',
                        'alert-notif'
                    ]
                },
                'action3': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'log',
                        'archive',
                        'intercept',
                        'block',
                        'archive-first',
                        'alert-notif'
                    ]
                },
                'block-time1': {
                    'required': False,
                    'type': 'int'
                },
                'block-time2': {
                    'required': False,
                    'type': 'int'
                },
                'block-time3': {
                    'required': False,
                    'type': 'int'
                },
                'limit1': {
                    'required': False,
                    'type': 'int'
                },
                'limit2': {
                    'required': False,
                    'type': 'int'
                },
                'limit3': {
                    'required': False,
                    'type': 'int'
                },
                'protocol': {
                    'required': False,
                    'type': 'str'
                },
                'status1': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'status2': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'status3': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'window1': {
                    'required': False,
                    'type': 'int'
                },
                'window2': {
                    'required': False,
                    'type': 'int'
                },
                'window3': {
                    'required': False,
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_mmsprofile_flood'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
