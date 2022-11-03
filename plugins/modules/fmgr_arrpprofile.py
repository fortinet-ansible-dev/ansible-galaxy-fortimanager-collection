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
module: fmgr_arrpprofile
short_description: no description
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
        description: |
          only set to True when module schema diffs with FortiManager API structure,
           module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: |
          the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
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
    arrpprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: no description
            darrp-optimize:
                type: int
                description: no description
            darrp-optimize-schedules:
                description: description
                type: str
            include-dfs-channel:
                type: str
                description: no description
                choices:
                    - 'no'
                    - 'disable'
                    - 'yes'
                    - 'enable'
            include-weather-channel:
                type: str
                description: no description
                choices:
                    - 'no'
                    - 'disable'
                    - 'yes'
                    - 'enable'
            monitor-period:
                type: int
                description: no description
            name:
                type: str
                description: no description
            override-darrp-optimize:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            selection-period:
                type: int
                description: no description
            threshold-ap:
                type: int
                description: no description
            threshold-channel-load:
                type: int
                description: no description
            threshold-noise-floor:
                type: str
                description: no description
            threshold-rx-errors:
                type: int
                description: no description
            threshold-spectral-rssi:
                type: str
                description: no description
            threshold-tx-retries:
                type: int
                description: no description
            weight-channel-load:
                type: int
                description: no description
            weight-dfs-channel:
                type: int
                description: no description
            weight-managed-ap:
                type: int
                description: no description
            weight-noise-floor:
                type: int
                description: no description
            weight-rogue-ap:
                type: int
                description: no description
            weight-spectral-rssi:
                type: int
                description: no description
            weight-weather-channel:
                type: int
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
    - name: no description
      fmgr_arrpprofile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         arrpprofile:
            comment: <value of string>
            darrp-optimize: <value of integer>
            darrp-optimize-schedules: <value of string>
            include-dfs-channel: <value in [no, disable, yes, ...]>
            include-weather-channel: <value in [no, disable, yes, ...]>
            monitor-period: <value of integer>
            name: <value of string>
            override-darrp-optimize: <value in [disable, enable]>
            selection-period: <value of integer>
            threshold-ap: <value of integer>
            threshold-channel-load: <value of integer>
            threshold-noise-floor: <value of string>
            threshold-rx-errors: <value of integer>
            threshold-spectral-rssi: <value of string>
            threshold-tx-retries: <value of integer>
            weight-channel-load: <value of integer>
            weight-dfs-channel: <value of integer>
            weight-managed-ap: <value of integer>
            weight-noise-floor: <value of integer>
            weight-rogue-ap: <value of integer>
            weight-spectral-rssi: <value of integer>
            weight-weather-channel: <value of integer>

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
        '/pm/config/global/obj/wireless-controller/arrp-profile',
        '/pm/config/adom/{adom}/obj/wireless-controller/arrp-profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/wireless-controller/arrp-profile/{arrp-profile}',
        '/pm/config/adom/{adom}/obj/wireless-controller/arrp-profile/{arrp-profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'arrpprofile': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.2.0': True
            },
            'options': {
                'comment': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'darrp-optimize': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'darrp-optimize-schedules': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'include-dfs-channel': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'no',
                        'disable',
                        'yes',
                        'enable'
                    ],
                    'type': 'str'
                },
                'include-weather-channel': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'no',
                        'disable',
                        'yes',
                        'enable'
                    ],
                    'type': 'str'
                },
                'monitor-period': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'override-darrp-optimize': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'selection-period': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'threshold-ap': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'threshold-channel-load': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'threshold-noise-floor': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'threshold-rx-errors': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'threshold-spectral-rssi': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'threshold-tx-retries': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'weight-channel-load': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'weight-dfs-channel': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'weight-managed-ap': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'weight-noise-floor': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'weight-rogue-ap': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'weight-spectral-rssi': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'weight-weather-channel': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'arrpprofile'),
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
