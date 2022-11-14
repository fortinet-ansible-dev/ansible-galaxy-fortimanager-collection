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
module: fmgr_dvmdb_adom
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
    dvmdb_adom:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            desc:
                type: str
                description: no description
            flags:
                description: no description
                type: list
                choices:
                 - migration
                 - db_export
                 - no_vpn_console
                 - backup
                 - other_devices
                 - central_sdwan
                 - is_autosync
                 - per_device_wtp
                 - policy_check_on_install
                 - install_on_policy_check_fail
                 - auto_push_cfg
                 - per_device_fsw
            log_db_retention_hours:
                type: int
                default: 1440
                description: no description
            log_disk_quota:
                type: int
                description: no description
            log_disk_quota_alert_thres:
                type: int
                default: 90
                description: no description
            log_disk_quota_split_ratio:
                type: int
                default: 70
                description: no description
            log_file_retention_hours:
                type: int
                default: 8760
                description: no description
            meta fields:
                description: no description
                type: dict
            mig_mr:
                type: int
                default: 2
                description: no description
            mig_os_ver:
                type: str
                default: '6.'
                description: no description
                choices:
                    - 'unknown'
                    - '0.0'
                    - '1.0'
                    - '2.0'
                    - '3.0'
                    - '4.0'
                    - '5.0'
                    - '6.0'
                    - '7.0'
                    - '8.0'
            mode:
                type: str
                default: 'gms'
                description:
                 - no description
                 - no description
                choices:
                    - 'ems'
                    - 'gms'
                    - 'provider'
            mr:
                type: int
                default: 2
                description: no description
            name:
                type: str
                description: no description
            os_ver:
                type: str
                default: '6.'
                description: no description
                choices:
                    - 'unknown'
                    - '0.0'
                    - '1.0'
                    - '2.0'
                    - '3.0'
                    - '4.0'
                    - '5.0'
                    - '6.0'
                    - '7.0'
                    - '8.0'
            restricted_prds:
                description: no description
                type: list
                choices:
                 - fos
                 - foc
                 - fml
                 - fch
                 - fwb
                 - log
                 - fct
                 - faz
                 - fsa
                 - fsw
                 - fmg
                 - fdd
                 - fac
                 - fpx
                 - fna
                 - fdc
                 - ffw
                 - fsr
                 - fad
                 - fap
                 - fxt
                 - fts
                 - fai
                 - fwc
            state:
                type: int
                default: 1
                description: no description
            uuid:
                type: str
                description: no description
            create_time:
                type: int
                description: no description
            workspace_mode:
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
      fmgr_dvmdb_adom:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         state: <value in [present, absent]>
         dvmdb_adom:
            desc: <value of string>
            flags:
              - migration
              - db_export
              - no_vpn_console
              - backup
              - other_devices
              - central_sdwan
              - is_autosync
              - per_device_wtp
              - policy_check_on_install
              - install_on_policy_check_fail
              - auto_push_cfg
              - per_device_fsw
            log_db_retention_hours: <value of integer>
            log_disk_quota: <value of integer>
            log_disk_quota_alert_thres: <value of integer>
            log_disk_quota_split_ratio: <value of integer>
            log_file_retention_hours: <value of integer>
            meta fields: <value of dict>
            mig_mr: <value of integer>
            mig_os_ver: <value in [unknown, 0.0, 1.0, ...]>
            mode: <value in [ems, gms, provider]>
            mr: <value of integer>
            name: <value of string>
            os_ver: <value in [unknown, 0.0, 1.0, ...]>
            restricted_prds:
              - fos
              - foc
              - fml
              - fch
              - fwb
              - log
              - fct
              - faz
              - fsa
              - fsw
              - fmg
              - fdd
              - fac
              - fpx
              - fna
              - fdc
              - ffw
              - fsr
              - fad
              - fap
              - fxt
              - fts
              - fai
              - fwc
            state: <value of integer>
            uuid: <value of string>
            create_time: <value of integer>
            workspace_mode: <value of integer>

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
        '/dvmdb/adom'
    ]

    perobject_jrpc_urls = [
        '/dvmdb/adom/{adom}'
    ]

    url_params = []
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
        'dvmdb_adom': {
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
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'desc': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'flags': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'migration',
                        'db_export',
                        'no_vpn_console',
                        'backup',
                        'other_devices',
                        'central_sdwan',
                        'is_autosync',
                        'per_device_wtp',
                        'policy_check_on_install',
                        'install_on_policy_check_fail',
                        'auto_push_cfg',
                        'per_device_fsw'
                    ]
                },
                'log_db_retention_hours': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'log_disk_quota': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'log_disk_quota_alert_thres': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'log_disk_quota_split_ratio': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'log_file_retention_hours': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'meta fields': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'dict'
                },
                'mig_mr': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'mig_os_ver': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'unknown',
                        '0.0',
                        '1.0',
                        '2.0',
                        '3.0',
                        '4.0',
                        '5.0',
                        '6.0',
                        '7.0',
                        '8.0'
                    ],
                    'type': 'str'
                },
                'mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'ems',
                        'gms',
                        'provider'
                    ],
                    'type': 'str'
                },
                'mr': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
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
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'os_ver': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'unknown',
                        '0.0',
                        '1.0',
                        '2.0',
                        '3.0',
                        '4.0',
                        '5.0',
                        '6.0',
                        '7.0',
                        '8.0'
                    ],
                    'type': 'str'
                },
                'restricted_prds': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'fos',
                        'foc',
                        'fml',
                        'fch',
                        'fwb',
                        'log',
                        'fct',
                        'faz',
                        'fsa',
                        'fsw',
                        'fmg',
                        'fdd',
                        'fac',
                        'fpx',
                        'fna',
                        'fdc',
                        'ffw',
                        'fsr',
                        'fad',
                        'fap',
                        'fxt',
                        'fts',
                        'fai',
                        'fwc'
                    ]
                },
                'state': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'uuid': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'create_time': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'workspace_mode': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvmdb_adom'),
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
