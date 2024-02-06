#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_dvmdb_adom
short_description: ADOM table, most attributes are read-only and can only be changed internally.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
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
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    dvmdb_adom:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            desc:
                type: str
                description: Desc.
            flags:
                type: list
                elements: str
                description: Flags.
                choices:
                    - 'migration'
                    - 'db_export'
                    - 'no_vpn_console'
                    - 'backup'
                    - 'other_devices'
                    - 'central_sdwan'
                    - 'is_autosync'
                    - 'per_device_wtp'
                    - 'policy_check_on_install'
                    - 'install_on_policy_check_fail'
                    - 'auto_push_cfg'
                    - 'per_device_fsw'
                    - 'install_deselect_all'
            log_db_retention_hours:
                type: int
                description: Log_Db_Retention_Hours.
            log_disk_quota:
                type: int
                description: Log_Disk_Quota.
            log_disk_quota_alert_thres:
                type: int
                description: Log_Disk_Quota_Alert_Thres.
            log_disk_quota_split_ratio:
                type: int
                description: Log_Disk_Quota_Split_Ratio.
            log_file_retention_hours:
                type: int
                description: Log_File_Retention_Hours.
            meta fields:
                type: dict
                description: Deprecated, please rename it to meta_fields. Default metafields
            mig_mr:
                type: int
                description: Mig_Mr.
            mig_os_ver:
                type: str
                description: Mig_Os_Ver.
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
                    - '9.0'
            mode:
                type: str
                description:
                    - ems -
                    - provider - Global database.
                choices:
                    - 'ems'
                    - 'gms'
                    - 'provider'
            mr:
                type: int
                description: Mr.
            name:
                type: str
                description: Name.
                required: true
            os_ver:
                type: str
                description: Os_Ver.
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
                    - '9.0'
            restricted_prds:
                type: raw
                description: (list or str) Restricted_Prds.
                choices:
                    - 'fos'
                    - 'foc'
                    - 'fml'
                    - 'fch'
                    - 'fwb'
                    - 'log'
                    - 'fct'
                    - 'faz'
                    - 'fsa'
                    - 'fsw'
                    - 'fmg'
                    - 'fdd'
                    - 'fac'
                    - 'fpx'
                    - 'fna'
                    - 'fdc'
                    - 'ffw'
                    - 'fsr'
                    - 'fad'
                    - 'fap'
                    - 'fxt'
                    - 'fts'
                    - 'fai'
                    - 'fwc'
                    - 'fis'
                    - 'fed'
                    - 'fabric'
                    - 'fpa'
                    - 'fca'
                    - 'ftc'
            state:
                type: int
                description: State.
            uuid:
                type: str
                description: Uuid.
            create_time:
                type: int
                description: Create_Time.
            workspace_mode:
                type: int
                description: Workspace_Mode.
            tz:
                type: int
                description: No description.
            lock_override:
                type: int
                description: No description.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: ADOM table, most attributes are read-only and can only be changed internally.
      fortinet.fortimanager.fmgr_dvmdb_adom:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        state: present # <value in [present, absent]>
        dvmdb_adom:
          desc: <string>
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
            - install_deselect_all
          log_db_retention_hours: <integer>
          log_disk_quota: <integer>
          log_disk_quota_alert_thres: <integer>
          log_disk_quota_split_ratio: <integer>
          log_file_retention_hours: <integer>
          meta_fields: <dict>
          mig_mr: <integer>
          mig_os_ver: <value in [unknown, 0.0, 1.0, ...]>
          mode: <value in [ems, gms, provider]>
          mr: <integer>
          name: <string>
          os_ver: <value in [unknown, 0.0, 1.0, ...]>
          restricted_prds: # <list or string>
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
            - fis
            - fed
            - fabric
            - fpa
            - fca
            - ftc
          state: <integer>
          uuid: <string>
          create_time: <integer>
          workspace_mode: <integer>
          tz: <integer>
          lock_override: <integer>
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


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
        'dvmdb_adom': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'desc': {'type': 'str'},
                'flags': {
                    'type': 'list',
                    'choices': [
                        'migration', 'db_export', 'no_vpn_console', 'backup', 'other_devices', 'central_sdwan', 'is_autosync', 'per_device_wtp',
                        'policy_check_on_install', 'install_on_policy_check_fail', 'auto_push_cfg', 'per_device_fsw', 'install_deselect_all'
                    ],
                    'elements': 'str'
                },
                'log_db_retention_hours': {'type': 'int'},
                'log_disk_quota': {'type': 'int'},
                'log_disk_quota_alert_thres': {'type': 'int'},
                'log_disk_quota_split_ratio': {'type': 'int'},
                'log_file_retention_hours': {'type': 'int'},
                'meta fields': {'type': 'dict'},
                'mig_mr': {'type': 'int'},
                'mig_os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0'], 'type': 'str'},
                'mode': {'choices': ['ems', 'gms', 'provider'], 'type': 'str'},
                'mr': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'os_ver': {'choices': ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0', '8.0', '9.0'], 'type': 'str'},
                'restricted_prds': {
                    'type': 'raw',
                    'choices': [
                        'fos', 'foc', 'fml', 'fch', 'fwb', 'log', 'fct', 'faz', 'fsa', 'fsw', 'fmg', 'fdd', 'fac', 'fpx', 'fna', 'fdc', 'ffw', 'fsr',
                        'fad', 'fap', 'fxt', 'fts', 'fai', 'fwc', 'fis', 'fed', 'fabric', 'fpa', 'fca', 'ftc'
                    ]
                },
                'state': {'type': 'int'},
                'uuid': {'type': 'str'},
                'create_time': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'workspace_mode': {'v_range': [['6.4.3', '']], 'type': 'int'},
                'tz': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'lock_override': {'v_range': [['7.4.1', '']], 'type': 'int'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvmdb_adom'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
