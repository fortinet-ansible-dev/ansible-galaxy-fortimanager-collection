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
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
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
                choices: ['migration', 'db_export', 'no_vpn_console', 'backup', 'other_devices',
                          'central_sdwan', 'is_autosync', 'per_device_wtp',
                          'policy_check_on_install', 'install_on_policy_check_fail',
                          'auto_push_cfg', 'per_device_fsw', 'install_deselect_all']
            log_db_retention_hours:
                type: int
                description: Log db retention hours.
            log_disk_quota:
                type: int
                description: Log disk quota.
            log_disk_quota_alert_thres:
                type: int
                description: Log disk quota alert thres.
            log_disk_quota_split_ratio:
                type: int
                description: Log disk quota split ratio.
            log_file_retention_hours:
                type: int
                description: Log file retention hours.
            meta_fields:
                aliases: ['meta fields']
                type: dict
                description: Default metafields
            mig_mr:
                type: int
                description: Mig mr.
            mig_os_ver:
                type: str
                description: Mig os ver.
                choices: ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0',
                          '8.0', '9.0']
            mode:
                type: str
                description:
                    - ems -
                    - provider - Global database.
                choices: ['ems', 'gms', 'provider']
            mr:
                type: int
                description: Mr.
            name:
                type: str
                description: Name.
                required: true
            os_ver:
                type: str
                description: Os ver.
                choices: ['unknown', '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '6.0', '7.0',
                          '8.0', '9.0']
            restricted_prds:
                type: raw
                description: (list or str) Restricted prds.
                choices: ['fos', 'foc', 'fml', 'fch', 'fwb', 'log', 'fct', 'faz', 'fsa', 'fsw',
                          'fmg', 'fdd', 'fac', 'fpx', 'fna', 'fdc', 'ffw', 'fsr', 'fad', 'fap',
                          'fxt', 'fts', 'fai', 'fwc', 'fis', 'fed', 'fabric', 'fpa', 'fca', 'ftc',
                          'fss', 'sim', 'fra']
            state:
                type: int
                description: State.
            uuid:
                type: str
                description: Uuid.
            create_time:
                type: int
                description: Create time.
            workspace_mode:
                type: int
                description: Workspace mode.
            tz:
                type: int
                description: Tz.
            lock_override:
                type: int
                description: Lock override.
            primary_dns_ip4:
                type: str
                description: Primary dns ip4.
            primary_dns_ip6_1:
                type: int
                description: Primary dns ip6 1.
            primary_dns_ip6_2:
                type: int
                description: Primary dns ip6 2.
            primary_dns_ip6_3:
                type: int
                description: Primary dns ip6 3.
            primary_dns_ip6_4:
                type: int
                description: Primary dns ip6 4.
            secondary_dns_ip4:
                type: str
                description: Secondary dns ip4.
            secondary_dns_ip6_1:
                type: int
                description: Secondary dns ip6 1.
            secondary_dns_ip6_2:
                type: int
                description: Secondary dns ip6 2.
            secondary_dns_ip6_3:
                type: int
                description: Secondary dns ip6 3.
            secondary_dns_ip6_4:
                type: int
                description: Secondary dns ip6 4.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: ADOM table, most attributes are read-only and can only be changed internally.
      fortinet.fortimanager.fmgr_dvmdb_adom:
        # workspace_locking_adom: <global or your adom name>
        state: present # <value in [present, absent]>
        dvmdb_adom:
          name: "your value" # Required variable, string
          # desc: <string>
          # flags: ["migration", "db_export", "no_vpn_console", "backup", "other_devices",
          #         "central_sdwan", "is_autosync", "per_device_wtp", "policy_check_on_install",
          #         "install_on_policy_check_fail", "auto_push_cfg", "per_device_fsw",
          #         "install_deselect_all"]
          # log_db_retention_hours: <integer>
          # log_disk_quota: <integer>
          # log_disk_quota_alert_thres: <integer>
          # log_disk_quota_split_ratio: <integer>
          # log_file_retention_hours: <integer>
          # meta_fields: <dict>
          # mig_mr: <integer>
          # mig_os_ver: <value in [unknown, 0.0, 1.0, ...]>
          # mode: <value in [ems, gms, provider]>
          # mr: <integer>
          # os_ver: <value in [unknown, 0.0, 1.0, ...]>
          # restricted_prds: ["fos", "foc", "fml", "fch", "fwb", "log", "fct", "faz", "fsa",
          #                   "fsw", "fmg", "fdd", "fac", "fpx", "fna", "fdc", "ffw", "fsr",
          #                   "fad", "fap", "fxt", "fts", "fai", "fwc", "fis", "fed", "fabric",
          #                   "fpa", "fca", "ftc", "fss", "sim", "fra"]
          # state: <integer>
          # uuid: <string>
          # create_time: <integer>
          # workspace_mode: <integer>
          # tz: <integer>
          # lock_override: <integer>
          # primary_dns_ip4: <string>
          # primary_dns_ip6_1: <integer>
          # primary_dns_ip6_2: <integer>
          # primary_dns_ip6_3: <integer>
          # primary_dns_ip6_4: <integer>
          # secondary_dns_ip4: <string>
          # secondary_dns_ip6_1: <integer>
          # secondary_dns_ip6_2: <integer>
          # secondary_dns_ip6_3: <integer>
          # secondary_dns_ip6_4: <integer>
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/dvmdb/adom'
    ]
    module_arg_spec = {
        'dvmdb_adom': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
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
                        'fad', 'fap', 'fxt', 'fts', 'fai', 'fwc', 'fis', 'fed', 'fabric', 'fpa', 'fca', 'ftc', 'fss', 'sim', 'fra'
                    ]
                },
                'state': {'type': 'int'},
                'uuid': {'type': 'str'},
                'create_time': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'workspace_mode': {'v_range': [['6.4.3', '']], 'type': 'int'},
                'tz': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'lock_override': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'primary_dns_ip4': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'primary_dns_ip6_1': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'primary_dns_ip6_2': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'primary_dns_ip6_3': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'primary_dns_ip6_4': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'secondary_dns_ip4': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'secondary_dns_ip6_1': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'secondary_dns_ip6_2': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'secondary_dns_ip6_3': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'secondary_dns_ip6_4': {'v_range': [['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvmdb_adom'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
