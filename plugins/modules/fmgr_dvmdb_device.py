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
module: fmgr_dvmdb_device
short_description: Device table, most attributes are read-only and can only be changed internally. Refer to Device Manager Command module for API to add, d...
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
    device:
        description: the parameter (device) in requested url
        type: str
        required: true
    dvmdb_device:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            adm_pass:
                description: no description
                type: str
            adm_usr:
                type: str
                description: no description
            app_ver:
                type: str
                description: no description
            av_ver:
                type: str
                description: no description
            beta:
                type: int
                description: no description
            branch_pt:
                type: int
                description: no description
            build:
                type: int
                description: no description
            checksum:
                type: str
                description: no description
            conf_status:
                type: str
                default: 'unknown'
                description: no description
                choices:
                    - 'unknown'
                    - 'insync'
                    - 'outofsync'
            conn_mode:
                type: str
                default: 'passive'
                description: no description
                choices:
                    - 'active'
                    - 'passive'
            conn_status:
                type: str
                default: 'UNKNOWN'
                description: no description
                choices:
                    - 'UNKNOWN'
                    - 'up'
                    - 'down'
            db_status:
                type: str
                default: 'unknown'
                description: no description
                choices:
                    - 'unknown'
                    - 'nomod'
                    - 'mod'
            desc:
                type: str
                description: no description
            dev_status:
                type: str
                default: 'unknown'
                description: no description
                choices:
                    - 'none'
                    - 'unknown'
                    - 'checkedin'
                    - 'inprogress'
                    - 'installed'
                    - 'aborted'
                    - 'sched'
                    - 'retry'
                    - 'canceled'
                    - 'pending'
                    - 'retrieved'
                    - 'changed_conf'
                    - 'sync_fail'
                    - 'timeout'
                    - 'rev_revert'
                    - 'auto_updated'
            fap_cnt:
                type: int
                description: no description
            faz.full_act:
                type: int
                description: no description
            faz.perm:
                type: int
                description: no description
            faz.quota:
                type: int
                description: no description
            faz.used:
                type: int
                description: no description
            fex_cnt:
                type: int
                description: no description
            flags:
                description: no description
                type: list
                choices:
                 - has_hdd
                 - vdom_enabled
                 - discover
                 - reload
                 - interim_build
                 - offline_mode
                 - is_model
                 - fips_mode
                 - linked_to_model
                 - ip-conflict
                 - faz-autosync
            foslic_cpu:
                type: int
                description: 'VM Meter vCPU count.'
            foslic_dr_site:
                type: str
                default: 'disable'
                description: 'VM Meter DR Site status.'
                choices:
                    - 'disable'
                    - 'enable'
            foslic_inst_time:
                type: int
                description: 'VM Meter first deployment time (in UNIX timestamp).'
            foslic_last_sync:
                type: int
                description: 'VM Meter last synchronized time (in UNIX timestamp).'
            foslic_ram:
                type: int
                description: 'VM Meter device RAM size (in MB).'
            foslic_type:
                type: str
                default: 'temporary'
                description: 'VM Meter license type.'
                choices:
                    - 'temporary'
                    - 'trial'
                    - 'regular'
                    - 'trial_expired'
            foslic_utm:
                description: no description
                type: list
                choices:
                 - fw
                 - av
                 - ips
                 - app
                 - url
                 - utm
                 - fwb
            fsw_cnt:
                type: int
                description: no description
            ha_group_id:
                type: int
                description: no description
            ha_group_name:
                type: str
                description: no description
            ha_mode:
                type: str
                default: 'standalone'
                description: 'enabled - Value reserved for non-FOS HA devices.'
                choices:
                    - 'standalone'
                    - 'AP'
                    - 'AA'
                    - 'ELBC'
                    - 'DUAL'
                    - 'enabled'
                    - 'unknown'
                    - 'fmg-enabled'
                    - 'autoscale'
            hdisk_size:
                type: int
                description: no description
            hostname:
                type: str
                description: no description
            hw_rev_major:
                type: int
                description: no description
            hw_rev_minor:
                type: int
                description: no description
            ip:
                type: str
                description: no description
            ips_ext:
                type: int
                description: no description
            ips_ver:
                type: str
                description: no description
            last_checked:
                type: int
                description: no description
            last_resync:
                type: int
                description: no description
            latitude:
                type: str
                description: no description
            lic_flags:
                type: int
                description: no description
            lic_region:
                type: str
                description: no description
            location_from:
                type: str
                description: no description
            logdisk_size:
                type: int
                description: no description
            longitude:
                type: str
                description: no description
            maxvdom:
                type: int
                default: 10
                description: no description
            meta fields:
                description: no description
                type: dict
            mgmt_id:
                type: int
                description: no description
            mgmt_if:
                type: str
                description: no description
            mgmt_mode:
                type: str
                default: 'unreg'
                description: no description
                choices:
                    - 'unreg'
                    - 'fmg'
                    - 'faz'
                    - 'fmgfaz'
            mgt_vdom:
                type: str
                description: no description
            mr:
                type: int
                default: -1
                description: no description
            name:
                type: str
                description: 'Unique name for the device.'
            os_type:
                type: str
                default: 'unknown'
                description: no description
                choices:
                    - 'unknown'
                    - 'fos'
                    - 'fsw'
                    - 'foc'
                    - 'fml'
                    - 'faz'
                    - 'fwb'
                    - 'fch'
                    - 'fct'
                    - 'log'
                    - 'fmg'
                    - 'fsa'
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
            os_ver:
                type: str
                default: 'unknown'
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
            patch:
                type: int
                description: no description
            platform_str:
                type: str
                description: no description
            psk:
                type: str
                description: no description
            sn:
                type: str
                description: 'Unique value for each device.'
            vdom:
                description: no description
                type: list
                suboptions:
                    comments:
                        type: str
                        description: no description
                    name:
                        type: str
                        description: no description
                    opmode:
                        type: str
                        default: 'nat'
                        description: no description
                        choices:
                            - 'nat'
                            - 'transparent'
                    rtm_prof_id:
                        type: int
                        description: no description
                    status:
                        type: str
                        description: no description
                    vpn_id:
                        type: int
                        description: no description
                    meta fields:
                        description: no description
                        type: dict
            version:
                type: int
                description: no description
            vm_cpu:
                type: int
                description: no description
            vm_cpu_limit:
                type: int
                description: no description
            vm_lic_expire:
                type: int
                description: no description
            vm_mem:
                type: int
                description: no description
            vm_mem_limit:
                type: int
                description: no description
            vm_status:
                type: int
                description: no description
            module_sn:
                type: str
                description: no description
            prefer_img_ver:
                type: str
                description: no description
            prio:
                type: int
                description: no description
            role:
                type: str
                default: 'master'
                description: no description
                choices:
                    - 'master'
                    - 'ha-slave'
                    - 'autoscale-slave'
            hyperscale:
                type: int
                description: no description
            nsxt_service_name:
                type: str
                description: no description
            private_key:
                type: str
                description: no description
            private_key_status:
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
    - name: Device table, most attributes are read-only and can only be changed internally. Refer to Device Manager Command module for API to add, d...
      fmgr_dvmdb_device:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         device: <your own value>
         dvmdb_device:
            adm_pass: <value of string>
            adm_usr: <value of string>
            app_ver: <value of string>
            av_ver: <value of string>
            beta: <value of integer>
            branch_pt: <value of integer>
            build: <value of integer>
            checksum: <value of string>
            conf_status: <value in [unknown, insync, outofsync]>
            conn_mode: <value in [active, passive]>
            conn_status: <value in [UNKNOWN, up, down]>
            db_status: <value in [unknown, nomod, mod]>
            desc: <value of string>
            dev_status: <value in [none, unknown, checkedin, ...]>
            fap_cnt: <value of integer>
            faz.full_act: <value of integer>
            faz.perm: <value of integer>
            faz.quota: <value of integer>
            faz.used: <value of integer>
            fex_cnt: <value of integer>
            flags:
              - has_hdd
              - vdom_enabled
              - discover
              - reload
              - interim_build
              - offline_mode
              - is_model
              - fips_mode
              - linked_to_model
              - ip-conflict
              - faz-autosync
            foslic_cpu: <value of integer>
            foslic_dr_site: <value in [disable, enable]>
            foslic_inst_time: <value of integer>
            foslic_last_sync: <value of integer>
            foslic_ram: <value of integer>
            foslic_type: <value in [temporary, trial, regular, ...]>
            foslic_utm:
              - fw
              - av
              - ips
              - app
              - url
              - utm
              - fwb
            fsw_cnt: <value of integer>
            ha_group_id: <value of integer>
            ha_group_name: <value of string>
            ha_mode: <value in [standalone, AP, AA, ...]>
            hdisk_size: <value of integer>
            hostname: <value of string>
            hw_rev_major: <value of integer>
            hw_rev_minor: <value of integer>
            ip: <value of string>
            ips_ext: <value of integer>
            ips_ver: <value of string>
            last_checked: <value of integer>
            last_resync: <value of integer>
            latitude: <value of string>
            lic_flags: <value of integer>
            lic_region: <value of string>
            location_from: <value of string>
            logdisk_size: <value of integer>
            longitude: <value of string>
            maxvdom: <value of integer>
            meta fields: <value of dict>
            mgmt_id: <value of integer>
            mgmt_if: <value of string>
            mgmt_mode: <value in [unreg, fmg, faz, ...]>
            mgt_vdom: <value of string>
            mr: <value of integer>
            name: <value of string>
            os_type: <value in [unknown, fos, fsw, ...]>
            os_ver: <value in [unknown, 0.0, 1.0, ...]>
            patch: <value of integer>
            platform_str: <value of string>
            psk: <value of string>
            sn: <value of string>
            vdom:
              -
                  comments: <value of string>
                  name: <value of string>
                  opmode: <value in [nat, transparent]>
                  rtm_prof_id: <value of integer>
                  status: <value of string>
                  vpn_id: <value of integer>
                  meta fields: <value of dict>
            version: <value of integer>
            vm_cpu: <value of integer>
            vm_cpu_limit: <value of integer>
            vm_lic_expire: <value of integer>
            vm_mem: <value of integer>
            vm_mem_limit: <value of integer>
            vm_status: <value of integer>
            module_sn: <value of string>
            prefer_img_ver: <value of string>
            prio: <value of integer>
            role: <value in [master, ha-slave, autoscale-slave]>
            hyperscale: <value of integer>
            nsxt_service_name: <value of string>
            private_key: <value of string>
            private_key_status: <value of integer>

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
        '/dvmdb/adom/{adom}/device/{device}',
        '/dvmdb/device/{device}'
    ]

    perobject_jrpc_urls = [
        '/dvmdb/adom/{adom}/device/{device}',
        '/dvmdb/device/{device}'
    ]

    url_params = ['adom', 'device']
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
        'device': {
            'required': True,
            'type': 'str'
        },
        'dvmdb_device': {
            'required': False,
            'type': 'dict',
            'options': {
                'adm_pass': {
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
                'adm_usr': {
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
                'app_ver': {
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
                'av_ver': {
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
                'beta': {
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
                    'type': 'int'
                },
                'branch_pt': {
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
                    'type': 'int'
                },
                'build': {
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
                    'type': 'int'
                },
                'checksum': {
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
                'conf_status': {
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
                        'unknown',
                        'insync',
                        'outofsync'
                    ],
                    'type': 'str'
                },
                'conn_mode': {
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
                        'active',
                        'passive'
                    ],
                    'type': 'str'
                },
                'conn_status': {
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
                        'UNKNOWN',
                        'up',
                        'down'
                    ],
                    'type': 'str'
                },
                'db_status': {
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
                        'unknown',
                        'nomod',
                        'mod'
                    ],
                    'type': 'str'
                },
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
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'dev_status': {
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
                        'unknown',
                        'checkedin',
                        'inprogress',
                        'installed',
                        'aborted',
                        'sched',
                        'retry',
                        'canceled',
                        'pending',
                        'retrieved',
                        'changed_conf',
                        'sync_fail',
                        'timeout',
                        'rev_revert',
                        'auto_updated'
                    ],
                    'type': 'str'
                },
                'fap_cnt': {
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
                    'type': 'int'
                },
                'faz.full_act': {
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
                    'type': 'int'
                },
                'faz.perm': {
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
                    'type': 'int'
                },
                'faz.quota': {
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
                    'type': 'int'
                },
                'faz.used': {
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
                    'type': 'int'
                },
                'fex_cnt': {
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
                    'type': 'int'
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
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'has_hdd',
                        'vdom_enabled',
                        'discover',
                        'reload',
                        'interim_build',
                        'offline_mode',
                        'is_model',
                        'fips_mode',
                        'linked_to_model',
                        'ip-conflict',
                        'faz-autosync'
                    ]
                },
                'foslic_cpu': {
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
                    'type': 'int'
                },
                'foslic_dr_site': {
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
                'foslic_inst_time': {
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
                    'type': 'int'
                },
                'foslic_last_sync': {
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
                    'type': 'int'
                },
                'foslic_ram': {
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
                    'type': 'int'
                },
                'foslic_type': {
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
                        'temporary',
                        'trial',
                        'regular',
                        'trial_expired'
                    ],
                    'type': 'str'
                },
                'foslic_utm': {
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
                        'fw',
                        'av',
                        'ips',
                        'app',
                        'url',
                        'utm',
                        'fwb'
                    ]
                },
                'fsw_cnt': {
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
                    'type': 'int'
                },
                'ha_group_id': {
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
                    'type': 'int'
                },
                'ha_group_name': {
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
                'ha_mode': {
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
                        'standalone',
                        'AP',
                        'AA',
                        'ELBC',
                        'DUAL',
                        'enabled',
                        'unknown',
                        'fmg-enabled',
                        'autoscale'
                    ],
                    'type': 'str'
                },
                'hdisk_size': {
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
                    'type': 'int'
                },
                'hostname': {
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
                'hw_rev_major': {
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
                    'type': 'int'
                },
                'hw_rev_minor': {
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
                    'type': 'int'
                },
                'ip': {
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
                'ips_ext': {
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
                    'type': 'int'
                },
                'ips_ver': {
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
                'last_checked': {
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
                    'type': 'int'
                },
                'last_resync': {
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
                    'type': 'int'
                },
                'latitude': {
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
                'lic_flags': {
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
                    'type': 'int'
                },
                'lic_region': {
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
                'location_from': {
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
                'logdisk_size': {
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
                    'type': 'int'
                },
                'longitude': {
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
                'maxvdom': {
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
                        '7.0.0': True
                    },
                    'type': 'dict'
                },
                'mgmt_id': {
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
                    'type': 'int'
                },
                'mgmt_if': {
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
                'mgmt_mode': {
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
                        'unreg',
                        'fmg',
                        'faz',
                        'fmgfaz'
                    ],
                    'type': 'str'
                },
                'mgt_vdom': {
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
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'name': {
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
                'os_type': {
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
                        'unknown',
                        'fos',
                        'fsw',
                        'foc',
                        'fml',
                        'faz',
                        'fwb',
                        'fch',
                        'fct',
                        'log',
                        'fmg',
                        'fsa',
                        'fdd',
                        'fac',
                        'fpx',
                        'fna',
                        'fdc',
                        'ffw',
                        'fsr',
                        'fad',
                        'fap',
                        'fxt'
                    ],
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
                        '7.0.0': True
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
                'patch': {
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
                    'type': 'int'
                },
                'platform_str': {
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
                'psk': {
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
                'sn': {
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
                'vdom': {
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
                        'comments': {
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
                        'name': {
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
                        'opmode': {
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
                                'nat',
                                'transparent'
                            ],
                            'type': 'str'
                        },
                        'rtm_prof_id': {
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
                            'type': 'int'
                        },
                        'status': {
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
                        'vpn_id': {
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
                        'meta fields': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'dict'
                        }
                    }
                },
                'version': {
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
                    'type': 'int'
                },
                'vm_cpu': {
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
                    'type': 'int'
                },
                'vm_cpu_limit': {
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
                    'type': 'int'
                },
                'vm_lic_expire': {
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
                    'type': 'int'
                },
                'vm_mem': {
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
                    'type': 'int'
                },
                'vm_mem_limit': {
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
                    'type': 'int'
                },
                'vm_status': {
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
                    'type': 'int'
                },
                'module_sn': {
                    'required': False,
                    'revision': {
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
                'prefer_img_ver': {
                    'required': False,
                    'revision': {
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
                'prio': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'role': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'master',
                        'ha-slave',
                        'autoscale-slave'
                    ],
                    'type': 'str'
                },
                'hyperscale': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'nsxt_service_name': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'private_key': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'private_key_status': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvmdb_device'),
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
