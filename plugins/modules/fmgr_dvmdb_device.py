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
module: fmgr_dvmdb_device
short_description: Device table, most attributes are read-only and can only be changed internally. Refer to Device Manager Command module for API to add, d...
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ get set update ] the following apis.
    - /dvmdb/adom/{adom}/device
    - /dvmdb/device
    - Examples include all parameters and values need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Frank Shen (@fshen01)
    - Link Zheng (@zhengl)
notes:
    - There are only three top-level parameters where 'method' is always required
      while other two 'params' and 'url_params' can be optional
    - Due to the complexity of fortimanager api schema, the validation is done
      out of Ansible native parameter validation procedure.
    - The syntax of OPTIONS doen not comply with the standard Ansible argument
      specification, but with the structure of fortimanager API schema, we need
      a trivial transformation when we are filling the ansible playbook
options:
    loose_validation:
        description:
          - Do parameter validation in a loose way
        type: bool
        required: false
    workspace_locking_adom:
        description:
          - the adom name to lock in case FortiManager running in workspace mode
          - it can be global or any other custom adom names
        required: false
        type: str
    workspace_locking_timeout:
        description:
          - the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    method:
        description:
          - The method in request
        required: true
        type: str
        choices:
          - get
          - set
          - update
    params:
        description:
          - The parameters for each method
          - See full parameters list in https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/latest
        type: list
        required: false
    url_params:
        description:
          - The parameters for each API request URL
          - Also see full URL parameters in https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/latest
        required: false
        type: dict

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

    - name: REQUESTING /DVMDB/DEVICE
      fmgr_dvmdb_device:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               expand member: <value of string>
               fields:
                 -
                    - <value in [adm_pass, adm_usr, app_ver, ...]>
               filter:
                 - <value of string>
               loadsub: <value of integer>
               meta fields:
                 - <value of string>
               option: <value in [count, object member, syntax]>
               range:
                 - <value of integer>
               sortings:
                 -
                     varidic.attr_name: <value in [1, -1]>

    - name: REQUESTING /DVMDB/DEVICE
      fmgr_dvmdb_device:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               data:
                 -
                     adm_pass:
                       - <value of string>
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
                       - <value in [has_hdd, vdom_enabled, discover, ...]>
                     foslic_cpu: <value of integer>
                     foslic_dr_site: <value in [disable, enable]>
                     foslic_inst_time: <value of integer>
                     foslic_last_sync: <value of integer>
                     foslic_ram: <value of integer>
                     foslic_type: <value in [temporary, trial, regular, ...]>
                     foslic_utm:
                       - <value in [fw, av, ips, ...]>
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
                     meta fields: <value of string>
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
                     version: <value of integer>
                     vm_cpu: <value of integer>
                     vm_cpu_limit: <value of integer>
                     vm_lic_expire: <value of integer>
                     vm_mem: <value of integer>
                     vm_mem_limit: <value of integer>
                     vm_status: <value of integer>

'''

RETURN = '''
url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
status:
    description: The status of api request
    returned: always
    type: dict
data:
    description: The payload returned in the request
    type: dict
    returned: always

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FAIL_SOCKET_MSG
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import DEFAULT_RESULT_OBJ
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGRCommon
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGBaseException
from ansible_collections.fortinet.fortimanager.plugins.module_utils.fortimanager import FortiManagerHandler


def main():
    jrpc_urls = [
        '/dvmdb/adom/{adom}/device',
        '/dvmdb/device'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        }
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'type': 'string',
                    'name': 'expand member',
                    'api_tag': 0
                },
                {
                    'name': 'fields',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'enum': [
                                'adm_pass',
                                'adm_usr',
                                'app_ver',
                                'av_ver',
                                'beta',
                                'branch_pt',
                                'build',
                                'checksum',
                                'conf_status',
                                'conn_mode',
                                'conn_status',
                                'db_status',
                                'desc',
                                'dev_status',
                                'fap_cnt',
                                'faz.full_act',
                                'faz.perm',
                                'faz.quota',
                                'faz.used',
                                'fex_cnt',
                                'flags',
                                'foslic_cpu',
                                'foslic_dr_site',
                                'foslic_inst_time',
                                'foslic_last_sync',
                                'foslic_ram',
                                'foslic_type',
                                'foslic_utm',
                                'fsw_cnt',
                                'ha_group_id',
                                'ha_group_name',
                                'ha_mode',
                                'hdisk_size',
                                'hostname',
                                'hw_rev_major',
                                'hw_rev_minor',
                                'ip',
                                'ips_ext',
                                'ips_ver',
                                'last_checked',
                                'last_resync',
                                'latitude',
                                'lic_flags',
                                'lic_region',
                                'location_from',
                                'logdisk_size',
                                'longitude',
                                'maxvdom',
                                'mgmt_id',
                                'mgmt_if',
                                'mgmt_mode',
                                'mgt_vdom',
                                'mr',
                                'name',
                                'os_type',
                                'os_ver',
                                'patch',
                                'platform_str',
                                'psk',
                                'sn',
                                'version',
                                'vm_cpu',
                                'vm_cpu_limit',
                                'vm_lic_expire',
                                'vm_mem',
                                'vm_mem_limit',
                                'vm_status'
                            ]
                        }
                    }
                },
                {
                    'name': 'filter',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'example': [
                                '<attr>',
                                '==',
                                'test'
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'integer',
                    'name': 'loadsub',
                    'api_tag': 0
                },
                {
                    'name': 'meta fields',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'count',
                            'object member',
                            'syntax'
                        ]
                    },
                    'api_tag': 0
                },
                {
                    'name': 'range',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            'type': 'integer',
                            'example': [
                                2,
                                5
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'name': 'sortings',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            '{attr_name}': {
                                'type': 'integer',
                                'enum': [
                                    1,
                                    -1
                                ]
                            }
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object1': [
                {
                    'name': 'data',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'adm_pass': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'adm_usr': {
                            'type': 'string'
                        },
                        'app_ver': {
                            'type': 'string'
                        },
                        'av_ver': {
                            'type': 'string'
                        },
                        'beta': {
                            'type': 'integer'
                        },
                        'branch_pt': {
                            'type': 'integer'
                        },
                        'build': {
                            'type': 'integer'
                        },
                        'checksum': {
                            'type': 'string'
                        },
                        'conf_status': {
                            'type': 'string',
                            'enum': [
                                'unknown',
                                'insync',
                                'outofsync'
                            ]
                        },
                        'conn_mode': {
                            'type': 'string',
                            'enum': [
                                'active',
                                'passive'
                            ]
                        },
                        'conn_status': {
                            'type': 'string',
                            'enum': [
                                'UNKNOWN',
                                'up',
                                'down'
                            ]
                        },
                        'db_status': {
                            'type': 'string',
                            'enum': [
                                'unknown',
                                'nomod',
                                'mod'
                            ]
                        },
                        'desc': {
                            'type': 'string'
                        },
                        'dev_status': {
                            'type': 'string',
                            'enum': [
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
                            ]
                        },
                        'fap_cnt': {
                            'type': 'integer'
                        },
                        'faz.full_act': {
                            'type': 'integer'
                        },
                        'faz.perm': {
                            'type': 'integer'
                        },
                        'faz.quota': {
                            'type': 'integer'
                        },
                        'faz.used': {
                            'type': 'integer'
                        },
                        'fex_cnt': {
                            'type': 'integer'
                        },
                        'flags': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
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
                            }
                        },
                        'foslic_cpu': {
                            'type': 'integer'
                        },
                        'foslic_dr_site': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'foslic_inst_time': {
                            'type': 'integer'
                        },
                        'foslic_last_sync': {
                            'type': 'integer'
                        },
                        'foslic_ram': {
                            'type': 'integer'
                        },
                        'foslic_type': {
                            'type': 'string',
                            'enum': [
                                'temporary',
                                'trial',
                                'regular',
                                'trial_expired'
                            ]
                        },
                        'foslic_utm': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'fw',
                                    'av',
                                    'ips',
                                    'app',
                                    'url',
                                    'utm',
                                    'fwb'
                                ]
                            }
                        },
                        'fsw_cnt': {
                            'type': 'integer'
                        },
                        'ha_group_id': {
                            'type': 'integer'
                        },
                        'ha_group_name': {
                            'type': 'string'
                        },
                        'ha_mode': {
                            'type': 'string',
                            'enum': [
                                'standalone',
                                'AP',
                                'AA',
                                'ELBC',
                                'DUAL',
                                'enabled',
                                'unknown'
                            ]
                        },
                        'hdisk_size': {
                            'type': 'integer'
                        },
                        'hostname': {
                            'type': 'string'
                        },
                        'hw_rev_major': {
                            'type': 'integer'
                        },
                        'hw_rev_minor': {
                            'type': 'integer'
                        },
                        'ip': {
                            'type': 'string'
                        },
                        'ips_ext': {
                            'type': 'integer'
                        },
                        'ips_ver': {
                            'type': 'string'
                        },
                        'last_checked': {
                            'type': 'integer'
                        },
                        'last_resync': {
                            'type': 'integer'
                        },
                        'latitude': {
                            'type': 'string'
                        },
                        'lic_flags': {
                            'type': 'integer'
                        },
                        'lic_region': {
                            'type': 'string'
                        },
                        'location_from': {
                            'type': 'string'
                        },
                        'logdisk_size': {
                            'type': 'integer'
                        },
                        'longitude': {
                            'type': 'string'
                        },
                        'maxvdom': {
                            'type': 'integer',
                            'default': 10,
                            'example': 10
                        },
                        'meta fields': {
                            'type': 'string'
                        },
                        'mgmt_id': {
                            'type': 'integer'
                        },
                        'mgmt_if': {
                            'type': 'string'
                        },
                        'mgmt_mode': {
                            'type': 'string',
                            'enum': [
                                'unreg',
                                'fmg',
                                'faz',
                                'fmgfaz'
                            ]
                        },
                        'mgt_vdom': {
                            'type': 'string'
                        },
                        'mr': {
                            'type': 'integer',
                            'default': -1,
                            'example': -1
                        },
                        'name': {
                            'type': 'string'
                        },
                        'os_type': {
                            'type': 'string',
                            'enum': [
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
                                'fpx'
                            ]
                        },
                        'os_ver': {
                            'type': 'string',
                            'enum': [
                                'unknown',
                                '0.0',
                                '1.0',
                                '2.0',
                                '3.0',
                                '4.0',
                                '5.0',
                                '6.0'
                            ]
                        },
                        'patch': {
                            'type': 'integer'
                        },
                        'platform_str': {
                            'type': 'string'
                        },
                        'psk': {
                            'type': 'string'
                        },
                        'sn': {
                            'type': 'string'
                        },
                        'vdom': {
                            'type': 'array',
                            'items': {
                                'comments': {
                                    'type': 'string'
                                },
                                'name': {
                                    'type': 'string'
                                },
                                'opmode': {
                                    'type': 'string',
                                    'enum': [
                                        'nat',
                                        'transparent'
                                    ]
                                },
                                'rtm_prof_id': {
                                    'type': 'integer'
                                },
                                'status': {
                                    'type': 'string'
                                }
                            }
                        },
                        'version': {
                            'type': 'integer'
                        },
                        'vm_cpu': {
                            'type': 'integer'
                        },
                        'vm_cpu_limit': {
                            'type': 'integer'
                        },
                        'vm_lic_expire': {
                            'type': 'integer'
                        },
                        'vm_mem': {
                            'type': 'integer'
                        },
                        'vm_mem_limit': {
                            'type': 'integer'
                        },
                        'vm_status': {
                            'type': 'integer'
                        }
                    }
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ]
        },
        'method_mapping': {
            'get': 'object0',
            'set': 'object1',
            'update': 'object1'
        }
    }

    module_arg_spec = {
        'loose_validation': {
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
        'params': {
            'type': 'list',
            'required': False
        },
        'method': {
            'type': 'str',
            'required': True,
            'choices': [
                'get',
                'set',
                'update'
            ]
        },
        'url_params': {
            'type': 'dict',
            'required': False
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    method = module.params['method']
    loose_validation = module.params['loose_validation']

    fmgr = None
    payload = None
    response = DEFAULT_RESULT_OBJ

    if module._socket_path:
        connection = Connection(module._socket_path)
        tools = FMGRCommon()
        if loose_validation is False:
            tools.validate_module_params(module, body_schema)
        tools.validate_module_url_params(module, jrpc_urls, url_schema)
        full_url = tools.get_full_url_path(module, jrpc_urls)
        payload = tools.get_full_payload(module, full_url)
        fmgr = FortiManagerHandler(connection, module)
        fmgr.tools = tools
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    try:
        response = fmgr._conn.send_request(method, payload)
        fmgr.govern_response(module=module, results=response,
                             msg='Operation Finished',
                             ansible_facts=fmgr.construct_ansible_facts(response, module.params, module.params))
    except Exception as e:
        raise FMGBaseException(e)

    module.exit_json(meta=response[1])


if __name__ == '__main__':
    main()
