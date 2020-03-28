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
module: fmgr_dvm_cmd_discover_device
short_description: Probe a remote device and retrieve its device information and system status.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ exec ] the following apis.
    - /dvm/cmd/discover/device
    - /dvm/cmd/discover/device
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
    schema_object0:
        methods: [exec]
        description: 'Probe a remote device and retrieve its device information and system status.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                device:
                    adm_pass:
                        type: str
                    adm_usr:
                        type: str
                    ip:
                        type: str

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

    - name: REQUESTING /DVM/CMD/DISCOVER/DEVICE
      fmgr_dvm_cmd_discover_device:
         method: <value in [exec]>
         params:
            -
               data:
                  device:
                     adm_pass: <value of string>
                     adm_usr: <value of string>
                     ip: <value of string>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[exec]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            device:
               adm_pass:
                  type: array
                  suboptions:
                     type: str
               adm_usr:
                  type: str
               app_ver:
                  type: str
               av_ver:
                  type: str
               beta:
                  type: int
               branch_pt:
                  type: int
               build:
                  type: int
               checksum:
                  type: str
               conf_status:
                  type: str
                  example: 'unknown'
               conn_mode:
                  type: str
                  example: 'passive'
               conn_status:
                  type: str
                  example: 'UNKNOWN'
               db_status:
                  type: str
                  example: 'unknown'
               desc:
                  type: str
               dev_status:
                  type: str
                  example: 'unknown'
               fap_cnt:
                  type: int
               faz.full_act:
                  type: int
               faz.perm:
                  type: int
               faz.quota:
                  type: int
               faz.used:
                  type: int
               fex_cnt:
                  type: int
               flags:
                  type: array
                  suboptions:
                     type: str
               foslic_cpu:
                  type: int
                  description: 'VM Meter vCPU count.'
               foslic_dr_site:
                  type: str
                  description: 'VM Meter DR Site status.'
                  example: 'disable'
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
                  description: 'VM Meter license type.'
                  example: 'temporary'
               foslic_utm:
                  type: array
                  suboptions:
                     type: str
               fsw_cnt:
                  type: int
               ha_group_id:
                  type: int
               ha_group_name:
                  type: str
               ha_mode:
                  type: str
                  description: 'enabled - Value reserved for non-FOS HA devices.'
                  example: 'standalone'
               ha_slave:
                  type: array
                  suboptions:
                     idx:
                        type: int
                     name:
                        type: str
                     prio:
                        type: int
                     role:
                        type: str
                        example: 'slave'
                     sn:
                        type: str
                     status:
                        type: int
               hdisk_size:
                  type: int
               hostname:
                  type: str
               hw_rev_major:
                  type: int
               hw_rev_minor:
                  type: int
               ip:
                  type: str
               ips_ext:
                  type: int
               ips_ver:
                  type: str
               last_checked:
                  type: int
               last_resync:
                  type: int
               latitude:
                  type: str
               lic_flags:
                  type: int
               lic_region:
                  type: str
               location_from:
                  type: str
               logdisk_size:
                  type: int
               longitude:
                  type: str
               maxvdom:
                  type: int
                  example: 10
               meta fields:
                  type: str
               mgmt_id:
                  type: int
               mgmt_if:
                  type: str
               mgmt_mode:
                  type: str
                  example: 'unreg'
               mgt_vdom:
                  type: str
               mr:
                  type: int
                  example: -1
               name:
                  type: str
                  description: 'Unique name for the device.'
               os_type:
                  type: str
                  example: 'unknown'
               os_ver:
                  type: str
                  example: 'unknown'
               patch:
                  type: int
               platform_str:
                  type: str
               psk:
                  type: str
               sn:
                  type: str
                  description: 'Unique value for each device.'
               vdom:
                  type: array
                  suboptions:
                     comments:
                        type: str
                     name:
                        type: str
                     opmode:
                        type: str
                        example: 'nat'
                     rtm_prof_id:
                        type: int
                     status:
                        type: str
               version:
                  type: int
               vm_cpu:
                  type: int
               vm_cpu_limit:
                  type: int
               vm_lic_expire:
                  type: int
               vm_mem:
                  type: int
               vm_mem_limit:
                  type: int
               vm_status:
                  type: int
            pid:
               type: int
               description: 'When "nonblocking" flag is set, return the process ID for the command.'
            taskid:
               type: str
               description: 'When "create_task" flag is set, return the ID of the task associated with the command.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/dvm/cmd/discover/device'

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
        '/dvm/cmd/discover/device',
        '/dvm/cmd/discover/device'
    ]

    url_schema = [
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'device': {
                            'adm_pass': {
                                'type': 'string'
                            },
                            'adm_usr': {
                                'type': 'string'
                            },
                            'ip': {
                                'type': 'string'
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
            ]
        },
        'method_mapping': {
            'exec': 'object0'
        }
    }

    module_arg_spec = {
        'loose_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'params': {
            'type': 'list',
            'required': False
        },
        'method': {
            'type': 'str',
            'required': True,
            'choices': [
                'exec'
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
        if loose_validation == False:
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
