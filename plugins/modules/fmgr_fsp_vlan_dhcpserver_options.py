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
module: fmgr_fsp_vlan_dhcpserver_options
short_description: DHCP options.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    vlan:
        description: The parameter (vlan) in requested url.
        type: str
        required: true
    fsp_vlan_dhcpserver_options:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            code:
                type: int
                description: Code.
            id:
                type: int
                description: Id.
                required: true
            ip:
                type: raw
                description: (list) Ip.
            type:
                type: str
                description: Type.
                choices: ['hex', 'string', 'ip', 'fqdn']
            value:
                type: str
                description: Value.
            vci_match:
                aliases: ['vci-match']
                type: str
                description: Enable/disable vendor class identifier
                choices: ['disable', 'enable']
            vci_string:
                aliases: ['vci-string']
                type: raw
                description: (list) One or more VCI strings in quotes separated by spaces.
            uci_match:
                aliases: ['uci-match']
                type: str
                description: Enable/disable user class identifier
                choices: ['disable', 'enable']
            uci_string:
                aliases: ['uci-string']
                type: raw
                description: (list) One or more UCI strings in quotes separated by spaces.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: DHCP options.
      fortinet.fortimanager.fmgr_fsp_vlan_dhcpserver_options:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        vlan: <your own value>
        state: present # <value in [present, absent]>
        fsp_vlan_dhcpserver_options:
          id: 0 # Required variable, integer
          # code: <integer>
          # ip: <list or string>
          # type: <value in [hex, string, ip, ...]>
          # value: <string>
          # vci_match: <value in [disable, enable]>
          # vci_string: <list or string>
          # uci_match: <value in [disable, enable]>
          # uci_string: <list or string>
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
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/options',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/options'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vlan': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fsp_vlan_dhcpserver_options': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'code': {'type': 'int'},
                'id': {'required': True, 'type': 'int'},
                'ip': {'type': 'raw'},
                'type': {'choices': ['hex', 'string', 'ip', 'fqdn'], 'type': 'str'},
                'value': {'type': 'str'},
                'vci-match': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vci-string': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'uci-match': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uci-string': {'v_range': [['7.2.2', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_dhcpserver_options'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
