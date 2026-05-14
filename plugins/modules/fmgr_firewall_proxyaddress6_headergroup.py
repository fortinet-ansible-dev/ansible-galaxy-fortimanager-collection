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
module: fmgr_firewall_proxyaddress6_headergroup
short_description: Firewall proxy address6 header group
version_added: "2.12.0"
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
    proxy-address6:
        description: Deprecated, please use "proxy_address6"
        type: str
    proxy_address6:
        description: The parameter (proxy-address6) in requested url.
        type: str
    firewall_proxyaddress6_headergroup:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            case_sensitivity:
                aliases: ['case-sensitivity']
                type: str
                description: Case sensitivity.
                choices: ['disable', 'enable']
            header:
                type: str
                description: Header.
            header_name:
                aliases: ['header-name']
                type: str
                description: Header name.
            id:
                type: int
                description: Id.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Firewall proxy address6 header group
      fortinet.fortimanager.fmgr_firewall_proxyaddress6_headergroup:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        proxy_address6: <your own value>
        state: present # <value in [present, absent]>
        firewall_proxyaddress6_headergroup:
          id: 0 # Required variable, integer
          # case_sensitivity: <value in [disable, enable]>
          # header: <string>
          # header_name: <string>
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
        '/pm/config/adom/{adom}/obj/firewall/proxy-address6/{proxy-address6}/header-group',
        '/pm/config/global/obj/firewall/proxy-address6/{proxy-address6}/header-group'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'proxy-address6': {'type': 'str', 'api_name': 'proxy_address6'},
        'proxy_address6': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_proxyaddress6_headergroup': {
            'type': 'dict', 'v_range': [['7.6.4', '']],
            'options': {
                'case-sensitivity': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'header': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'header-name': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'id': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_proxyaddress6_headergroup'),
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
