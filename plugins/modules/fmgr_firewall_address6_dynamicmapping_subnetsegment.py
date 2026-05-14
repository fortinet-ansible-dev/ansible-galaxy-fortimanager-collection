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
module: fmgr_firewall_address6_dynamicmapping_subnetsegment
short_description: IPv6 subnet segments.
version_added: "2.1.0"
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
    address6:
        description: The parameter (address6) in requested url.
        type: str
        required: true
    dynamic_mapping:
        description: The parameter (dynamic_mapping) in requested url.
        type: str
        required: true
    firewall_address6_dynamicmapping_subnetsegment:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: Name.
                required: true
            type:
                type: str
                description: Type.
                choices: ['any', 'specific']
            value:
                type: str
                description: Value.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: IPv6 subnet segments.
      fortinet.fortimanager.fmgr_firewall_address6_dynamicmapping_subnetsegment:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        address6: <your own value>
        dynamic_mapping: <your own value>
        state: present # <value in [present, absent]>
        firewall_address6_dynamicmapping_subnetsegment:
          name: "your value" # Required variable, string
          # type: <value in [any, specific]>
          # value: <string>
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
        '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment',
        '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'address6': {'required': True, 'type': 'str'},
        'dynamic_mapping': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_address6_dynamicmapping_subnetsegment': {
            'type': 'dict', 'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.0']],
            'options': {
                'name': {'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.0']], 'required': True, 'type': 'str'},
                'type': {'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['any', 'specific'], 'type': 'str'},
                'value': {'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_address6_dynamicmapping_subnetsegment'),
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
