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
module: fmgr_firewall_identitybasedroute_rule
short_description: Rule.
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
    identity-based-route:
        description: Deprecated, please use "identity_based_route"
        type: str
    identity_based_route:
        description: The parameter (identity-based-route) in requested url.
        type: str
    firewall_identitybasedroute_rule:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            device:
                type: str
                description: Outgoing interface for the rule.
            gateway:
                type: str
                description: IPv4 address of the gateway
            groups:
                type: raw
                description: (list or str) Select one or more group
            id:
                type: int
                description: Rule ID.
                required: true
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Rule.
      fortinet.fortimanager.fmgr_firewall_identitybasedroute_rule:
        bypass_validation: false
        adom: ansible
        identity_based_route: "ansible-test" # name
        state: present
        firewall_identitybasedroute_rule:
          id: 1

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the identity based routing rules
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_identitybasedroute_rule"
          params:
            adom: "ansible"
            identity_based_route: "your_value" # name
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
        '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}/rule',
        '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}/rule'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'identity-based-route': {'type': 'str', 'api_name': 'identity_based_route'},
        'identity_based_route': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_identitybasedroute_rule': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {'device': {'type': 'str'}, 'gateway': {'type': 'str'}, 'groups': {'type': 'raw'}, 'id': {'required': True, 'type': 'int'}}
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_identitybasedroute_rule'),
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
