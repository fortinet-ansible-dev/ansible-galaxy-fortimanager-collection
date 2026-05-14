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
module: fmgr_firewall_wildcardfqdn_custom
short_description: Config global/VDOM Wildcard FQDN address.
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
    firewall_wildcardfqdn_custom:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            color:
                type: int
                description: GUI icon color.
            comment:
                type: str
                description: Comment.
            name:
                type: str
                description: Address name.
                required: true
            uuid:
                type: str
                description: Universally Unique Identifier
            visibility:
                type: str
                description: Enable/disable address visibility.
                choices: ['disable', 'enable']
            wildcard_fqdn:
                aliases: ['wildcard-fqdn']
                type: str
                description: Wildcard FQDN.
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
    - name: Config global/VDOM Wildcard FQDN address.
      fortinet.fortimanager.fmgr_firewall_wildcardfqdn_custom:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_wildcardfqdn_custom:
          color: 1
          comment: "ansible-comment"
          name: "ansible-test"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the global/VDOM Wildcard FQDN address
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_wildcardfqdn_custom"
          params:
            adom: "ansible"
            custom: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom',
        '/pm/config/global/obj/firewall/wildcard-fqdn/custom'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_wildcardfqdn_custom': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'color': {'type': 'int'},
                'comment': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'uuid': {'type': 'str'},
                'visibility': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wildcard-fqdn': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_wildcardfqdn_custom'),
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
