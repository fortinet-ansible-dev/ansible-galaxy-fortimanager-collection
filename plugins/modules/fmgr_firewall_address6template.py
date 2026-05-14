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
module: fmgr_firewall_address6template
short_description: Configure IPv6 address templates.
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
    firewall_address6template:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ip6:
                type: str
                description: IPv6 address prefix.
            name:
                type: str
                description: IPv6 address template name.
                required: true
            subnet_segment:
                aliases: ['subnet-segment']
                type: list
                elements: dict
                description: Subnet segment.
                suboptions:
                    bits:
                        type: int
                        description: Number of bits.
                    exclusive:
                        type: str
                        description: Enable/disable exclusive value.
                        choices: ['disable', 'enable']
                    id:
                        type: int
                        description: Subnet segment ID.
                    name:
                        type: str
                        description: Subnet segment name.
                    values:
                        type: list
                        elements: dict
                        description: Values.
                        suboptions:
                            name:
                                type: str
                                description: Subnet segment value name.
                            value:
                                type: str
                                description: Subnet segment value.
            subnet_segment_count:
                aliases: ['subnet-segment-count']
                type: int
                description: Number of IPv6 subnet segments.
            _image_base64:
                aliases: ['_image-base64']
                type: str
                description: Image base64.
            fabric_object:
                aliases: ['fabric-object']
                type: str
                description: Security Fabric global object setting.
                choices: ['disable', 'enable']
            uuid:
                type: str
                description: Universally Unique Identifier
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
    - name: Configure IPv6 address templates.
      fortinet.fortimanager.fmgr_firewall_address6template:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_address6template:
          ip6: "::33/128"
          name: "ansible-name"
          subnet_segment:
            - bits: 1
              exclusive: enable
              id: 1
              name: "ansible-name-sub"
              values:
                - name: "ansible-name-val"
                  value: "ansible"
          subnet_segment_count: 2

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv6 address templates
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_address6template"
          params:
            adom: "ansible"
            address6_template: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/address6-template',
        '/pm/config/global/obj/firewall/address6-template'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_address6template': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'ip6': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'subnet-segment': {
                    'type': 'list',
                    'options': {
                        'bits': {'type': 'int'},
                        'exclusive': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'type': 'int'},
                        'name': {'type': 'str'},
                        'values': {'type': 'list', 'options': {'name': {'type': 'str'}, 'value': {'type': 'str'}}, 'elements': 'dict'}
                    },
                    'elements': 'dict'
                },
                'subnet-segment-count': {'type': 'int'},
                '_image-base64': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'fabric-object': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['7.6.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_address6template'),
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
