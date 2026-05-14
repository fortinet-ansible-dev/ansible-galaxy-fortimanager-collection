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
module: fmgr_firewall_ippool6
short_description: Configure IPv6 IP pools.
version_added: "1.0.0"
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
    firewall_ippool6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comments:
                type: str
                description: Comment.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _scope:
                        type: list
                        elements: dict
                        description: Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    comments:
                        type: str
                        description: Comments.
                    endip:
                        type: str
                        description: Endip.
                    startip:
                        type: str
                        description: Startip.
                    add_nat46_route:
                        aliases: ['add-nat46-route']
                        type: str
                        description: Enable/disable adding NAT46 route.
                        choices: ['disable', 'enable']
                    nat46:
                        type: str
                        description: Enable/disable NAT46.
                        choices: ['disable', 'enable']
                    external_prefix:
                        aliases: ['external-prefix']
                        type: str
                        description:
                            - Support meta variable
                            - External NPTv6 prefix length
                    internal_prefix:
                        aliases: ['internal-prefix']
                        type: str
                        description:
                            - Support meta variable
                            - Internal NPTv6 prefix length
                    type:
                        type: str
                        description: Configure IPv6 pool type
                        choices: ['overload', 'nptv6']
            endip:
                type: str
                description: Final IPv6 address
            name:
                type: str
                description: IPv6 IP pool name.
                required: true
            startip:
                type: str
                description: First IPv6 address
            add_nat46_route:
                aliases: ['add-nat46-route']
                type: str
                description: Enable/disable adding NAT46 route.
                choices: ['disable', 'enable']
            nat46:
                type: str
                description: Enable/disable NAT46.
                choices: ['disable', 'enable']
            external_prefix:
                aliases: ['external-prefix']
                type: str
                description:
                    - Support meta variable
                    - External NPTv6 prefix length
            internal_prefix:
                aliases: ['internal-prefix']
                type: str
                description:
                    - Support meta variable
                    - Internal NPTv6 prefix length
            type:
                type: str
                description: Configure IPv6 pool type
                choices: ['overload', 'nptv6']
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
    - name: Configure IPv6 IP pools.
      fortinet.fortimanager.fmgr_firewall_ippool6:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_ippool6:
          comments: "ansible-comment"
          endip: "2001::101"
          name: "ansible-test"
          startip: "2001::0"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv6 IP pools
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_ippool6"
          params:
            adom: "ansible"
            ippool6: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/ippool6',
        '/pm/config/global/obj/firewall/ippool6'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_ippool6': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'comments': {'type': 'str'},
                'dynamic_mapping': {
                    'type': 'list',
                    'options': {
                        '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                        'comments': {'type': 'str'},
                        'endip': {'type': 'str'},
                        'startip': {'type': 'str'},
                        'add-nat46-route': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'nat46': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'external-prefix': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'internal-prefix': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'type': {'v_range': [['7.6.0', '']], 'choices': ['overload', 'nptv6'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'endip': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'startip': {'type': 'str'},
                'add-nat46-route': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat46': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'external-prefix': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'internal-prefix': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'type': {'v_range': [['7.6.0', '']], 'choices': ['overload', 'nptv6'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_ippool6'),
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
