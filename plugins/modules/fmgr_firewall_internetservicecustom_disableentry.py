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
module: fmgr_firewall_internetservicecustom_disableentry
short_description: Disable entries in the Internet Service database.
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
    internet-service-custom:
        description: Deprecated, please use "internet_service_custom"
        type: str
    internet_service_custom:
        description: The parameter (internet-service-custom) in requested url.
        type: str
    firewall_internetservicecustom_disableentry:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            id:
                type: int
                description: Disable entry ID.
                required: true
            ip_range:
                aliases: ['ip-range']
                type: list
                elements: dict
                description: Ip range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description: End IP address.
                    id:
                        type: int
                        description: Disable entry range ID.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Start IP address.
            port:
                type: raw
                description: (list) Integer value for the TCP/IP port
            protocol:
                type: int
                description: Integer value for the protocol type as defined by IANA
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
    - name: Disable entries in the Internet Service database.
      fortinet.fortimanager.fmgr_firewall_internetservicecustom_disableentry:
        bypass_validation: false
        adom: ansible
        internet_service_custom: "ansible-test" # name
        state: present
        firewall_internetservicecustom_disableentry:
          id: 1
          port: 1

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the disable entries in the custom internet service
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_internetservicecustom_disableentry"
          params:
            adom: "ansible"
            internet_service_custom: "ansible-test" # name
            disable_entry: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry',
        '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'internet-service-custom': {'type': 'str', 'api_name': 'internet_service_custom'},
        'internet_service_custom': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_internetservicecustom_disableentry': {
            'type': 'dict', 'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']],
            'options': {
                'id': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'required': True, 'type': 'int'},
                'ip-range': {
                    'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']],
                    'type': 'list',
                    'options': {
                        'end-ip': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'},
                        'id': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'int'},
                        'start-ip': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'port': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'raw'},
                'protocol': {'v_range': [['6.0.0', '7.2.1'], ['7.4.8', '7.4.10']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetservicecustom_disableentry'),
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
