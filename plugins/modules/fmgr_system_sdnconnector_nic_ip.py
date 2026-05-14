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
module: fmgr_system_sdnconnector_nic_ip
short_description: Configure IP configuration.
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
    sdn-connector:
        description: Deprecated, please use "sdn_connector"
        type: str
    sdn_connector:
        description: The parameter (sdn-connector) in requested url.
        type: str
    nic:
        description: The parameter (nic) in requested url.
        type: str
        required: true
    system_sdnconnector_nic_ip:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: IP configuration name.
                required: true
            public_ip:
                aliases: ['public-ip']
                type: str
                description: Public IP name.
            resource_group:
                aliases: ['resource-group']
                type: str
                description: Resource group of Azure public IP.
            private_ip:
                aliases: ['private-ip']
                type: str
                description: Private IP address.
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
    - name: Configure IP configuration.
      fortinet.fortimanager.fmgr_system_sdnconnector_nic_ip:
        bypass_validation: false
        adom: ansible
        sdn_connector: ansible-test-sdn # name
        nic: ansible-test-nic # name
        state: present
        system_sdnconnector_nic_ip:
          name: ansible-test-nicip
          public_ip: 222.222.222.2

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IP configurations of Azure network interface
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_sdnconnector_nic_ip"
          params:
            adom: "ansible"
            sdn_connector: "ansible-test-sdn" # name
            nic: "ansible-test-nic" # name
            ip: "your_value"
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
        '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip',
        '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'sdn-connector': {'type': 'str', 'api_name': 'sdn_connector'},
        'sdn_connector': {'type': 'str'},
        'nic': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_sdnconnector_nic_ip': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'name': {'required': True, 'type': 'str'},
                'public-ip': {'type': 'str'},
                'resource-group': {'v_range': [['6.2.3', '']], 'type': 'str'},
                'private-ip': {'v_range': [['7.4.4', '7.4.10'], ['7.6.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sdnconnector_nic_ip'),
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
