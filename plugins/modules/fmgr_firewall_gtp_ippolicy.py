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
module: fmgr_firewall_gtp_ippolicy
short_description: IP policy.
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
    gtp:
        description: The parameter (gtp) in requested url.
        type: str
        required: true
    firewall_gtp_ippolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action.
                choices: ['allow', 'deny']
            dstaddr:
                type: str
                description: Destination address name.
            id:
                type: int
                description: ID.
                required: true
            srcaddr:
                type: str
                description: Source address name.
            dstaddr6:
                type: str
                description: Destination IPv6 address name.
            srcaddr6:
                type: str
                description: Source IPv6 address name.
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
    - name: IP policy.
      fortinet.fortimanager.fmgr_firewall_gtp_ippolicy:
        bypass_validation: false
        adom: FortiCarrier # This is FOC-only object, need a FortiCarrier adom
        gtp: "ansible-test" # name
        state: present
        firewall_gtp_ippolicy:
          action: allow # <value in [allow, deny]>
          id: 3

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IP policys in the GTP
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_gtp_ippolicy"
          params:
            adom: "FortiCarrier" # This is FOC-only object, need a FortiCarrier adom
            gtp: "ansible-test" # name
            ip_policy: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ip-policy',
        '/pm/config/global/obj/firewall/gtp/{gtp}/ip-policy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'gtp': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_gtp_ippolicy': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['allow', 'deny'], 'type': 'str'},
                'dstaddr': {'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'srcaddr': {'type': 'str'},
                'dstaddr6': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'srcaddr6': {'v_range': [['6.4.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_gtp_ippolicy'),
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
