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
module: fmgr_firewall_gtp_ieremovepolicy
short_description: IE remove policy.
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
    firewall_gtp_ieremovepolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            id:
                type: int
                description: ID.
                required: true
            remove_ies:
                aliases: ['remove-ies']
                type: list
                elements: str
                description: GTP IEs to be removed.
                choices: ['apn-restriction', 'rat-type', 'rai', 'uli', 'imei']
            sgsn_addr:
                aliases: ['sgsn-addr']
                type: str
                description: SGSN address name.
            sgsn_addr6:
                aliases: ['sgsn-addr6']
                type: str
                description: SGSN IPv6 address name.
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
    - name: IE remove policy.
      fortinet.fortimanager.fmgr_firewall_gtp_ieremovepolicy:
        bypass_validation: false
        adom: FortiCarrier # This is FOC-only object, need a FortiCarrier adom
        gtp: "ansible-test" # name
        state: present
        firewall_gtp_ieremovepolicy:
          id: 1
          remove_ies:
            - apn-restriction
            - rat-type
            - rai
            - uli
            - imei
          sgsn_addr: "your_value"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IE remove policys in the GTP
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_gtp_ieremovepolicy"
          params:
            adom: "FortiCarrier" # This is FOC-only object, need a FortiCarrier adom
            gtp: "ansible-test" # name
            ie_remove_policy: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-remove-policy',
        '/pm/config/global/obj/firewall/gtp/{gtp}/ie-remove-policy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'gtp': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_gtp_ieremovepolicy': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'id': {'required': True, 'type': 'int'},
                'remove-ies': {'type': 'list', 'choices': ['apn-restriction', 'rat-type', 'rai', 'uli', 'imei'], 'elements': 'str'},
                'sgsn-addr': {'type': 'str'},
                'sgsn-addr6': {'v_range': [['6.4.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_gtp_ieremovepolicy'),
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
