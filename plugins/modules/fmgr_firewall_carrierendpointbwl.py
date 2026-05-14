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
module: fmgr_firewall_carrierendpointbwl
short_description: Carrier end point black/white list tables.
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
    firewall_carrierendpointbwl:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Optional comments.
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    action:
                        type: list
                        elements: str
                        description: Action to take on this end point
                        choices: ['block', 'exempt', 'exempt-mass-mms']
                    carrier_endpoint:
                        aliases: ['carrier-endpoint']
                        type: str
                        description: End point to act on.
                    log_action:
                        aliases: ['log-action']
                        type: list
                        elements: str
                        description: Action to take on this end point
                        choices: ['archive', 'intercept']
                    pattern_type:
                        aliases: ['pattern-type']
                        type: str
                        description: Wildcard pattern or regular expression.
                        choices: ['wildcard', 'regexp', 'simple']
                    status:
                        type: str
                        description: Enable/disable specified action
                        choices: ['disable', 'enable']
            id:
                type: int
                description: ID.
                required: true
            name:
                type: str
                description: Name of table.
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
    - name: Carrier end point black/white list tables.
      fortinet.fortimanager.fmgr_firewall_carrierendpointbwl:
        bypass_validation: false
        adom: FortiCarrier # This is FOC-only object, need a FortiCarrier adom
        state: present
        firewall_carrierendpointbwl:
          comment: "ansible-test"
          id: 1
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
    - name: Retrieve all the carrier endpoint black/white list tables
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_carrierendpointbwl"
          params:
            adom: "FortiCarrier" # This is FOC-only object, need a FortiCarrier adom
            carrier_endpoint_bwl: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl',
        '/pm/config/global/obj/firewall/carrier-endpoint-bwl'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_carrierendpointbwl': {
            'type': 'dict', 'v_range': [['6.0.0', '7.6.2']],
            'options': {
                'comment': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'entries': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.0.0', '7.6.2']], 'type': 'list', 'choices': ['block', 'exempt', 'exempt-mass-mms'], 'elements': 'str'},
                        'carrier-endpoint': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                        'log-action': {'v_range': [['6.0.0', '7.6.2']], 'type': 'list', 'choices': ['archive', 'intercept'], 'elements': 'str'},
                        'pattern-type': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['wildcard', 'regexp', 'simple'], 'type': 'str'},
                        'status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['6.0.0', '7.6.2']], 'required': True, 'type': 'int'},
                'name': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_carrierendpointbwl'),
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
