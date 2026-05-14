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
module: fmgr_firewall_carrierendpointbwl_entries
short_description: Carrier end point black/white list.
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
    carrier-endpoint-bwl:
        description: Deprecated, please use "carrier_endpoint_bwl"
        type: str
    carrier_endpoint_bwl:
        description: The parameter (carrier-endpoint-bwl) in requested url.
        type: str
    firewall_carrierendpointbwl_entries:
        description: The top level parameters set.
        required: false
        type: dict
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
                required: true
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
    - name: Carrier end point black/white list.
      fortinet.fortimanager.fmgr_firewall_carrierendpointbwl_entries:
        bypass_validation: false
        adom: FortiCarrier # This is FOC-only object, need a FortiCarrier adom
        carrier_endpoint_bwl: "1" # id
        state: present
        firewall_carrierendpointbwl_entries:
          action:
            - block
            - exempt
            - exempt-mass-mms
          carrier_endpoint: "string"
          log_action:
            - archive
            - intercept
          pattern_type: wildcard # <value in [wildcard, regexp, simple]>
          status: enable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the carrier endpoint black/white list table
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_carrierendpointbwl_entries"
          params:
            adom: "FortiCarrier" # This is FOC-only object, need a FortiCarrier adom
            carrier_endpoint_bwl: "1" # id
            entries: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries',
        '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'carrier-endpoint-bwl': {'type': 'str', 'api_name': 'carrier_endpoint_bwl'},
        'carrier_endpoint_bwl': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_carrierendpointbwl_entries': {
            'type': 'dict', 'v_range': [['6.0.0', '7.6.2']],
            'options': {
                'action': {'v_range': [['6.0.0', '7.6.2']], 'type': 'list', 'choices': ['block', 'exempt', 'exempt-mass-mms'], 'elements': 'str'},
                'carrier-endpoint': {'v_range': [['6.0.0', '7.6.2']], 'required': True, 'type': 'str'},
                'log-action': {'v_range': [['6.0.0', '7.6.2']], 'type': 'list', 'choices': ['archive', 'intercept'], 'elements': 'str'},
                'pattern-type': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['wildcard', 'regexp', 'simple'], 'type': 'str'},
                'status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_carrierendpointbwl_entries'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'carrier-endpoint', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
