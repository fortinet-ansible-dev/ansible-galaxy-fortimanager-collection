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
module: fmgr_firewall_gtp_messageratelimitv0
short_description: Message rate limiting for GTP version 0.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
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
    firewall_gtp_messageratelimitv0:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            create_pdp_request:
                aliases: ['create-pdp-request']
                type: int
                description: Rate limit
            delete_pdp_request:
                aliases: ['delete-pdp-request']
                type: int
                description: Rate limit
            echo_request:
                aliases: ['echo-request']
                type: int
                description: Rate limit
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Message rate limiting for GTP version 0.
      fortinet.fortimanager.fmgr_firewall_gtp_messageratelimitv0:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        gtp: <your own value>
        firewall_gtp_messageratelimitv0:
          # create_pdp_request: <integer>
          # delete_pdp_request: <integer>
          # echo_request: <integer>
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
        '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-rate-limit-v0',
        '/pm/config/global/obj/firewall/gtp/{gtp}/message-rate-limit-v0'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'gtp': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_gtp_messageratelimitv0': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {'create-pdp-request': {'type': 'int'}, 'delete-pdp-request': {'type': 'int'}, 'echo-request': {'type': 'int'}}
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_gtp_messageratelimitv0'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
