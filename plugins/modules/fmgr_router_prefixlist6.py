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
module: fmgr_router_prefixlist6
short_description: Configure IPv6 prefix lists.
version_added: "2.1.0"
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
    router_prefixlist6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comments:
                type: str
                description: Comment.
            name:
                type: str
                description: Name.
                required: true
            rule:
                type: list
                elements: dict
                description: Rule.
                suboptions:
                    action:
                        type: str
                        description: Permit or deny packets that match this rule.
                        choices: ['permit', 'deny']
                    flags:
                        type: int
                        description: Flags.
                    ge:
                        type: int
                        description: Minimum prefix length to be matched
                    id:
                        type: int
                        description: Rule ID.
                    le:
                        type: int
                        description: Maximum prefix length to be matched
                    prefix6:
                        type: str
                        description: IPv6 prefix to define regular filter criteria, such as any or subnets.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv6 prefix lists.
      fortinet.fortimanager.fmgr_router_prefixlist6:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        router_prefixlist6:
          name: "your value" # Required variable, string
          # comments: <string>
          # rule:
          #   - action: <value in [permit, deny]>
          #     flags: <integer>
          #     ge: <integer>
          #     id: <integer>
          #     le: <integer>
          #     prefix6: <string>
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
        '/pm/config/adom/{adom}/obj/router/prefix-list6',
        '/pm/config/global/obj/router/prefix-list6'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'router_prefixlist6': {
            'type': 'dict', 'v_range': [['7.0.2', '']],
            'options': {
                'comments': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'name': {'v_range': [['7.0.2', '']], 'required': True, 'type': 'str'},
                'rule': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.0.2', '']], 'choices': ['permit', 'deny'], 'type': 'str'},
                        'flags': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'ge': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'id': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'le': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'prefix6': {'v_range': [['7.0.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_prefixlist6'),
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
