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
module: fmgr_casb_useractivity_controloptions
short_description: CASB control options.
version_added: "2.3.0"
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
    user-activity:
        description: Deprecated, please use "user_activity"
        type: str
    user_activity:
        description: The parameter (user-activity) in requested url.
        type: str
    casb_useractivity_controloptions:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: CASB control option name.
                required: true
            operations:
                type: list
                elements: dict
                description: Operations.
                suboptions:
                    action:
                        type: str
                        description: CASB operation action.
                        choices: ['append', 'prepend', 'replace', 'new', 'new-on-not-found',
                                  'delete']
                    case_sensitive:
                        aliases: ['case-sensitive']
                        type: str
                        description: CASB operation search case sensitive.
                        choices: ['disable', 'enable']
                    direction:
                        type: str
                        description: CASB operation direction.
                        choices: ['request', 'response']
                    header_name:
                        aliases: ['header-name']
                        type: str
                        description: CASB operation header name to search.
                    name:
                        type: str
                        description: CASB control option operation name.
                    search_key:
                        aliases: ['search-key']
                        type: str
                        description: CASB operation key to search.
                    search_pattern:
                        aliases: ['search-pattern']
                        type: str
                        description: CASB operation search pattern.
                        choices: ['simple', 'substr', 'regexp']
                    target:
                        type: str
                        description: CASB operation target.
                        choices: ['header', 'path', 'body']
                    value_from_input:
                        aliases: ['value-from-input']
                        type: str
                        description: Enable/disable value from user input.
                        choices: ['disable', 'enable']
                    values:
                        type: list
                        elements: str
                        description: CASB operation new values.
                    value_name_from_input:
                        aliases: ['value-name-from-input']
                        type: str
                        description: CASB operation value name from user input.
            status:
                type: str
                description: CASB control option status.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: CASB control options.
      fortinet.fortimanager.fmgr_casb_useractivity_controloptions:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        user_activity: <your own value>
        state: present # <value in [present, absent]>
        casb_useractivity_controloptions:
          name: "your value" # Required variable, string
          # operations:
          #   - action: <value in [append, prepend, replace, ...]>
          #     case_sensitive: <value in [disable, enable]>
          #     direction: <value in [request, response]>
          #     header_name: <string>
          #     name: <string>
          #     search_key: <string>
          #     search_pattern: <value in [simple, substr, regexp]>
          #     target: <value in [header, path, body]>
          #     value_from_input: <value in [disable, enable]>
          #     values: <list or string>
          #     value_name_from_input: <string>
          # status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/control-options',
        '/pm/config/global/obj/casb/user-activity/{user-activity}/control-options'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'user-activity': {'type': 'str', 'api_name': 'user_activity'},
        'user_activity': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'casb_useractivity_controloptions': {
            'type': 'dict', 'v_range': [['7.4.1', '']],
            'options': {
                'name': {'v_range': [['7.4.1', '']], 'required': True, 'type': 'str'},
                'operations': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {
                        'action': {
                            'v_range': [['7.4.1', '']],
                            'choices': ['append', 'prepend', 'replace', 'new', 'new-on-not-found', 'delete'],
                            'type': 'str'
                        },
                        'case-sensitive': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'direction': {'v_range': [['7.4.1', '']], 'choices': ['request', 'response'], 'type': 'str'},
                        'header-name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'search-key': {'v_range': [['7.4.1', '']], 'no_log': True, 'type': 'str'},
                        'search-pattern': {'v_range': [['7.4.1', '']], 'choices': ['simple', 'substr', 'regexp'], 'type': 'str'},
                        'target': {'v_range': [['7.4.1', '']], 'choices': ['header', 'path', 'body'], 'type': 'str'},
                        'value-from-input': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'values': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'str'},
                        'value-name-from-input': {'v_range': [['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'status': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_useractivity_controloptions'),
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
