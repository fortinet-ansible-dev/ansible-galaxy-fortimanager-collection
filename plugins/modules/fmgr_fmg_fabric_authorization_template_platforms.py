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
module: fmgr_fmg_fabric_authorization_template_platforms
short_description: Fmg fabric authorization template platforms
version_added: "2.2.0"
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
    template:
        description: The parameter (template) in requested url.
        type: str
        required: true
    fmg_fabric_authorization_template_platforms:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            count:
                type: int
                description: Count.
            extension_type:
                aliases: ['extension-type']
                type: str
                description: Extension type.
                choices: ['wan-extension', 'lan-extension']
            fortilink:
                type: str
                description: Fortilink.
            prefix:
                type: str
                description: Prefix.
            type:
                type: str
                description: Type.
                choices: ['ap', 'extender', 'switch']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Fmg fabric authorization template platforms
      fortinet.fortimanager.fmgr_fmg_fabric_authorization_template_platforms:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        template: <your own value>
        state: present # <value in [present, absent]>
        fmg_fabric_authorization_template_platforms:
          # count: <integer>
          # extension_type: <value in [wan-extension, lan-extension]>
          # fortilink: <string>
          # prefix: <string>
          # type: <value in [ap, extender, switch]>
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
        '/pm/config/adom/{adom}/obj/fmg/fabric/authorization/template/{template}/platforms',
        '/pm/config/global/obj/fmg/fabric/authorization/template/{template}/platforms'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'template': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'fmg_fabric_authorization_template_platforms': {
            'type': 'dict', 'v_range': [['7.2.1', '']],
            'options': {
                'count': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'extension-type': {'v_range': [['7.2.1', '']], 'choices': ['wan-extension', 'lan-extension'], 'type': 'str'},
                'fortilink': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'prefix': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'type': {'v_range': [['7.2.1', '']], 'choices': ['ap', 'extender', 'switch'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmg_fabric_authorization_template_platforms'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
