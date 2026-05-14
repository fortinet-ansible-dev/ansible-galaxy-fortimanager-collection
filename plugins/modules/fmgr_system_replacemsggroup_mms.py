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
module: fmgr_system_replacemsggroup_mms
short_description: Replacement message table entries.
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
    replacemsg-group:
        description: Deprecated, please use "replacemsg_group"
        type: str
    replacemsg_group:
        description: The parameter (replacemsg-group) in requested url.
        type: str
    system_replacemsggroup_mms:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            buffer:
                type: str
                description: Message string.
            charset:
                type: str
                description: Character encoding used for replacement message
                choices: ['us-ascii', 'utf-8']
            format:
                type: str
                description: Format flag.
                choices: ['none', 'text', 'html', 'wml']
            header:
                type: str
                description: Header flag.
                choices: ['none', 'http', '8bit']
            image:
                type: str
                description: Message string.
            msg_type:
                aliases: ['msg-type']
                type: str
                description: Message type.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Replacement message table entries.
      fortinet.fortimanager.fmgr_system_replacemsggroup_mms:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        replacemsg_group: <your own value>
        state: present # <value in [present, absent]>
        system_replacemsggroup_mms:
          msg_type: "your value" # Required variable, string
          # buffer: <string>
          # charset: <value in [us-ascii, utf-8]>
          # format: <value in [none, text, html, ...]>
          # header: <value in [none, http, 8bit]>
          # image: <string>
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
        '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mms',
        '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mms'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'replacemsg-group': {'type': 'str', 'api_name': 'replacemsg_group'},
        'replacemsg_group': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_replacemsggroup_mms': {
            'type': 'dict', 'v_range': [['6.0.0', '7.6.2']],
            'options': {
                'buffer': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'charset': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                'format': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                'header': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                'image': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'msg-type': {'v_range': [['6.0.0', '7.6.2']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_replacemsggroup_mms'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'msg-type', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
