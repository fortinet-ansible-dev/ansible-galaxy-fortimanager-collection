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
module: fmgr_system_replacemsggroup_mm4
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
    system_replacemsggroup_mm4:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            add_smil:
                aliases: ['add-smil']
                type: str
                description: Add message encapsulation
                choices: ['disable', 'enable']
            charset:
                type: str
                description: Character encoding used for replacement message
                choices: ['us-ascii', 'utf-8']
            class:
                type: str
                description: Message class
                choices: ['personal', 'advertisement', 'informational', 'auto', 'not-included']
            domain:
                type: str
                description: From address domain
            format:
                type: str
                description: Format flag.
                choices: ['none', 'text', 'html', 'wml']
            from:
                type: str
                description: From address
            from_sender:
                aliases: ['from-sender']
                type: str
                description: Notification message sent from recipient
                choices: ['disable', 'enable']
            header:
                type: str
                description: Header flag.
                choices: ['none', 'http', '8bit']
            image:
                type: str
                description: Message string.
            fmgr_message:
                type: str
                description: Message text
            msg_type:
                aliases: ['msg-type']
                type: str
                description: Message type.
                required: true
            priority:
                type: str
                description: Message priority
                choices: ['low', 'normal', 'high', 'not-included']
            rsp_status:
                aliases: ['rsp-status']
                type: str
                description: Response status
                choices: ['ok', 'err-unspecified', 'err-srv-denied', 'err-msg-fmt-corrupt',
                          'err-snd-addr-unresolv', 'err-net-prob', 'err-content-not-accept',
                          'err-unsupp-msg']
            smil_part:
                aliases: ['smil-part']
                type: str
                description: Message encapsulation text
            subject:
                type: str
                description: Subject text string
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Replacement message table entries.
      fortinet.fortimanager.fmgr_system_replacemsggroup_mm4:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        replacemsg_group: <your own value>
        state: present # <value in [present, absent]>
        system_replacemsggroup_mm4:
          msg_type: "your value" # Required variable, string
          # add_smil: <value in [disable, enable]>
          # charset: <value in [us-ascii, utf-8]>
          # class: <value in [personal, advertisement, informational, ...]>
          # domain: <string>
          # format: <value in [none, text, html, ...]>
          # from: <string>
          # from_sender: <value in [disable, enable]>
          # header: <value in [none, http, 8bit]>
          # image: <string>
          # fmgr_message: <string>
          # priority: <value in [low, normal, high, ...]>
          # rsp_status: <value in [ok, err-unspecified, err-srv-denied, ...]>
          # smil_part: <string>
          # subject: <string>
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
        '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm4',
        '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm4'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'replacemsg-group': {'type': 'str', 'api_name': 'replacemsg_group'},
        'replacemsg_group': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_replacemsggroup_mm4': {
            'type': 'dict', 'v_range': [['6.0.0', '7.6.2']],
            'options': {
                'add-smil': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'charset': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                'class': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'choices': ['personal', 'advertisement', 'informational', 'auto', 'not-included'],
                    'type': 'str'
                },
                'domain': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'format': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                'from': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'from-sender': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'header': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                'image': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'fmgr_message': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'msg-type': {'v_range': [['6.0.0', '7.6.2']], 'required': True, 'type': 'str'},
                'priority': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['low', 'normal', 'high', 'not-included'], 'type': 'str'},
                'rsp-status': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'choices': [
                        'ok', 'err-unspecified', 'err-srv-denied', 'err-msg-fmt-corrupt', 'err-snd-addr-unresolv', 'err-net-prob',
                        'err-content-not-accept', 'err-unsupp-msg'
                    ],
                    'type': 'str'
                },
                'smil-part': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'subject': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_replacemsggroup_mm4'),
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
