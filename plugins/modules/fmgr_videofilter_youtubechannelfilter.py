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
module: fmgr_videofilter_youtubechannelfilter
short_description: Configure YouTube channel filter.
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
    videofilter_youtubechannelfilter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    action:
                        type: str
                        description: YouTube channel filter action.
                        choices: ['block', 'bypass', 'monitor', 'allow']
                    channel_id:
                        aliases: ['channel-id']
                        type: str
                        description: Channel ID.
                    comment:
                        type: str
                        description: Comment.
                    id:
                        type: int
                        description: ID.
            id:
                type: int
                description: ID.
                required: true
            name:
                type: str
                description: Name.
            default_action:
                aliases: ['default-action']
                type: str
                description: YouTube channel filter default action.
                choices: ['monitor', 'block', 'allow']
            log:
                type: str
                description: Enable/disable logging.
                choices: ['disable', 'enable']
            override_category:
                aliases: ['override-category']
                type: str
                description: Enable/disable overriding category filtering result.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure YouTube channel filter.
      fortinet.fortimanager.fmgr_videofilter_youtubechannelfilter:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        videofilter_youtubechannelfilter:
          id: 0 # Required variable, integer
          # comment: <string>
          # entries:
          #   - action: <value in [block, bypass, monitor, ...]>
          #     channel_id: <string>
          #     comment: <string>
          #     id: <integer>
          # name: <string>
          # default_action: <value in [monitor, block, allow]>
          # log: <value in [disable, enable]>
          # override_category: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter',
        '/pm/config/global/obj/videofilter/youtube-channel-filter'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'videofilter_youtubechannelfilter': {
            'type': 'dict', 'v_range': [['7.0.0', '']],
            'options': {
                'comment': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'entries': {
                    'v_range': [['7.0.0', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.0.0', '']], 'choices': ['block', 'bypass', 'monitor', 'allow'], 'type': 'str'},
                        'channel-id': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'comment': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'id': {'v_range': [['7.0.0', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['7.0.0', '']], 'required': True, 'type': 'int'},
                'name': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'default-action': {'v_range': [['7.0.1', '']], 'choices': ['monitor', 'block', 'allow'], 'type': 'str'},
                'log': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-category': {'v_range': [['7.0.4', '7.0.16'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'videofilter_youtubechannelfilter'),
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
