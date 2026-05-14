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
module: fmgr_videofilter_profile_filters
short_description: YouTube filter entries.
version_added: "2.4.0"
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    videofilter_profile_filters:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Video filter action.
                choices: ['block', 'monitor', 'allow']
            category:
                type: str
                description: FortiGuard category ID.
            channel:
                type: str
                description: Channel ID.
            comment:
                type: str
                description: Comment.
            id:
                type: int
                description: ID.
                required: true
            keyword:
                type: str
                description: Video filter keyword ID.
            log:
                type: str
                description: Enable/disable logging.
                choices: ['disable', 'enable']
            type:
                type: str
                description: Filter type.
                choices: ['category', 'channel', 'title', 'description']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: YouTube filter entries.
      fortinet.fortimanager.fmgr_videofilter_profile_filters:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        state: present # <value in [present, absent]>
        videofilter_profile_filters:
          id: 0 # Required variable, integer
          # action: <value in [block, monitor, allow]>
          # category: <string>
          # channel: <string>
          # comment: <string>
          # keyword: <string>
          # log: <value in [disable, enable]>
          # type: <value in [category, channel, title, ...]>
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
        '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/filters',
        '/pm/config/global/obj/videofilter/profile/{profile}/filters'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'videofilter_profile_filters': {
            'type': 'dict', 'v_range': [['7.4.2', '']],
            'options': {
                'action': {'v_range': [['7.4.2', '']], 'choices': ['block', 'monitor', 'allow'], 'type': 'str'},
                'category': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'channel': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'comment': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'id': {'v_range': [['7.4.2', '']], 'required': True, 'type': 'int'},
                'keyword': {'v_range': [['7.4.2', '']], 'no_log': True, 'type': 'str'},
                'log': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.4.2', '']], 'choices': ['category', 'channel', 'title', 'description'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'videofilter_profile_filters'),
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
