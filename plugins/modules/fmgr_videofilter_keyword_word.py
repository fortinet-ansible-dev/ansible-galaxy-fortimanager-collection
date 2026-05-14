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
module: fmgr_videofilter_keyword_word
short_description: List of keywords.
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
    keyword:
        description: The parameter (keyword) in requested url.
        type: str
        required: true
    videofilter_keyword_word:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            name:
                type: str
                description: Name.
                required: true
            pattern_type:
                aliases: ['pattern-type']
                type: str
                description: Pattern type.
                choices: ['wildcard', 'regex']
            status:
                type: str
                description: Enable
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: List of keywords.
      fortinet.fortimanager.fmgr_videofilter_keyword_word:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        keyword: <your own value>
        state: present # <value in [present, absent]>
        videofilter_keyword_word:
          name: "your value" # Required variable, string
          # comment: <string>
          # pattern_type: <value in [wildcard, regex]>
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
        '/pm/config/adom/{adom}/obj/videofilter/keyword/{keyword}/word',
        '/pm/config/global/obj/videofilter/keyword/{keyword}/word'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'keyword': {'required': True, 'type': 'str', 'no_log': False},
        'revision_note': {'type': 'str'},
        'videofilter_keyword_word': {
            'type': 'dict', 'v_range': [['7.4.2', '']], 'no_log': False,
            'options': {
                'comment': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'name': {'v_range': [['7.4.2', '']], 'required': True, 'type': 'str'},
                'pattern-type': {'v_range': [['7.4.2', '']], 'choices': ['wildcard', 'regex'], 'type': 'str'},
                'status': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'videofilter_keyword_word'),
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
