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
module: fmgr_webfilter_content
short_description: Configure Web filter banned word table.
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
    webfilter_content:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Optional comments.
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    action:
                        type: str
                        description: Block or exempt word when a match is found.
                        choices: ['exempt', 'block']
                    lang:
                        type: str
                        description: Language of banned word.
                        choices: ['western', 'simch', 'trach', 'japanese', 'korean', 'french',
                                  'thai', 'spanish', 'cyrillic']
                    name:
                        type: str
                        description: Banned word.
                    pattern_type:
                        aliases: ['pattern-type']
                        type: str
                        description: Banned word pattern type
                        choices: ['wildcard', 'regexp']
                    score:
                        type: int
                        description: Score, to be applied every time the word appears on a web page
                    status:
                        type: str
                        description: Enable/disable banned word.
                        choices: ['disable', 'enable']
            id:
                type: int
                description: ID.
                required: true
            name:
                type: str
                description: Name of table.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Web filter banned word table.
      fortinet.fortimanager.fmgr_webfilter_content:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        webfilter_content:
          id: 0 # Required variable, integer
          # comment: <string>
          # entries:
          #   - action: <value in [exempt, block]>
          #     lang: <value in [western, simch, trach, ...]>
          #     name: <string>
          #     pattern_type: <value in [wildcard, regexp]>
          #     score: <integer>
          #     status: <value in [disable, enable]>
          # name: <string>
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
        '/pm/config/adom/{adom}/obj/webfilter/content',
        '/pm/config/global/obj/webfilter/content'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'webfilter_content': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'comment': {'type': 'str'},
                'entries': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['exempt', 'block'], 'type': 'str'},
                        'lang': {'choices': ['western', 'simch', 'trach', 'japanese', 'korean', 'french', 'thai', 'spanish', 'cyrillic'], 'type': 'str'},
                        'name': {'type': 'str'},
                        'pattern-type': {'choices': ['wildcard', 'regexp'], 'type': 'str'},
                        'score': {'type': 'int'},
                        'status': {'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'id': {'required': True, 'type': 'int'},
                'name': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_content'),
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
