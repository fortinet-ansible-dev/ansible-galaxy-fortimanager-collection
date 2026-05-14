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
module: fmgr_dlp_datatype
short_description: Configure predefined data type used by DLP blocking.
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
    dlp_datatype:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Optional comments.
            look_ahead:
                aliases: ['look-ahead']
                type: int
                description: Number of characters to obtain in advance for verification
            look_back:
                aliases: ['look-back']
                type: int
                description: Number of characters required to save for verification
            name:
                type: str
                description: Name of table containing the data type.
                required: true
            pattern:
                type: str
                description: Regular expression pattern string without look around.
            transform:
                type: str
                description: Template to transform user input to a pattern using capture group from pattern.
            verify:
                type: str
                description: Regular expression pattern string used to verify the data type.
            verify_transformed_pattern:
                aliases: ['verify-transformed-pattern']
                type: str
                description: Enable/disable verification for transformed pattern.
                choices: ['disable', 'enable']
            match_around:
                aliases: ['match-around']
                type: str
                description: Dictionary to check whether it has a match around
            match_ahead:
                aliases: ['match-ahead']
                type: int
                description: Number of characters behind for match-around
            match_back:
                aliases: ['match-back']
                type: int
                description: Number of characters in front for match-around
            verify2:
                type: str
                description: Extra regular expression pattern string used to verify the data type.
            fgd_id:
                aliases: ['fgd-id']
                type: int
                description: ID of object in FortiGuard database.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure predefined data type used by DLP blocking.
      fortinet.fortimanager.fmgr_dlp_datatype:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        dlp_datatype:
          name: "your value" # Required variable, string
          # comment: <string>
          # look_ahead: <integer>
          # look_back: <integer>
          # pattern: <string>
          # transform: <string>
          # verify: <string>
          # verify_transformed_pattern: <value in [disable, enable]>
          # match_around: <string>
          # match_ahead: <integer>
          # match_back: <integer>
          # verify2: <string>
          # fgd_id: <integer>
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
        '/pm/config/adom/{adom}/obj/dlp/data-type',
        '/pm/config/global/obj/dlp/data-type'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dlp_datatype': {
            'type': 'dict', 'v_range': [['7.2.0', '']],
            'options': {
                'comment': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'look-ahead': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'look-back': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.0', '']], 'required': True, 'type': 'str'},
                'pattern': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'transform': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'verify': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'verify-transformed-pattern': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'match-around': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'match-ahead': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'match-back': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'verify2': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'fgd-id': {'v_range': [['7.6.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_datatype'),
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
