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
module: fmgr_sshfilter_profile_shellcommands
short_description: SSH command filter.
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    sshfilter_profile_shellcommands:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action to take for URL filter matches.
                choices: ['block', 'allow']
            alert:
                type: str
                description: Enable/disable alert.
                choices: ['disable', 'enable']
            id:
                type: int
                description: Id.
                required: true
            log:
                type: str
                description: Enable/disable logging.
                choices: ['disable', 'enable']
            pattern:
                type: str
                description: SSH shell command pattern.
            severity:
                type: str
                description: Log severity.
                choices: ['low', 'medium', 'high', 'critical']
            type:
                type: str
                description: Matching type.
                choices: ['regex', 'simple']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: SSH command filter.
      fortinet.fortimanager.fmgr_sshfilter_profile_shellcommands:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        state: present # <value in [present, absent]>
        sshfilter_profile_shellcommands:
          id: 0 # Required variable, integer
          # action: <value in [block, allow]>
          # alert: <value in [disable, enable]>
          # log: <value in [disable, enable]>
          # pattern: <string>
          # severity: <value in [low, medium, high, ...]>
          # type: <value in [regex, simple]>
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
        '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/shell-commands',
        '/pm/config/global/obj/ssh-filter/profile/{profile}/shell-commands'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'sshfilter_profile_shellcommands': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['block', 'allow'], 'type': 'str'},
                'alert': {'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pattern': {'type': 'str'},
                'severity': {'choices': ['low', 'medium', 'high', 'critical'], 'type': 'str'},
                'type': {'choices': ['regex', 'simple'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'sshfilter_profile_shellcommands'),
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
