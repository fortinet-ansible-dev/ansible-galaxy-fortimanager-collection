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
module: fmgr_waf_profile_urlaccess
short_description: URL access list
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
    waf_profile_urlaccess:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            access_pattern:
                aliases: ['access-pattern']
                type: list
                elements: dict
                description: Access pattern.
                suboptions:
                    id:
                        type: int
                        description: URL access pattern ID.
                    negate:
                        type: str
                        description: Enable/disable match negation.
                        choices: ['disable', 'enable']
                    pattern:
                        type: str
                        description: URL pattern.
                    regex:
                        type: str
                        description: Enable/disable regular expression based pattern match.
                        choices: ['disable', 'enable']
                    srcaddr:
                        type: str
                        description: Source address.
            action:
                type: str
                description: Action.
                choices: ['bypass', 'permit', 'block']
            address:
                type: str
                description: Host address.
            id:
                type: int
                description: URL access ID.
                required: true
            log:
                type: str
                description: Enable/disable logging.
                choices: ['disable', 'enable']
            severity:
                type: str
                description: Severity.
                choices: ['low', 'medium', 'high']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: URL access list
      fortinet.fortimanager.fmgr_waf_profile_urlaccess:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        state: present # <value in [present, absent]>
        waf_profile_urlaccess:
          id: 0 # Required variable, integer
          # access_pattern:
          #   - id: <integer>
          #     negate: <value in [disable, enable]>
          #     pattern: <string>
          #     regex: <value in [disable, enable]>
          #     srcaddr: <string>
          # action: <value in [bypass, permit, block]>
          # address: <string>
          # log: <value in [disable, enable]>
          # severity: <value in [low, medium, high]>
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
        '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access',
        '/pm/config/global/obj/waf/profile/{profile}/url-access'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'waf_profile_urlaccess': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'access-pattern': {
                    'type': 'list',
                    'options': {
                        'id': {'type': 'int'},
                        'negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'pattern': {'type': 'str'},
                        'regex': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'srcaddr': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'action': {'choices': ['bypass', 'permit', 'block'], 'type': 'str'},
                'address': {'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'waf_profile_urlaccess'),
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
