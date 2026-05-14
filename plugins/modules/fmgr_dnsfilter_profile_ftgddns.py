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
module: fmgr_dnsfilter_profile_ftgddns
short_description: FortiGuard DNS Filter settings.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
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
    dnsfilter_profile_ftgddns:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            filters:
                type: list
                elements: dict
                description: Filters.
                suboptions:
                    action:
                        type: str
                        description: Action to take for DNS requests matching the category.
                        choices: ['monitor', 'block']
                    category:
                        type: str
                        description: Category number.
                    id:
                        type: int
                        description: ID number.
                    log:
                        type: str
                        description: Enable/disable DNS filter logging for this DNS profile.
                        choices: ['disable', 'enable']
            options:
                type: list
                elements: str
                description: FortiGuard DNS filter options.
                choices: ['error-allow', 'ftgd-disable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: FortiGuard DNS Filter settings.
      fortinet.fortimanager.fmgr_dnsfilter_profile_ftgddns:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        dnsfilter_profile_ftgddns:
          # filters:
          #   - action: <value in [monitor, block]>
          #     category: <string>
          #     id: <integer>
          #     log: <value in [disable, enable]>
          # options: ["error-allow", "ftgd-disable"]
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
        '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/ftgd-dns',
        '/pm/config/global/obj/dnsfilter/profile/{profile}/ftgd-dns'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dnsfilter_profile_ftgddns': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'filters': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['monitor', 'block'], 'type': 'str'},
                        'category': {'type': 'str'},
                        'id': {'type': 'int'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'options': {'type': 'list', 'choices': ['error-allow', 'ftgd-disable'], 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dnsfilter_profile_ftgddns'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
