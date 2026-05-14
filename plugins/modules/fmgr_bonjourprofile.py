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
module: fmgr_bonjourprofile
short_description: Configure Bonjour profiles.
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
    bonjourprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            name:
                type: str
                description: Bonjour profile name.
                required: true
            policy_list:
                aliases: ['policy-list']
                type: list
                elements: dict
                description: Policy list.
                suboptions:
                    description:
                        type: str
                        description: Description.
                    from_vlan:
                        aliases: ['from-vlan']
                        type: str
                        description: VLAN ID from which the Bonjour service is advertised
                    policy_id:
                        aliases: ['policy-id']
                        type: int
                        description: Policy ID.
                    services:
                        type: list
                        elements: str
                        description: Bonjour services for the VLAN connecting to the Bonjour network.
                        choices: ['airplay', 'afp', 'bit-torrent', 'ftp', 'ichat', 'itunes',
                                  'printers', 'samba', 'scanners', 'ssh', 'chromecast', 'all',
                                  'miracast']
                    to_vlan:
                        aliases: ['to-vlan']
                        type: str
                        description: VLAN ID to which the Bonjour service is made available
            micro_location:
                aliases: ['micro-location']
                type: str
                description: Enable/disable Micro location for Bonjour profile
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Bonjour profiles.
      fortinet.fortimanager.fmgr_bonjourprofile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        bonjourprofile:
          name: "your value" # Required variable, string
          # comment: <string>
          # policy_list:
          #   - description: <string>
          #     from_vlan: <string>
          #     policy_id: <integer>
          #     services: ["airplay", "afp", "bit-torrent", "ftp", "ichat", "itunes", "printers",
          #                "samba", "scanners", "ssh", "chromecast", "all", "miracast"]
          #     to_vlan: <string>
          # micro_location: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile',
        '/pm/config/global/obj/wireless-controller/bonjour-profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'bonjourprofile': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'comment': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'policy-list': {
                    'type': 'list',
                    'options': {
                        'description': {'type': 'str'},
                        'from-vlan': {'type': 'str'},
                        'policy-id': {'type': 'int'},
                        'services': {
                            'type': 'list',
                            'choices': [
                                'airplay', 'afp', 'bit-torrent', 'ftp', 'ichat', 'itunes', 'printers', 'samba', 'scanners', 'ssh', 'chromecast', 'all',
                                'miracast'
                            ],
                            'elements': 'str'
                        },
                        'to-vlan': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'micro-location': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'bonjourprofile'),
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
