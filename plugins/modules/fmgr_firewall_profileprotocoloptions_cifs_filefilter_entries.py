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
module: fmgr_firewall_profileprotocoloptions_cifs_filefilter_entries
short_description: File filter entries.
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
    profile-protocol-options:
        description: Deprecated, please use "profile_protocol_options"
        type: str
    profile_protocol_options:
        description: The parameter (profile-protocol-options) in requested url.
        type: str
    firewall_profileprotocoloptions_cifs_filefilter_entries:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action taken for matched file.
                choices: ['log', 'block']
            comment:
                type: str
                description: Comment.
            direction:
                type: str
                description: Match files transmitted in the sessions originating or reply direction.
                choices: ['any', 'incoming', 'outgoing']
            file_type:
                aliases: ['file-type']
                type: raw
                description: (list) Select file type.
            filter:
                type: str
                description: Add a file filter.
            protocol:
                type: list
                elements: str
                description: Protocols to apply with.
                choices: ['cifs']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: File filter entries.
      fortinet.fortimanager.fmgr_firewall_profileprotocoloptions_cifs_filefilter_entries:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile_protocol_options: <your own value>
        state: present # <value in [present, absent]>
        firewall_profileprotocoloptions_cifs_filefilter_entries:
          # action: <value in [log, block]>
          # comment: <string>
          # direction: <value in [any, incoming, outgoing]>
          # file_type: <list or string>
          # filter: <string>
          # protocol: ["cifs"]
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
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries',
        '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile-protocol-options': {'type': 'str', 'api_name': 'profile_protocol_options'},
        'profile_protocol_options': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_profileprotocoloptions_cifs_filefilter_entries': {
            'type': 'dict', 'v_range': [['6.4.2', '']],
            'options': {
                'action': {'v_range': [['6.4.2', '']], 'choices': ['log', 'block'], 'type': 'str'},
                'comment': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'direction': {'v_range': [['6.4.2', '']], 'choices': ['any', 'incoming', 'outgoing'], 'type': 'str'},
                'file-type': {'v_range': [['6.4.2', '']], 'type': 'raw'},
                'filter': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'protocol': {'v_range': [['6.4.2', '']], 'type': 'list', 'choices': ['cifs'], 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profileprotocoloptions_cifs_filefilter_entries'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
