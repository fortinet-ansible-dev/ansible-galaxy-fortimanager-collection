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
module: fmgr_firewall_profileprotocoloptions_mailsignature
short_description: Configure Mail signature.
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
    profile-protocol-options:
        description: Deprecated, please use "profile_protocol_options"
        type: str
    profile_protocol_options:
        description: The parameter (profile-protocol-options) in requested url.
        type: str
    firewall_profileprotocoloptions_mailsignature:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            signature:
                type: str
                description: Email signature to be added to outgoing email
            status:
                type: str
                description: Enable/disable adding an email signature to SMTP email messages as they pass through the FortiGate.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Mail signature.
      fortinet.fortimanager.fmgr_firewall_profileprotocoloptions_mailsignature:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile_protocol_options: <your own value>
        firewall_profileprotocoloptions_mailsignature:
          # signature: <string>
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
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/mail-signature',
        '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/mail-signature'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile-protocol-options': {'type': 'str', 'api_name': 'profile_protocol_options'},
        'profile_protocol_options': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_profileprotocoloptions_mailsignature': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {'signature': {'type': 'str'}, 'status': {'choices': ['disable', 'enable'], 'type': 'str'}}
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profileprotocoloptions_mailsignature'),
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
