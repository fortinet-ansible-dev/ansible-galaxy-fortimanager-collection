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
module: fmgr_system_csf_trustedlist
short_description: Pre-authorized and blocked security fabric nodes.
version_added: "2.3.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_csf_trustedlist:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description:
                    - Security fabric authorization action.
                    - accept - Accept authorization request.
                    - deny - Deny authorization request.
                choices: ['accept', 'deny']
            authorization_type:
                aliases: ['authorization-type']
                type: str
                description:
                    - Authorization type.
                    - serial - Verify downstream by serial number.
                    - certificate - Verify downstream by certificate.
                choices: ['serial', 'certificate']
            certificate:
                type: str
                description: Certificate.
            downstream_authorization:
                aliases: ['downstream-authorization']
                type: str
                description:
                    - Trust authorizations by this node&apos;s administrator.
                    - disable - Disable downstream authorization.
                    - enable - Enable downstream authorization.
                choices: ['disable', 'enable']
            ha_members:
                aliases: ['ha-members']
                type: str
                description: HA members.
            index:
                type: int
                description: Index of the downstream in tree.
            name:
                type: str
                description: Name.
                required: true
            serial:
                type: str
                description: Serial.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Pre-authorized and blocked security fabric nodes.
      fortinet.fortimanager.fmgr_system_csf_trustedlist:
        # workspace_locking_adom: <global or your adom name>
        state: present # <value in [present, absent]>
        system_csf_trustedlist:
          name: "your value" # Required variable, string
          # action: <value in [accept, deny]>
          # authorization_type: <value in [serial, certificate]>
          # certificate: <string>
          # downstream_authorization: <value in [disable, enable]>
          # ha_members: <string>
          # index: <integer>
          # serial: <string>
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
        '/cli/global/system/csf/trusted-list'
    ]
    module_arg_spec = {
        'system_csf_trustedlist': {
            'type': 'dict', 'v_range': [['7.4.1', '']],
            'options': {
                'action': {'v_range': [['7.4.1', '']], 'choices': ['accept', 'deny'], 'type': 'str'},
                'authorization-type': {'v_range': [['7.4.1', '']], 'choices': ['serial', 'certificate'], 'type': 'str'},
                'certificate': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'downstream-authorization': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ha-members': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'index': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.1', '']], 'required': True, 'type': 'str'},
                'serial': {'v_range': [['7.4.1', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_csf_trustedlist'),
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
