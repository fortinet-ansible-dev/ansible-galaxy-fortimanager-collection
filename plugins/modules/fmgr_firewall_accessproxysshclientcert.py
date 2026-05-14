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
module: fmgr_firewall_accessproxysshclientcert
short_description: Configure Access Proxy SSH client certificate.
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
    firewall_accessproxysshclientcert:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_ca:
                aliases: ['auth-ca']
                type: str
                description: Name of the SSH server public key authentication CA.
            cert_extension:
                aliases: ['cert-extension']
                type: list
                elements: dict
                description: Cert extension.
                suboptions:
                    critical:
                        type: str
                        description: Critical option.
                        choices: ['no', 'yes']
                    data:
                        type: str
                        description: Data of certificate extension.
                    name:
                        type: str
                        description: Name of certificate extension.
                    type:
                        type: str
                        description: Type of certificate extension.
                        choices: ['fixed', 'user']
            name:
                type: str
                description: SSH client certificate name.
                required: true
            permit_agent_forwarding:
                aliases: ['permit-agent-forwarding']
                type: str
                description: Enable/disable appending permit-agent-forwarding certificate extension.
                choices: ['disable', 'enable']
            permit_port_forwarding:
                aliases: ['permit-port-forwarding']
                type: str
                description: Enable/disable appending permit-port-forwarding certificate extension.
                choices: ['disable', 'enable']
            permit_pty:
                aliases: ['permit-pty']
                type: str
                description: Enable/disable appending permit-pty certificate extension.
                choices: ['disable', 'enable']
            permit_user_rc:
                aliases: ['permit-user-rc']
                type: str
                description: Enable/disable appending permit-user-rc certificate extension.
                choices: ['disable', 'enable']
            permit_x11_forwarding:
                aliases: ['permit-x11-forwarding']
                type: str
                description: Enable/disable appending permit-x11-forwarding certificate extension.
                choices: ['disable', 'enable']
            source_address:
                aliases: ['source-address']
                type: str
                description: Enable/disable appending source-address certificate critical option.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Access Proxy SSH client certificate.
      fortinet.fortimanager.fmgr_firewall_accessproxysshclientcert:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        firewall_accessproxysshclientcert:
          name: "your value" # Required variable, string
          # auth_ca: <string>
          # cert_extension:
          #   - critical: <value in [no, yes]>
          #     data: <string>
          #     name: <string>
          #     type: <value in [fixed, user]>
          # permit_agent_forwarding: <value in [disable, enable]>
          # permit_port_forwarding: <value in [disable, enable]>
          # permit_pty: <value in [disable, enable]>
          # permit_user_rc: <value in [disable, enable]>
          # permit_x11_forwarding: <value in [disable, enable]>
          # source_address: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/firewall/access-proxy-ssh-client-cert',
        '/pm/config/global/obj/firewall/access-proxy-ssh-client-cert'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_accessproxysshclientcert': {
            'type': 'dict', 'v_range': [['7.4.2', '']],
            'options': {
                'auth-ca': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'cert-extension': {
                    'v_range': [['7.4.2', '']],
                    'type': 'list',
                    'options': {
                        'critical': {'v_range': [['7.4.2', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                        'data': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'name': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'type': {'v_range': [['7.4.2', '']], 'choices': ['fixed', 'user'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['7.4.2', '']], 'required': True, 'type': 'str'},
                'permit-agent-forwarding': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'permit-port-forwarding': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'permit-pty': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'permit-user-rc': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'permit-x11-forwarding': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-address': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_accessproxysshclientcert'),
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
