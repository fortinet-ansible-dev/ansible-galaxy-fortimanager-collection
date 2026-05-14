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
module: fmgr_user_scim
short_description: Configure SCIM client entries.
version_added: "2.10.0"
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
    user_scim:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_method:
                aliases: ['auth-method']
                type: str
                description: TLS client authentication methods
                choices: ['token', 'base']
            base_url:
                aliases: ['base-url']
                type: str
                description: Server URL to receive SCIM create, read, update, delete
            certificate:
                type: list
                elements: str
                description: Certificate for client verification during TLS handshake.
            client_authentication_method:
                aliases: ['client-authentication-method']
                type: str
                description: Client authentication method.
                choices: ['token', 'base']
            client_identity_check:
                aliases: ['client-identity-check']
                type: str
                description: Enable/disable client identity check.
                choices: ['disable', 'enable']
            client_secret_token:
                aliases: ['client-secret-token']
                type: str
                description: Client secret token.
            id:
                type: int
                description: SCIM client ID.
                required: true
            name:
                type: str
                description: SCIM client name.
            secret:
                type: list
                elements: str
                description: Secret for token verification or base authentication.
            status:
                type: str
                description: Enable/disable System for Cross-domain Identity Management
                choices: ['disable', 'enable']
            token_certificate:
                aliases: ['token-certificate']
                type: list
                elements: str
                description: Certificate for token verification.
            cascade:
                type: str
                description: Enable/disable to follow SCIM users/groups changes in IDP.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure SCIM client entries.
      fortinet.fortimanager.fmgr_user_scim:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        user_scim:
          id: 0 # Required variable, integer
          # auth_method: <value in [token, base]>
          # base_url: <string>
          # certificate: <list or string>
          # client_authentication_method: <value in [token, base]>
          # client_identity_check: <value in [disable, enable]>
          # client_secret_token: <string>
          # name: <string>
          # secret: <list or string>
          # status: <value in [disable, enable]>
          # token_certificate: <list or string>
          # cascade: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/user/scim',
        '/pm/config/global/obj/user/scim'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_scim': {
            'type': 'dict', 'v_range': [['7.6.3', '']],
            'options': {
                'auth-method': {'v_range': [['7.6.3', '']], 'choices': ['token', 'base'], 'type': 'str'},
                'base-url': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'certificate': {'v_range': [['7.6.3', '']], 'type': 'list', 'elements': 'str'},
                'client-authentication-method': {'v_range': [['7.6.3', '']], 'choices': ['token', 'base'], 'type': 'str'},
                'client-identity-check': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-secret-token': {'v_range': [['7.6.3', '']], 'no_log': True, 'type': 'str'},
                'id': {'v_range': [['7.6.3', '']], 'required': True, 'type': 'int'},
                'name': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'secret': {'v_range': [['7.6.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'token-certificate': {'v_range': [['7.6.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'cascade': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_scim'),
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
