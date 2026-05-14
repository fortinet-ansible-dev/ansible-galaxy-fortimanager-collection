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
module: fmgr_user_peer
short_description: Configure peer users.
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
    user_peer:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ca:
                type: str
                description: Name of the CA certificate as returned by the execute vpn certificate ca list command.
            cn:
                type: str
                description: Peer certificate common name.
            cn_type:
                aliases: ['cn-type']
                type: str
                description: Peer certificate common name type.
                choices: ['string', 'email', 'FQDN', 'ipv4', 'ipv6']
            ldap_mode:
                aliases: ['ldap-mode']
                type: str
                description: Mode for LDAP peer authentication.
                choices: ['password', 'principal-name']
            ldap_password:
                aliases: ['ldap-password']
                type: raw
                description: (list) Password for LDAP server bind.
            ldap_server:
                aliases: ['ldap-server']
                type: str
                description: Name of an LDAP server defined under the user ldap command.
            ldap_username:
                aliases: ['ldap-username']
                type: str
                description: Username for LDAP server bind.
            mandatory_ca_verify:
                aliases: ['mandatory-ca-verify']
                type: str
                description: Determine what happens to the peer if the CA certificate is not installed.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Peer name.
                required: true
            ocsp_override_server:
                aliases: ['ocsp-override-server']
                type: str
                description: Online Certificate Status Protocol
            passwd:
                type: raw
                description: (list) Peers password used for two-factor authentication.
            subject:
                type: str
                description: Peer certificate name constraints.
            two_factor:
                aliases: ['two-factor']
                type: str
                description: Enable/disable two-factor authentication, applying certificate and password-based authentication.
                choices: ['disable', 'enable']
            mfa_mode:
                aliases: ['mfa-mode']
                type: str
                description: MFA mode for remote peer authentication/authorization.
                choices: ['none', 'password', 'subject-identity']
            mfa_password:
                aliases: ['mfa-password']
                type: raw
                description: (list) Unified password for remote authentication.
            mfa_server:
                aliases: ['mfa-server']
                type: str
                description: Name of a remote authenticator.
            mfa_username:
                aliases: ['mfa-username']
                type: str
                description: Unified username for remote authentication.
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure peer users.
      fortinet.fortimanager.fmgr_user_peer:
        bypass_validation: false
        adom: ansible
        state: present
        user_peer:
          cn_type: email # <value in [string, email, FQDN, ...]>
          name: ansible-test-peer
          passwd: fortinet

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the peer users
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "user_peer"
          params:
            adom: "ansible"
            peer: "your_value"
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
        '/pm/config/adom/{adom}/obj/user/peer',
        '/pm/config/global/obj/user/peer'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_peer': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'ca': {'type': 'str'},
                'cn': {'type': 'str'},
                'cn-type': {'choices': ['string', 'email', 'FQDN', 'ipv4', 'ipv6'], 'type': 'str'},
                'ldap-mode': {'choices': ['password', 'principal-name'], 'type': 'str'},
                'ldap-password': {'no_log': True, 'type': 'raw'},
                'ldap-server': {'type': 'str'},
                'ldap-username': {'type': 'str'},
                'mandatory-ca-verify': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'ocsp-override-server': {'type': 'str'},
                'passwd': {'no_log': True, 'type': 'raw'},
                'subject': {'type': 'str'},
                'two-factor': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mfa-mode': {'v_range': [['7.4.1', '']], 'choices': ['none', 'password', 'subject-identity'], 'type': 'str'},
                'mfa-password': {'v_range': [['7.4.1', '']], 'no_log': True, 'type': 'raw'},
                'mfa-server': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'mfa-username': {'v_range': [['7.4.1', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_peer'),
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
