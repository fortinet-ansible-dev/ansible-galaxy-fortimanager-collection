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
module: fmgr_user_local
short_description: Configure local users.
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
    user_local:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_concurrent_override:
                aliases: ['auth-concurrent-override']
                type: str
                description: Enable/disable overriding the policy-auth-concurrent under config system global.
                choices: ['disable', 'enable']
            auth_concurrent_value:
                aliases: ['auth-concurrent-value']
                type: int
                description: Maximum number of concurrent logins permitted from the same user.
            authtimeout:
                type: int
                description: Time in minutes before the authentication timeout for a user is reached.
            email_to:
                aliases: ['email-to']
                type: str
                description: Two-factor recipients email address.
            fortitoken:
                type: str
                description: Two-factor recipients FortiToken serial number.
            id:
                type: int
                description: User ID.
            ldap_server:
                aliases: ['ldap-server']
                type: str
                description: Name of LDAP server with which the user must authenticate.
            name:
                type: str
                description: User name.
                required: true
            passwd:
                type: raw
                description: (list) Users password.
            passwd_policy:
                aliases: ['passwd-policy']
                type: str
                description: Password policy to apply to this user, as defined in config user password-policy.
            ppk_identity:
                aliases: ['ppk-identity']
                type: str
                description: IKEv2 Postquantum Preshared Key Identity.
            ppk_secret:
                aliases: ['ppk-secret']
                type: raw
                description: (list) IKEv2 Postquantum Preshared Key
            radius_server:
                aliases: ['radius-server']
                type: str
                description: Name of RADIUS server with which the user must authenticate.
            sms_custom_server:
                aliases: ['sms-custom-server']
                type: str
                description: Two-factor recipients SMS server.
            sms_phone:
                aliases: ['sms-phone']
                type: str
                description: Two-factor recipients mobile phone number.
            sms_server:
                aliases: ['sms-server']
                type: str
                description: Send SMS through FortiGuard or other external server.
                choices: ['fortiguard', 'custom']
            status:
                type: str
                description: Enable/disable allowing the local user to authenticate with the FortiGate unit.
                choices: ['disable', 'enable']
            tacacs__server:
                aliases: ['tacacs+-server']
                type: str
                description: Name of TACACS+ server with which the user must authenticate.
            two_factor:
                aliases: ['two-factor']
                type: str
                description: Enable/disable two-factor authentication.
                choices: ['disable', 'fortitoken', 'email', 'sms', 'fortitoken-cloud']
            type:
                type: str
                description: Authentication method.
                choices: ['password', 'radius', 'tacacs+', 'ldap', 'saml']
            workstation:
                type: str
                description: Name of the remote user workstation, if you want to limit the user to authenticate only from a particular workstation.
            two_factor_authentication:
                aliases: ['two-factor-authentication']
                type: str
                description: Authentication method by FortiToken Cloud.
                choices: ['fortitoken', 'email', 'sms']
            two_factor_notification:
                aliases: ['two-factor-notification']
                type: str
                description: Notification method for user activation by FortiToken Cloud.
                choices: ['email', 'sms']
            username_case_sensitivity:
                aliases: ['username-case-sensitivity']
                type: str
                description: Enable/disable case sensitivity when performing username matching
                choices: ['disable', 'enable']
            username_case_insensitivity:
                aliases: ['username-case-insensitivity']
                type: str
                description: Enable/disable case sensitivity when performing username matching
                choices: ['disable', 'enable']
            username_sensitivity:
                aliases: ['username-sensitivity']
                type: str
                description: Enable/disable case and accent sensitivity when performing username matching
                choices: ['disable', 'enable']
            history0:
                type: raw
                description: (list) History0.
            history1:
                type: raw
                description: (list) History1.
            qkd_profile:
                aliases: ['qkd-profile']
                type: str
                description: Quantum Key Distribution
            saml_server:
                aliases: ['saml-server']
                type: raw
                description: (list) Name of SAML server with which the user must authenticate.
            history10:
                type: raw
                description: (list) History10.
            history11:
                type: raw
                description: (list) History11.
            history12:
                type: raw
                description: (list) History12.
            history13:
                type: raw
                description: (list) History13.
            history14:
                type: raw
                description: (list) History14.
            history15:
                type: raw
                description: (list) History15.
            history16:
                type: raw
                description: (list) History16.
            history17:
                type: raw
                description: (list) History17.
            history18:
                type: raw
                description: (list) History18.
            history19:
                type: raw
                description: (list) History19.
            history2:
                type: raw
                description: (list) History2.
            history3:
                type: raw
                description: (list) History3.
            history4:
                type: raw
                description: (list) History4.
            history5:
                type: raw
                description: (list) History5.
            history6:
                type: raw
                description: (list) History6.
            history7:
                type: raw
                description: (list) History7.
            history8:
                type: raw
                description: (list) History8.
            history9:
                type: raw
                description: (list) History9.
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
    - name: Configure local users.
      fortinet.fortimanager.fmgr_user_local:
        bypass_validation: false
        adom: ansible
        state: present
        user_local:
          id: 1
          name: ansible-test-local
          passwd: fortinet
          status: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the local users
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "user_local"
          params:
            adom: "ansible"
            local: "your_value"
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
        '/pm/config/adom/{adom}/obj/user/local',
        '/pm/config/global/obj/user/local'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_local': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'auth-concurrent-override': {'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-concurrent-value': {'type': 'int'},
                'authtimeout': {'type': 'int'},
                'email-to': {'type': 'str'},
                'fortitoken': {'no_log': True, 'type': 'str'},
                'id': {'type': 'int'},
                'ldap-server': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'passwd': {'no_log': True, 'type': 'raw'},
                'passwd-policy': {'no_log': True, 'type': 'str'},
                'ppk-identity': {'type': 'str'},
                'ppk-secret': {'no_log': True, 'type': 'raw'},
                'radius-server': {'type': 'str'},
                'sms-custom-server': {'type': 'str'},
                'sms-phone': {'type': 'str'},
                'sms-server': {'choices': ['fortiguard', 'custom'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tacacs+-server': {'type': 'str'},
                'two-factor': {'choices': ['disable', 'fortitoken', 'email', 'sms', 'fortitoken-cloud'], 'type': 'str'},
                'type': {'choices': ['password', 'radius', 'tacacs+', 'ldap', 'saml'], 'type': 'str'},
                'workstation': {'type': 'str'},
                'two-factor-authentication': {'v_range': [['6.2.5', '']], 'choices': ['fortitoken', 'email', 'sms'], 'type': 'str'},
                'two-factor-notification': {'v_range': [['6.2.5', '']], 'choices': ['email', 'sms'], 'type': 'str'},
                'username-case-sensitivity': {'v_range': [['6.2.5', '6.2.13'], ['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'username-case-insensitivity': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'username-sensitivity': {
                    'v_range': [['6.2.9', '6.2.13'], ['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'history0': {'v_range': [['7.4.1', '']], 'type': 'raw'},
                'history1': {'v_range': [['7.4.1', '']], 'type': 'raw'},
                'qkd-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'saml-server': {'v_range': [['7.6.3', '']], 'type': 'raw'},
                'history10': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history11': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history12': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history13': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history14': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history15': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history16': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history17': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history18': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history19': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history2': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history3': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history4': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history5': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history6': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history7': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history8': {'v_range': [['7.6.4', '']], 'type': 'raw'},
                'history9': {'v_range': [['7.6.4', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_local'),
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
