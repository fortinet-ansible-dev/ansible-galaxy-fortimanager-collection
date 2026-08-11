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
module: fmgr_user_local_dynamicmapping
short_description: Configure local users.
version_added: "2.15.0"
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
  local:
    description: The parameter (local) in requested url.
    type: str
    required: true
  user_local_dynamicmapping:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      _scope:
        type: list
        elements: dict
        description: Scope.
        suboptions:
          name:
            type: str
            description: Name.
          vdom:
            type: str
            description: Vdom.
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
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Source of truth for fabric object.
        choices: ['member', 'local', 'root']
      fortitoken:
        type: list
        elements: str
        description: Two-factor recipients FortiToken serial number.
      history0:
        type: list
        elements: str
        description: History0.
      history1:
        type: list
        elements: str
        description: History1.
      history10:
        type: list
        elements: str
        description: History10.
      history11:
        type: list
        elements: str
        description: History11.
      history12:
        type: list
        elements: str
        description: History12.
      history13:
        type: list
        elements: str
        description: History13.
      history14:
        type: list
        elements: str
        description: History14.
      history15:
        type: list
        elements: str
        description: History15.
      history16:
        type: list
        elements: str
        description: History16.
      history17:
        type: list
        elements: str
        description: History17.
      history18:
        type: list
        elements: str
        description: History18.
      history19:
        type: list
        elements: str
        description: History19.
      history2:
        type: list
        elements: str
        description: History2.
      history3:
        type: list
        elements: str
        description: History3.
      history4:
        type: list
        elements: str
        description: History4.
      history5:
        type: list
        elements: str
        description: History5.
      history6:
        type: list
        elements: str
        description: History6.
      history7:
        type: list
        elements: str
        description: History7.
      history8:
        type: list
        elements: str
        description: History8.
      history9:
        type: list
        elements: str
        description: History9.
      id:
        type: int
        description: Id.
      ldap_server:
        aliases: ['ldap-server']
        type: list
        elements: str
        description: Name of LDAP server with which the user must authenticate.
      passwd:
        type: list
        elements: str
        description: Users password.
      passwd_policy:
        aliases: ['passwd-policy']
        type: list
        elements: str
        description: Password policy to apply to this user, as defined in config user password-policy.
      passwd_time:
        aliases: ['passwd-time']
        type: str
        description: Time of the last password update.
      ppk_identity:
        aliases: ['ppk-identity']
        type: str
        description: IKEv2 Postquantum Preshared Key Identity.
      ppk_secret:
        aliases: ['ppk-secret']
        type: list
        elements: str
        description: IKEv2 Postquantum Preshared Key
      qkd_profile:
        aliases: ['qkd-profile']
        type: list
        elements: str
        description: Quantum Key Distribution
      radius_server:
        aliases: ['radius-server']
        type: list
        elements: str
        description: Name of RADIUS server with which the user must authenticate.
      saml_server:
        aliases: ['saml-server']
        type: list
        elements: str
        description: Name of SAML server with which the user must authenticate.
      sms_custom_server:
        aliases: ['sms-custom-server']
        type: list
        elements: str
        description: Two-factor recipients SMS server.
      sms_phone:
        aliases: ['sms-phone']
        type: str
        description: Two-factor recipients mobile phone number.
      sms_provider:
        aliases: ['sms-provider']
        type: list
        elements: str
        description: Sms provider.
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
        type: list
        elements: str
        description: Name of TACACS+ server with which the user must authenticate.
      two_factor:
        aliases: ['two-factor']
        type: str
        description: Enable/disable two-factor authentication.
        choices: ['disable', 'fortitoken', 'email', 'sms', 'fortitoken-cloud']
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
      type:
        type: str
        description: Authentication method.
        choices: ['password', 'radius', 'tacacs+', 'ldap', 'saml']
      username_case_insensitivity:
        aliases: ['username-case-insensitivity']
        type: str
        description: Username case insensitivity.
        choices: ['disable', 'enable']
      username_case_sensitivity:
        aliases: ['username-case-sensitivity']
        type: str
        description: Username case sensitivity.
        choices: ['disable', 'enable']
      username_sensitivity:
        aliases: ['username-sensitivity']
        type: str
        description: Enable/disable case and accent sensitivity when performing username matching
        choices: ['disable', 'enable']
      uuid:
        type: str
        description: Universally Unique Identifier
      workstation:
        type: str
        description: Name of the remote user workstation, if you want to limit the user to authenticate only from a particular workstation.
'''

EXAMPLES = '''
- name: Test local user dynamic mappings
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create the parent local user
      fortinet.fortimanager.fmgr_user_local:
        enable_log: true
        adom: root
        state: present
        user_local:
          name: test_local_user
          status: disable

    - name: Configure a local user dynamic mapping
      fortinet.fortimanager.fmgr_user_local_dynamicmapping:
        enable_log: true
        adom: root
        local: test_local_user
        user_local_dynamicmapping:
          _scope:
            - name: test_device
              vdom: root
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
        '/pm/config/adom/{adom}/obj/user/local/{local}/dynamic_mapping',
        '/pm/config/global/obj/user/local/{local}/dynamic_mapping'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'local': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_local_dynamicmapping': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                '_scope': {
                    'v_range': [['8.0.0', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['8.0.0', '']], 'type': 'str'}, 'vdom': {'v_range': [['8.0.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'auth-concurrent-override': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-concurrent-value': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'authtimeout': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'email-to': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'fortitoken': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'history0': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history1': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history10': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history11': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history12': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history13': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history14': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history15': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history16': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history17': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history18': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history19': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history2': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history3': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history4': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history5': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history6': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history7': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history8': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'history9': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'id': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'ldap-server': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'passwd': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'passwd-policy': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'passwd-time': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'str'},
                'ppk-identity': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ppk-secret': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'qkd-profile': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'radius-server': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'saml-server': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'sms-custom-server': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'sms-phone': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'sms-provider': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'sms-server': {'v_range': [['8.0.0', '']], 'choices': ['fortiguard', 'custom'], 'type': 'str'},
                'status': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tacacs+-server': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'two-factor': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'fortitoken', 'email', 'sms', 'fortitoken-cloud'], 'type': 'str'},
                'two-factor-authentication': {'v_range': [['8.0.0', '']], 'choices': ['fortitoken', 'email', 'sms'], 'type': 'str'},
                'two-factor-notification': {'v_range': [['8.0.0', '']], 'choices': ['email', 'sms'], 'type': 'str'},
                'type': {'v_range': [['8.0.0', '']], 'choices': ['password', 'radius', 'tacacs+', 'ldap', 'saml'], 'type': 'str'},
                'username-case-insensitivity': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'username-case-sensitivity': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'username-sensitivity': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'workstation': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_local_dynamicmapping'),
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
