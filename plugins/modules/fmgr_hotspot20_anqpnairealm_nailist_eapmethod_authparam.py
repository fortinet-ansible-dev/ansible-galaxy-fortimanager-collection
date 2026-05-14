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
module: fmgr_hotspot20_anqpnairealm_nailist_eapmethod_authparam
short_description: EAP auth param.
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
    anqp-nai-realm:
        description: Deprecated, please use "anqp_nai_realm"
        type: str
    anqp_nai_realm:
        description: The parameter (anqp-nai-realm) in requested url.
        type: str
    nai-list:
        description: Deprecated, please use "nai_list"
        type: str
    nai_list:
        description: The parameter (nai-list) in requested url.
        type: str
    eap-method:
        description: Deprecated, please use "eap_method"
        type: str
    eap_method:
        description: The parameter (eap-method) in requested url.
        type: str
    hotspot20_anqpnairealm_nailist_eapmethod_authparam:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            id:
                type: str
                description: ID of authentication parameter.
                choices: ['non-eap-inner-auth', 'inner-auth-eap', 'credential',
                          'tunneled-credential']
            index:
                type: int
                description: Param index.
                required: true
            val:
                type: str
                description: Value of authentication parameter.
                choices: ['eap-identity', 'eap-md5', 'eap-tls', 'eap-ttls', 'eap-peap', 'eap-sim',
                          'eap-aka', 'eap-aka-prime', 'non-eap-pap', 'non-eap-chap',
                          'non-eap-mschap', 'non-eap-mschapv2', 'cred-sim', 'cred-usim',
                          'cred-nfc', 'cred-hardware-token', 'cred-softoken', 'cred-certificate',
                          'cred-user-pwd', 'cred-none', 'cred-vendor-specific', 'tun-cred-sim',
                          'tun-cred-usim', 'tun-cred-nfc', 'tun-cred-hardware-token',
                          'tun-cred-softoken', 'tun-cred-certificate', 'tun-cred-user-pwd',
                          'tun-cred-anonymous', 'tun-cred-vendor-specific']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: EAP auth param.
      ? fortinet.fortimanager.fmgr_hotspot20_anqpnairealm_nailist_eapmethod_authparam
      : # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        anqp_nai_realm: <your own value>
        nai_list: <your own value>
        eap_method: <your own value>
        state: present # <value in [present, absent]>
        hotspot20_anqpnairealm_nailist_eapmethod_authparam:
          index: 0 # Required variable, integer
          id: "non-eap-inner-auth" # <value in [non-eap-inner-auth, inner-auth-eap, credential, ...]>
          # val: <value in [eap-identity, eap-md5, eap-tls, ...]>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-param',
        '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-param'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'anqp-nai-realm': {'type': 'str', 'api_name': 'anqp_nai_realm'},
        'anqp_nai_realm': {'type': 'str'},
        'nai-list': {'type': 'str', 'api_name': 'nai_list'},
        'nai_list': {'type': 'str'},
        'eap-method': {'type': 'str', 'api_name': 'eap_method'},
        'eap_method': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'hotspot20_anqpnairealm_nailist_eapmethod_authparam': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'id': {'choices': ['non-eap-inner-auth', 'inner-auth-eap', 'credential', 'tunneled-credential'], 'type': 'str'},
                'index': {'required': True, 'type': 'int'},
                'val': {
                    'choices': [
                        'eap-identity', 'eap-md5', 'eap-tls', 'eap-ttls', 'eap-peap', 'eap-sim', 'eap-aka', 'eap-aka-prime', 'non-eap-pap',
                        'non-eap-chap', 'non-eap-mschap', 'non-eap-mschapv2', 'cred-sim', 'cred-usim', 'cred-nfc', 'cred-hardware-token',
                        'cred-softoken', 'cred-certificate', 'cred-user-pwd', 'cred-none', 'cred-vendor-specific', 'tun-cred-sim', 'tun-cred-usim',
                        'tun-cred-nfc', 'tun-cred-hardware-token', 'tun-cred-softoken', 'tun-cred-certificate', 'tun-cred-user-pwd',
                        'tun-cred-anonymous', 'tun-cred-vendor-specific'
                    ],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'hotspot20_anqpnairealm_nailist_eapmethod_authparam'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'index', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
