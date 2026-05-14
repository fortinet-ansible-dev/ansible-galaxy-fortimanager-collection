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
module: fmgr_hotspot20_anqpnairealm_nailist_eapmethod
short_description: EAP Methods.
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
    hotspot20_anqpnairealm_nailist_eapmethod:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_param:
                aliases: ['auth-param']
                type: list
                elements: dict
                description: Auth param.
                suboptions:
                    id:
                        type: str
                        description: ID of authentication parameter.
                        choices: ['non-eap-inner-auth', 'inner-auth-eap', 'credential',
                                  'tunneled-credential']
                    index:
                        type: int
                        description: Param index.
                    val:
                        type: str
                        description: Value of authentication parameter.
                        choices: ['eap-identity', 'eap-md5', 'eap-tls', 'eap-ttls', 'eap-peap',
                                  'eap-sim', 'eap-aka', 'eap-aka-prime', 'non-eap-pap',
                                  'non-eap-chap', 'non-eap-mschap', 'non-eap-mschapv2',
                                  'cred-sim', 'cred-usim', 'cred-nfc', 'cred-hardware-token',
                                  'cred-softoken', 'cred-certificate', 'cred-user-pwd',
                                  'cred-none', 'cred-vendor-specific', 'tun-cred-sim',
                                  'tun-cred-usim', 'tun-cred-nfc', 'tun-cred-hardware-token',
                                  'tun-cred-softoken', 'tun-cred-certificate',
                                  'tun-cred-user-pwd', 'tun-cred-anonymous',
                                  'tun-cred-vendor-specific']
            index:
                type: int
                description: EAP method index.
                required: true
            method:
                type: str
                description: EAP method type.
                choices: ['eap-identity', 'eap-md5', 'eap-tls', 'eap-ttls', 'eap-peap', 'eap-sim',
                          'eap-aka', 'eap-aka-prime']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: EAP Methods.
      fortinet.fortimanager.fmgr_hotspot20_anqpnairealm_nailist_eapmethod:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        anqp_nai_realm: <your own value>
        nai_list: <your own value>
        state: present # <value in [present, absent]>
        hotspot20_anqpnairealm_nailist_eapmethod:
          index: 0 # Required variable, integer
          # auth_param:
          #   - id: <value in [non-eap-inner-auth, inner-auth-eap, credential, ...]>
          #     index: <integer>
          #     val: <value in [eap-identity, eap-md5, eap-tls, ...]>
          # method: <value in [eap-identity, eap-md5, eap-tls, ...]>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method',
        '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'anqp-nai-realm': {'type': 'str', 'api_name': 'anqp_nai_realm'},
        'anqp_nai_realm': {'type': 'str'},
        'nai-list': {'type': 'str', 'api_name': 'nai_list'},
        'nai_list': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'hotspot20_anqpnairealm_nailist_eapmethod': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'auth-param': {
                    'type': 'list',
                    'options': {
                        'id': {'choices': ['non-eap-inner-auth', 'inner-auth-eap', 'credential', 'tunneled-credential'], 'type': 'str'},
                        'index': {'type': 'int'},
                        'val': {
                            'choices': [
                                'eap-identity', 'eap-md5', 'eap-tls', 'eap-ttls', 'eap-peap', 'eap-sim', 'eap-aka', 'eap-aka-prime', 'non-eap-pap',
                                'non-eap-chap', 'non-eap-mschap', 'non-eap-mschapv2', 'cred-sim', 'cred-usim', 'cred-nfc', 'cred-hardware-token',
                                'cred-softoken', 'cred-certificate', 'cred-user-pwd', 'cred-none', 'cred-vendor-specific', 'tun-cred-sim',
                                'tun-cred-usim', 'tun-cred-nfc', 'tun-cred-hardware-token', 'tun-cred-softoken', 'tun-cred-certificate',
                                'tun-cred-user-pwd', 'tun-cred-anonymous', 'tun-cred-vendor-specific'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'index': {'required': True, 'type': 'int'},
                'method': {
                    'choices': ['eap-identity', 'eap-md5', 'eap-tls', 'eap-ttls', 'eap-peap', 'eap-sim', 'eap-aka', 'eap-aka-prime'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'hotspot20_anqpnairealm_nailist_eapmethod'),
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
