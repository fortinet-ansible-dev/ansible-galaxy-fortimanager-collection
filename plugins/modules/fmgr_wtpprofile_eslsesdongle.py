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
module: fmgr_wtpprofile_eslsesdongle
short_description: ESL SES-imagotag dongle configuration.
version_added: "2.1.0"
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
    wtp-profile:
        description: Deprecated, please use "wtp_profile"
        type: str
    wtp_profile:
        description: The parameter (wtp-profile) in requested url.
        type: str
    wtpprofile_eslsesdongle:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            apc_addr_type:
                aliases: ['apc-addr-type']
                type: str
                description: ESL SES-imagotag APC address type
                choices: ['fqdn', 'ip']
            apc_fqdn:
                aliases: ['apc-fqdn']
                type: str
                description: FQDN of ESL SES-imagotag Access Point Controller
            apc_ip:
                aliases: ['apc-ip']
                type: str
                description: IP address of ESL SES-imagotag Access Point Controller
            apc_port:
                aliases: ['apc-port']
                type: int
                description: Port of ESL SES-imagotag Access Point Controller
            coex_level:
                aliases: ['coex-level']
                type: str
                description: ESL SES-imagotag dongle coexistence level
                choices: ['none']
            compliance_level:
                aliases: ['compliance-level']
                type: str
                description: Compliance levels for the ESL solution integration
                choices: ['compliance-level-2']
            esl_channel:
                aliases: ['esl-channel']
                type: str
                description: ESL SES-imagotag dongle channel
                choices: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '127', '-1']
            output_power:
                aliases: ['output-power']
                type: str
                description: ESL SES-imagotag dongle output power
                choices: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']
            scd_enable:
                aliases: ['scd-enable']
                type: str
                description: Enable/disable ESL SES-imagotag Serial Communication Daemon
                choices: ['disable', 'enable']
            tls_cert_verification:
                aliases: ['tls-cert-verification']
                type: str
                description: Enable/disable TLS certificate verification
                choices: ['disable', 'enable']
            tls_fqdn_verification:
                aliases: ['tls-fqdn-verification']
                type: str
                description: Enable/disable TLS certificate verification
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: ESL SES-imagotag dongle configuration.
      fortinet.fortimanager.fmgr_wtpprofile_eslsesdongle:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        wtp_profile: <your own value>
        wtpprofile_eslsesdongle:
          # apc_addr_type: <value in [fqdn, ip]>
          # apc_fqdn: <string>
          # apc_ip: <string>
          # apc_port: <integer>
          # coex_level: <value in [none]>
          # compliance_level: <value in [compliance-level-2]>
          # esl_channel: <value in [0, 1, 2, ...]>
          # output_power: <value in [a, b, c, ...]>
          # scd_enable: <value in [disable, enable]>
          # tls_cert_verification: <value in [disable, enable]>
          # tls_fqdn_verification: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/esl-ses-dongle',
        '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/esl-ses-dongle'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'wtp-profile': {'type': 'str', 'api_name': 'wtp_profile'},
        'wtp_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'wtpprofile_eslsesdongle': {
            'type': 'dict', 'v_range': [['7.0.1', '']],
            'options': {
                'apc-addr-type': {'v_range': [['7.0.1', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                'apc-fqdn': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'apc-ip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'apc-port': {'v_range': [['7.0.1', '']], 'type': 'int'},
                'coex-level': {'v_range': [['7.0.1', '']], 'choices': ['none'], 'type': 'str'},
                'compliance-level': {'v_range': [['7.0.1', '']], 'choices': ['compliance-level-2'], 'type': 'str'},
                'esl-channel': {
                    'v_range': [['7.0.1', '']],
                    'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '127', '-1'],
                    'type': 'str'
                },
                'output-power': {'v_range': [['7.0.1', '']], 'choices': ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'], 'type': 'str'},
                'scd-enable': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tls-cert-verification': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tls-fqdn-verification': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wtpprofile_eslsesdongle'),
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
