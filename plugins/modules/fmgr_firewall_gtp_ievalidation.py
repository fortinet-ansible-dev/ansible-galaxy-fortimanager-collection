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
module: fmgr_firewall_gtp_ievalidation
short_description: IE validation.
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
    gtp:
        description: The parameter (gtp) in requested url.
        type: str
        required: true
    firewall_gtp_ievalidation:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            apn_restriction:
                aliases: ['apn-restriction']
                type: str
                description: Validate APN restriction.
                choices: ['disable', 'enable']
            charging_ID:
                aliases: ['charging-ID']
                type: str
                description: Validate charging ID.
                choices: ['disable', 'enable']
            charging_gateway_addr:
                aliases: ['charging-gateway-addr']
                type: str
                description: Validate charging gateway address.
                choices: ['disable', 'enable']
            end_user_addr:
                aliases: ['end-user-addr']
                type: str
                description: Validate end user address.
                choices: ['disable', 'enable']
            gsn_addr:
                aliases: ['gsn-addr']
                type: str
                description: Validate GSN address.
                choices: ['disable', 'enable']
            imei:
                type: str
                description: Validate IMEI
                choices: ['disable', 'enable']
            imsi:
                type: str
                description: Validate IMSI.
                choices: ['disable', 'enable']
            mm_context:
                aliases: ['mm-context']
                type: str
                description: Validate MM context.
                choices: ['disable', 'enable']
            ms_tzone:
                aliases: ['ms-tzone']
                type: str
                description: Validate MS time zone.
                choices: ['disable', 'enable']
            ms_validated:
                aliases: ['ms-validated']
                type: str
                description: Validate MS validated.
                choices: ['disable', 'enable']
            msisdn:
                type: str
                description: Validate MSISDN.
                choices: ['disable', 'enable']
            nsapi:
                type: str
                description: Validate NSAPI.
                choices: ['disable', 'enable']
            pdp_context:
                aliases: ['pdp-context']
                type: str
                description: Validate PDP context.
                choices: ['disable', 'enable']
            qos_profile:
                aliases: ['qos-profile']
                type: str
                description: Validate Quality of Service
                choices: ['disable', 'enable']
            rai:
                type: str
                description: Validate RAI.
                choices: ['disable', 'enable']
            rat_type:
                aliases: ['rat-type']
                type: str
                description: Validate RAT type.
                choices: ['disable', 'enable']
            reordering_required:
                aliases: ['reordering-required']
                type: str
                description: Validate re-ordering required.
                choices: ['disable', 'enable']
            selection_mode:
                aliases: ['selection-mode']
                type: str
                description: Validate selection mode.
                choices: ['disable', 'enable']
            uli:
                type: str
                description: Validate user location information.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: IE validation.
      fortinet.fortimanager.fmgr_firewall_gtp_ievalidation:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        gtp: <your own value>
        firewall_gtp_ievalidation:
          # apn_restriction: <value in [disable, enable]>
          # charging_ID: <value in [disable, enable]>
          # charging_gateway_addr: <value in [disable, enable]>
          # end_user_addr: <value in [disable, enable]>
          # gsn_addr: <value in [disable, enable]>
          # imei: <value in [disable, enable]>
          # imsi: <value in [disable, enable]>
          # mm_context: <value in [disable, enable]>
          # ms_tzone: <value in [disable, enable]>
          # ms_validated: <value in [disable, enable]>
          # msisdn: <value in [disable, enable]>
          # nsapi: <value in [disable, enable]>
          # pdp_context: <value in [disable, enable]>
          # qos_profile: <value in [disable, enable]>
          # rai: <value in [disable, enable]>
          # rat_type: <value in [disable, enable]>
          # reordering_required: <value in [disable, enable]>
          # selection_mode: <value in [disable, enable]>
          # uli: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-validation',
        '/pm/config/global/obj/firewall/gtp/{gtp}/ie-validation'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'gtp': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_gtp_ievalidation': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'apn-restriction': {'choices': ['disable', 'enable'], 'type': 'str'},
                'charging-ID': {'choices': ['disable', 'enable'], 'type': 'str'},
                'charging-gateway-addr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'end-user-addr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'gsn-addr': {'choices': ['disable', 'enable'], 'type': 'str'},
                'imei': {'choices': ['disable', 'enable'], 'type': 'str'},
                'imsi': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mm-context': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ms-tzone': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ms-validated': {'choices': ['disable', 'enable'], 'type': 'str'},
                'msisdn': {'choices': ['disable', 'enable'], 'type': 'str'},
                'nsapi': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pdp-context': {'choices': ['disable', 'enable'], 'type': 'str'},
                'qos-profile': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rai': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rat-type': {'choices': ['disable', 'enable'], 'type': 'str'},
                'reordering-required': {'choices': ['disable', 'enable'], 'type': 'str'},
                'selection-mode': {'choices': ['disable', 'enable'], 'type': 'str'},
                'uli': {'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_gtp_ievalidation'),
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
