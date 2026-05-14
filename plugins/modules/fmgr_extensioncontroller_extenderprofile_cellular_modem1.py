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
module: fmgr_extensioncontroller_extenderprofile_cellular_modem1
short_description: Configuration options for modem 1.
version_added: "2.2.0"
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
    extender-profile:
        description: Deprecated, please use "extender_profile"
        type: str
    extender_profile:
        description: The parameter (extender-profile) in requested url.
        type: str
    extensioncontroller_extenderprofile_cellular_modem1:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auto_switch:
                aliases: ['auto-switch']
                type: dict
                description: Auto switch.
                suboptions:
                    dataplan:
                        type: str
                        description: Automatically switch based on data usage.
                        choices: ['disable', 'enable']
                    disconnect:
                        type: str
                        description: Auto switch by disconnect.
                        choices: ['disable', 'enable']
                    disconnect_period:
                        aliases: ['disconnect-period']
                        type: int
                        description: Automatically switch based on disconnect period.
                    disconnect_threshold:
                        aliases: ['disconnect-threshold']
                        type: int
                        description: Automatically switch based on disconnect threshold.
                    signal:
                        type: str
                        description: Automatically switch based on signal strength.
                        choices: ['disable', 'enable']
                    switch_back:
                        aliases: ['switch-back']
                        type: list
                        elements: str
                        description: Auto switch with switch back multi-options.
                        choices: ['time', 'timer']
                    switch_back_time:
                        aliases: ['switch-back-time']
                        type: str
                        description: Automatically switch over to preferred SIM/carrier at a specified time in UTC
                    switch_back_timer:
                        aliases: ['switch-back-timer']
                        type: int
                        description: Automatically switch over to preferred SIM/carrier after the given time
            conn_status:
                aliases: ['conn-status']
                type: int
                description: Conn status.
            default_sim:
                aliases: ['default-sim']
                type: str
                description: Default SIM selection.
                choices: ['sim1', 'sim2', 'carrier', 'cost']
            gps:
                type: str
                description: FortiExtender GPS enable/disable.
                choices: ['disable', 'enable']
            modem_id:
                aliases: ['modem-id']
                type: int
                description: Modem ID.
            preferred_carrier:
                aliases: ['preferred-carrier']
                type: str
                description: Preferred carrier.
            redundant_intf:
                aliases: ['redundant-intf']
                type: str
                description: Redundant interface.
            redundant_mode:
                aliases: ['redundant-mode']
                type: str
                description: FortiExtender mode.
                choices: ['disable', 'enable']
            sim1_pin:
                aliases: ['sim1-pin']
                type: str
                description: SIM #1 PIN status.
                choices: ['disable', 'enable']
            sim1_pin_code:
                aliases: ['sim1-pin-code']
                type: raw
                description: (list) SIM #1 PIN password.
            sim2_pin:
                aliases: ['sim2-pin']
                type: str
                description: SIM #2 PIN status.
                choices: ['disable', 'enable']
            sim2_pin_code:
                aliases: ['sim2-pin-code']
                type: raw
                description: (list) SIM #2 PIN password.
            multiple_PDN:
                aliases: ['multiple-PDN']
                type: str
                description: Multiple-PDN enable/disable.
                choices: ['disable', 'enable']
            pdn1_dataplan:
                aliases: ['pdn1-dataplan']
                type: raw
                description: (list) PDN1-dataplan.
            pdn2_dataplan:
                aliases: ['pdn2-dataplan']
                type: raw
                description: (list) PDN2-dataplan.
            pdn3_dataplan:
                aliases: ['pdn3-dataplan']
                type: raw
                description: (list) PDN3-dataplan.
            pdn4_dataplan:
                aliases: ['pdn4-dataplan']
                type: raw
                description: (list) PDN4-dataplan.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configuration options for modem 1.
      fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_cellular_modem1:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        extender_profile: <your own value>
        extensioncontroller_extenderprofile_cellular_modem1:
          # auto_switch:
          #   dataplan: <value in [disable, enable]>
          #   disconnect: <value in [disable, enable]>
          #   disconnect_period: <integer>
          #   disconnect_threshold: <integer>
          #   signal: <value in [disable, enable]>
          #   switch_back: ["time", "timer"]
          #   switch_back_time: <string>
          #   switch_back_timer: <integer>
          # conn_status: <integer>
          # default_sim: <value in [sim1, sim2, carrier, ...]>
          # gps: <value in [disable, enable]>
          # modem_id: <integer>
          # preferred_carrier: <string>
          # redundant_intf: <string>
          # redundant_mode: <value in [disable, enable]>
          # sim1_pin: <value in [disable, enable]>
          # sim1_pin_code: <list or string>
          # sim2_pin: <value in [disable, enable]>
          # sim2_pin_code: <list or string>
          # multiple_PDN: <value in [disable, enable]>
          # pdn1_dataplan: <list or string>
          # pdn2_dataplan: <list or string>
          # pdn3_dataplan: <list or string>
          # pdn4_dataplan: <list or string>
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
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/modem1',
        '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/modem1'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'extender-profile': {'type': 'str', 'api_name': 'extender_profile'},
        'extender_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'extensioncontroller_extenderprofile_cellular_modem1': {
            'type': 'dict', 'v_range': [['7.2.1', '']],
            'options': {
                'auto-switch': {
                    'v_range': [['7.2.1', '']],
                    'type': 'dict',
                    'options': {
                        'dataplan': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'disconnect': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'disconnect-period': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'disconnect-threshold': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'signal': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'switch-back': {'v_range': [['7.2.1', '']], 'type': 'list', 'choices': ['time', 'timer'], 'elements': 'str'},
                        'switch-back-time': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'switch-back-timer': {'v_range': [['7.2.1', '']], 'type': 'int'}
                    }
                },
                'conn-status': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'default-sim': {'v_range': [['7.2.1', '']], 'choices': ['sim1', 'sim2', 'carrier', 'cost'], 'type': 'str'},
                'gps': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'modem-id': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'preferred-carrier': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'redundant-intf': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'redundant-mode': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sim1-pin': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sim1-pin-code': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'sim2-pin': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sim2-pin-code': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'multiple-PDN': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pdn1-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                'pdn2-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                'pdn3-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'},
                'pdn4-dataplan': {'v_range': [['7.6.2', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extenderprofile_cellular_modem1'),
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
