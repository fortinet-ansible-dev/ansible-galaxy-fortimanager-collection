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
module: fmgr_extensioncontroller_extenderprofile_wifi_radio2
short_description: Radio-2 config for Wi-Fi 5GHz
version_added: "2.6.0"
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
    extensioncontroller_extenderprofile_wifi_radio2:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            d80211d:
                aliases: ['80211d']
                type: str
                description: Enable/disable Wi-Fi 802.
                choices: ['disable', 'enable']
            band:
                type: str
                description: Wi-Fi band selection 2.
                choices: ['5GHz']
            bandwidth:
                type: str
                description: Wi-Fi channel bandwidth.
                choices: ['auto', '20MHz', '40MHz', '80MHz']
            beacon_interval:
                aliases: ['beacon-interval']
                type: int
                description: Wi-Fi beacon interval in miliseconds
            bss_color:
                aliases: ['bss-color']
                type: int
                description: Wi-Fi 802.
            bss_color_mode:
                aliases: ['bss-color-mode']
                type: str
                description: Wi-Fi 802.
                choices: ['auto', 'static']
            channel:
                type: list
                elements: str
                description: Wi-Fi channels.
                choices: ['CH36', 'CH40', 'CH44', 'CH48', 'CH52', 'CH56', 'CH60', 'CH64', 'CH100',
                          'CH104', 'CH108', 'CH112', 'CH116', 'CH120', 'CH124', 'CH128', 'CH132',
                          'CH136', 'CH140', 'CH144', 'CH149', 'CH153', 'CH157', 'CH161', 'CH165']
            extension_channel:
                aliases: ['extension-channel']
                type: str
                description: Wi-Fi extension channel.
                choices: ['auto', 'higher', 'lower']
            guard_interval:
                aliases: ['guard-interval']
                type: str
                description: Wi-Fi guard interval.
                choices: ['auto', '400ns', '800ns']
            lan_ext_vap:
                aliases: ['lan-ext-vap']
                type: list
                elements: str
                description: Wi-Fi LAN-Extention VAP.
            local_vaps:
                aliases: ['local-vaps']
                type: list
                elements: str
                description: Wi-Fi local VAP.
            max_clients:
                aliases: ['max-clients']
                type: int
                description: Maximum number of Wi-Fi radio clients
            mode:
                type: str
                description: Wi-Fi radio mode AP
                choices: ['AP', 'Client']
            operating_standard:
                aliases: ['operating-standard']
                type: str
                description: Wi-Fi operating standard.
                choices: ['auto', '11A-N-AC-AX', '11A-N-AC', '11A-N', '11A', '11N-AC-AX',
                          '11AC-AX', '11AC', '11N-AC', '11B-G-N-AX', '11B-G-N', '11B-G', '11B',
                          '11G-N-AX', '11N-AX', '11AX', '11G-N', '11N', '11G']
            power_level:
                aliases: ['power-level']
                type: int
                description: Wi-Fi power level in percent
            radio_id:
                aliases: ['radio-id']
                type: int
                description: Radio ID.
            status:
                type: str
                description: Enable/disable Wi-Fi radio.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Radio-2 config for Wi-Fi 5GHz
      fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_wifi_radio2:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        extender_profile: <your own value>
        extensioncontroller_extenderprofile_wifi_radio2:
          # d80211d: <value in [disable, enable]>
          # band: <value in [5GHz]>
          # bandwidth: <value in [auto, 20MHz, 40MHz, ...]>
          # beacon_interval: <integer>
          # bss_color: <integer>
          # bss_color_mode: <value in [auto, static]>
          # channel: ["CH36", "CH40", "CH44", "CH48", "CH52", "CH56", "CH60", "CH64", "CH100",
          #           "CH104", "CH108", "CH112", "CH116", "CH120", "CH124", "CH128", "CH132",
          #           "CH136", "CH140", "CH144", "CH149", "CH153", "CH157", "CH161", "CH165"]
          # extension_channel: <value in [auto, higher, lower]>
          # guard_interval: <value in [auto, 400ns, 800ns]>
          # lan_ext_vap: <list or string>
          # local_vaps: <list or string>
          # max_clients: <integer>
          # mode: <value in [AP, Client]>
          # operating_standard: <value in [auto, 11A-N-AC-AX, 11A-N-AC, ...]>
          # power_level: <integer>
          # radio_id: <integer>
          # status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/wifi/radio-2',
        '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/wifi/radio-2'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'extender-profile': {'type': 'str', 'api_name': 'extender_profile'},
        'extender_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'extensioncontroller_extenderprofile_wifi_radio2': {
            'type': 'dict', 'v_range': [['7.4.3', '']],
            'options': {
                '80211d': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'band': {'v_range': [['7.4.3', '']], 'choices': ['5GHz'], 'type': 'str'},
                'bandwidth': {'v_range': [['7.4.3', '']], 'choices': ['auto', '20MHz', '40MHz', '80MHz'], 'type': 'str'},
                'beacon-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'bss-color': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'bss-color-mode': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'static'], 'type': 'str'},
                'channel': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'CH36', 'CH40', 'CH44', 'CH48', 'CH52', 'CH56', 'CH60', 'CH64', 'CH100', 'CH104', 'CH108', 'CH112', 'CH116', 'CH120', 'CH124',
                        'CH128', 'CH132', 'CH136', 'CH140', 'CH144', 'CH149', 'CH153', 'CH157', 'CH161', 'CH165'
                    ],
                    'elements': 'str'
                },
                'extension-channel': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'higher', 'lower'], 'type': 'str'},
                'guard-interval': {'v_range': [['7.4.3', '']], 'choices': ['auto', '400ns', '800ns'], 'type': 'str'},
                'lan-ext-vap': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'local-vaps': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'max-clients': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'mode': {'v_range': [['7.4.3', '']], 'choices': ['AP', 'Client'], 'type': 'str'},
                'operating-standard': {
                    'v_range': [['7.4.3', '']],
                    'choices': [
                        'auto', '11A-N-AC-AX', '11A-N-AC', '11A-N', '11A', '11N-AC-AX', '11AC-AX', '11AC', '11N-AC', '11B-G-N-AX', '11B-G-N', '11B-G',
                        '11B', '11G-N-AX', '11N-AX', '11AX', '11G-N', '11N', '11G'
                    ],
                    'type': 'str'
                },
                'power-level': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'radio-id': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extenderprofile_wifi_radio2'),
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
