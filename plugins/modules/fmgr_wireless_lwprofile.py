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
module: fmgr_wireless_lwprofile
short_description: Configure LoRaWAN profile.
version_added: "2.15.0"
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
  wireless_lwprofile:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      comment:
        type: str
        description: Comment.
      cups_api_key:
        aliases: ['cups-api-key']
        type: list
        elements: str
        description: CUPS API key of LoRaWAN device.
      cups_server:
        aliases: ['cups-server']
        type: str
        description: CUPS
      cups_server_port:
        aliases: ['cups-server-port']
        type: int
        description: CUPS Port value of LoRaWAN device.
      lw_protocol:
        aliases: ['lw-protocol']
        type: str
        description: Configure LoRaWAN protocol
        choices: ['basics-station', 'packet-forwarder']
      name:
        type: str
        description: LoRaWAN profile name.
        required: true
      tc_api_key:
        aliases: ['tc-api-key']
        type: list
        elements: str
        description: TC API key of LoRaWAN device.
      tc_server:
        aliases: ['tc-server']
        type: str
        description: TC
      tc_server_port:
        aliases: ['tc-server-port']
        type: int
        description: TC Port value of LoRaWAN device.
'''

EXAMPLES = '''
- name: Test LoRaWAN profiles
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create a LoRaWAN profile
      fortinet.fortimanager.fmgr_wireless_lwprofile:
        enable_log: true
        adom: root
        state: present
        wireless_lwprofile:
          name: test_lw_profile
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
        '/pm/config/adom/{adom}/obj/wireless-controller/lw-profile',
        '/pm/config/global/obj/wireless-controller/lw-profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'wireless_lwprofile': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'comment': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'cups-api-key': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'cups-server': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'cups-server-port': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'lw-protocol': {'v_range': [['8.0.0', '']], 'choices': ['basics-station', 'packet-forwarder'], 'type': 'str'},
                'name': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'str'},
                'tc-api-key': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'tc-server': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'tc-server-port': {'v_range': [['8.0.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_lwprofile'),
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
