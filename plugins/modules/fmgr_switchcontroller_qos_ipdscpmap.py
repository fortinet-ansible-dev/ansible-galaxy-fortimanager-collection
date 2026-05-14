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
module: fmgr_switchcontroller_qos_ipdscpmap
short_description: Configure FortiSwitch QoS IP precedence/DSCP.
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
    switchcontroller_qos_ipdscpmap:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            description:
                type: str
                description: Description of the ip-dscp map name.
            map:
                type: list
                elements: dict
                description: Map.
                suboptions:
                    cos_queue:
                        aliases: ['cos-queue']
                        type: int
                        description: COS queue number.
                    diffserv:
                        type: list
                        elements: str
                        description: Differentiated service.
                        choices: ['CS0', 'CS1', 'AF11', 'AF12', 'AF13', 'CS2', 'AF21', 'AF22',
                                  'AF23', 'CS3', 'AF31', 'AF32', 'AF33', 'CS4', 'AF41', 'AF42',
                                  'AF43', 'CS5', 'EF', 'CS6', 'CS7']
                    ip_precedence:
                        aliases: ['ip-precedence']
                        type: list
                        elements: str
                        description: IP Precedence.
                        choices: ['network-control', 'internetwork-control', 'critic-ecp',
                                  'flashoverride', 'flash', 'immediate', 'priority', 'routine']
                    name:
                        type: str
                        description: Dscp mapping entry name.
                    value:
                        type: str
                        description: Raw values of DSCP
            name:
                type: str
                description: Dscp map name.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiSwitch QoS IP precedence/DSCP.
      fortinet.fortimanager.fmgr_switchcontroller_qos_ipdscpmap:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_qos_ipdscpmap:
          name: "your value" # Required variable, string
          # description: <string>
          # map:
          #   - cos_queue: <integer>
          #     diffserv: ["CS0", "CS1", "AF11", "AF12", "AF13", "CS2", "AF21", "AF22", "AF23",
          #                "CS3", "AF31", "AF32", "AF33", "CS4", "AF41", "AF42", "AF43", "CS5",
          #                "EF", "CS6", "CS7"]
          #     ip_precedence: ["network-control", "internetwork-control", "critic-ecp",
          #                     "flashoverride", "flash", "immediate", "priority", "routine"]
          #     name: <string>
          #     value: <string>
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
        '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map',
        '/pm/config/global/obj/switch-controller/qos/ip-dscp-map'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_qos_ipdscpmap': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'description': {'type': 'str'},
                'map': {
                    'type': 'list',
                    'options': {
                        'cos-queue': {'type': 'int'},
                        'diffserv': {
                            'type': 'list',
                            'choices': [
                                'CS0', 'CS1', 'AF11', 'AF12', 'AF13', 'CS2', 'AF21', 'AF22', 'AF23', 'CS3', 'AF31', 'AF32', 'AF33', 'CS4', 'AF41',
                                'AF42', 'AF43', 'CS5', 'EF', 'CS6', 'CS7'
                            ],
                            'elements': 'str'
                        },
                        'ip-precedence': {
                            'type': 'list',
                            'choices': [
                                'network-control', 'internetwork-control', 'critic-ecp', 'flashoverride', 'flash', 'immediate', 'priority', 'routine'
                            ],
                            'elements': 'str'
                        },
                        'name': {'type': 'str'},
                        'value': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_qos_ipdscpmap'),
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
