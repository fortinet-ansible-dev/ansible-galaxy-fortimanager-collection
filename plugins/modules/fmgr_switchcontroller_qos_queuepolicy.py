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
module: fmgr_switchcontroller_qos_queuepolicy
short_description: Configure FortiSwitch QoS egress queue policy.
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
    switchcontroller_qos_queuepolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cos_queue:
                aliases: ['cos-queue']
                type: list
                elements: dict
                description: Cos queue.
                suboptions:
                    description:
                        type: str
                        description: Description of the COS queue.
                    drop_policy:
                        aliases: ['drop-policy']
                        type: str
                        description: COS queue drop policy.
                        choices: ['taildrop', 'weighted-random-early-detection']
                    max_rate:
                        aliases: ['max-rate']
                        type: int
                        description: Maximum rate
                    min_rate:
                        aliases: ['min-rate']
                        type: int
                        description: Minimum rate
                    name:
                        type: str
                        description: Cos queue ID.
                    weight:
                        type: int
                        description: Weight of weighted round robin scheduling.
                    max_rate_percent:
                        aliases: ['max-rate-percent']
                        type: int
                        description: Maximum rate
                    min_rate_percent:
                        aliases: ['min-rate-percent']
                        type: int
                        description: Minimum rate
                    ecn:
                        type: str
                        description: Enable/disable ECN packet marking to drop eligible packets.
                        choices: ['disable', 'enable']
            name:
                type: str
                description: QoS policy name
                required: true
            schedule:
                type: str
                description: COS queue scheduling.
                choices: ['strict', 'round-robin', 'weighted']
            rate_by:
                aliases: ['rate-by']
                type: str
                description: COS queue rate by kbps or percent.
                choices: ['kbps', 'percent']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiSwitch QoS egress queue policy.
      fortinet.fortimanager.fmgr_switchcontroller_qos_queuepolicy:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_qos_queuepolicy:
          name: "your value" # Required variable, string
          # cos_queue:
          #   - description: <string>
          #     drop_policy: <value in [taildrop, weighted-random-early-detection]>
          #     max_rate: <integer>
          #     min_rate: <integer>
          #     name: <string>
          #     weight: <integer>
          #     max_rate_percent: <integer>
          #     min_rate_percent: <integer>
          #     ecn: <value in [disable, enable]>
          # schedule: <value in [strict, round-robin, weighted]>
          # rate_by: <value in [kbps, percent]>
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
        '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy',
        '/pm/config/global/obj/switch-controller/qos/queue-policy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_qos_queuepolicy': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'cos-queue': {
                    'type': 'list',
                    'options': {
                        'description': {'type': 'str'},
                        'drop-policy': {'choices': ['taildrop', 'weighted-random-early-detection'], 'type': 'str'},
                        'max-rate': {'type': 'int'},
                        'min-rate': {'type': 'int'},
                        'name': {'type': 'str'},
                        'weight': {'type': 'int'},
                        'max-rate-percent': {'v_range': [['6.2.0', '']], 'type': 'int'},
                        'min-rate-percent': {'v_range': [['6.2.0', '']], 'type': 'int'},
                        'ecn': {'v_range': [['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'required': True, 'type': 'str'},
                'schedule': {'choices': ['strict', 'round-robin', 'weighted'], 'type': 'str'},
                'rate-by': {'v_range': [['6.2.0', '']], 'choices': ['kbps', 'percent'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_qos_queuepolicy'),
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
