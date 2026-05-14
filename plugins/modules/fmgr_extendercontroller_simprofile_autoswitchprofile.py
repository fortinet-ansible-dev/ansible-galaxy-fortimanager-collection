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
module: fmgr_extendercontroller_simprofile_autoswitchprofile
short_description: Extender controller sim profile auto switch profile
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
    sim_profile:
        description: The parameter (sim_profile) in requested url.
        type: str
        required: true
    extendercontroller_simprofile_autoswitchprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            dataplan:
                type: str
                description: Dataplan.
                choices: ['disable', 'enable']
            disconnect:
                type: str
                description: Disconnect.
                choices: ['disable', 'enable']
            disconnect_period:
                aliases: ['disconnect-period']
                type: int
                description: Disconnect period.
            disconnect_threshold:
                aliases: ['disconnect-threshold']
                type: int
                description: Disconnect threshold.
            signal:
                type: str
                description: Signal.
                choices: ['disable', 'enable']
            status:
                type: str
                description: Status.
                choices: ['disable', 'enable']
            switch_back:
                aliases: ['switch-back']
                type: list
                elements: str
                description: Switch back.
                choices: ['time', 'timer']
            switch_back_time:
                aliases: ['switch-back-time']
                type: str
                description: Switch back time.
            switch_back_timer:
                aliases: ['switch-back-timer']
                type: int
                description: Switch back timer.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Extender controller sim profile auto switch profile
      fortinet.fortimanager.fmgr_extendercontroller_simprofile_autoswitchprofile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        sim_profile: <your own value>
        extendercontroller_simprofile_autoswitchprofile:
          # dataplan: <value in [disable, enable]>
          # disconnect: <value in [disable, enable]>
          # disconnect_period: <integer>
          # disconnect_threshold: <integer>
          # signal: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # switch_back: ["time", "timer"]
          # switch_back_time: <string>
          # switch_back_timer: <integer>
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
        '/pm/config/adom/{adom}/obj/extender-controller/sim_profile/{sim_profile}/auto-switch_profile',
        '/pm/config/global/obj/extender-controller/sim_profile/{sim_profile}/auto-switch_profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'sim_profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'extendercontroller_simprofile_autoswitchprofile': {
            'type': 'dict', 'v_range': [['6.4.4', '']],
            'options': {
                'dataplan': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'disconnect': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'disconnect-period': {'v_range': [['6.4.4', '']], 'type': 'int'},
                'disconnect-threshold': {'v_range': [['6.4.4', '']], 'type': 'int'},
                'signal': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'switch-back': {'v_range': [['6.4.4', '']], 'type': 'list', 'choices': ['time', 'timer'], 'elements': 'str'},
                'switch-back-time': {'v_range': [['6.4.4', '']], 'type': 'str'},
                'switch-back-timer': {'v_range': [['6.4.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extendercontroller_simprofile_autoswitchprofile'),
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
