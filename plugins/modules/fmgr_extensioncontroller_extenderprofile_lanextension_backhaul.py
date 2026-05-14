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
module: fmgr_extensioncontroller_extenderprofile_lanextension_backhaul
short_description: LAN extension backhaul tunnel configuration.
version_added: "2.2.0"
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
    extender-profile:
        description: Deprecated, please use "extender_profile"
        type: str
    extender_profile:
        description: The parameter (extender-profile) in requested url.
        type: str
    extensioncontroller_extenderprofile_lanextension_backhaul:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: FortiExtender LAN extension backhaul name.
                required: true
            port:
                type: str
                description: FortiExtender uplink port.
                choices: ['wan', 'lte1', 'lte2', 'port1', 'port2', 'port3', 'port4', 'port5', 'sfp']
            role:
                type: str
                description: FortiExtender uplink port.
                choices: ['primary', 'secondary']
            weight:
                type: int
                description: WRR weight parameter.
            health_check_fail_cnt:
                aliases: ['health-check-fail-cnt']
                type: int
                description: Number of failures before the link is considered dead
            health_check_interval:
                aliases: ['health-check-interval']
                type: int
                description: Health monitoring interval in seconds
            health_check_probe_cnt:
                aliases: ['health-check-probe-cnt']
                type: int
                description: Number of health monitoring probes to send within an interval
            health_check_probe_tm:
                aliases: ['health-check-probe-tm']
                type: int
                description: Health monitoring probe timeout in seconds
            health_check_recovery_cnt:
                aliases: ['health-check-recovery-cnt']
                type: int
                description: Number of successful checks before the link is considered alive
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: LAN extension backhaul tunnel configuration.
      fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_lanextension_backhaul:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        extender_profile: <your own value>
        state: present # <value in [present, absent]>
        extensioncontroller_extenderprofile_lanextension_backhaul:
          name: "your value" # Required variable, string
          # port: <value in [wan, lte1, lte2, ...]>
          # role: <value in [primary, secondary]>
          # weight: <integer>
          # health_check_fail_cnt: <integer>
          # health_check_interval: <integer>
          # health_check_probe_cnt: <integer>
          # health_check_probe_tm: <integer>
          # health_check_recovery_cnt: <integer>
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
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul',
        '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'extender-profile': {'type': 'str', 'api_name': 'extender_profile'},
        'extender_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'extensioncontroller_extenderprofile_lanextension_backhaul': {
            'type': 'dict', 'v_range': [['7.2.1', '']],
            'options': {
                'name': {'v_range': [['7.2.1', '']], 'required': True, 'type': 'str'},
                'port': {
                    'v_range': [['7.2.1', '']],
                    'choices': ['wan', 'lte1', 'lte2', 'port1', 'port2', 'port3', 'port4', 'port5', 'sfp'],
                    'type': 'str'
                },
                'role': {'v_range': [['7.2.1', '']], 'choices': ['primary', 'secondary'], 'type': 'str'},
                'weight': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'health-check-fail-cnt': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'health-check-interval': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'health-check-probe-cnt': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'health-check-probe-tm': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'health-check-recovery-cnt': {'v_range': [['7.6.5', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extenderprofile_lanextension_backhaul'),
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
