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
module: fmgr_extendercontroller_extenderprofile_lanextension_backhaul
short_description: LAN extension backhaul tunnel configuration.
version_added: "2.1.0"
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
    extendercontroller_extenderprofile_lanextension_backhaul:
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
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: LAN extension backhaul tunnel configuration.
      fortinet.fortimanager.fmgr_extendercontroller_extenderprofile_lanextension_backhaul:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        extender_profile: <your own value>
        state: present # <value in [present, absent]>
        extendercontroller_extenderprofile_lanextension_backhaul:
          name: "your value" # Required variable, string
          # port: <value in [wan, lte1, lte2, ...]>
          # role: <value in [primary, secondary]>
          # weight: <integer>
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
        '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul',
        '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'extender-profile': {'type': 'str', 'api_name': 'extender_profile'},
        'extender_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'extendercontroller_extenderprofile_lanextension_backhaul': {
            'type': 'dict', 'v_range': [['7.0.2', '']],
            'options': {
                'name': {'v_range': [['7.0.2', '']], 'required': True, 'type': 'str'},
                'port': {
                    'v_range': [['7.0.2', '']],
                    'choices': ['wan', 'lte1', 'lte2', 'port1', 'port2', 'port3', 'port4', 'port5', 'sfp'],
                    'type': 'str'
                },
                'role': {'v_range': [['7.0.2', '']], 'choices': ['primary', 'secondary'], 'type': 'str'},
                'weight': {'v_range': [['7.0.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extendercontroller_extenderprofile_lanextension_backhaul'),
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
