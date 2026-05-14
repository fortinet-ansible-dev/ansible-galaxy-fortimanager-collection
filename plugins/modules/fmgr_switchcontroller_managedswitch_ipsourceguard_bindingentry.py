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
module: fmgr_switchcontroller_managedswitch_ipsourceguard_bindingentry
short_description: IP and MAC address configuration.
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
    managed-switch:
        description: Deprecated, please use "managed_switch"
        type: str
    managed_switch:
        description: The parameter (managed-switch) in requested url.
        type: str
    ip-source-guard:
        description: Deprecated, please use "ip_source_guard"
        type: str
    ip_source_guard:
        description: The parameter (ip-source-guard) in requested url.
        type: str
    switchcontroller_managedswitch_ipsourceguard_bindingentry:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            entry_name:
                aliases: ['entry-name']
                type: str
                description: Configure binding pair.
            ip:
                type: str
                description: Source IP for this rule.
            mac:
                type: str
                description: MAC address for this rule.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: IP and MAC address configuration.
      fortinet.fortimanager.fmgr_switchcontroller_managedswitch_ipsourceguard_bindingentry:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        managed_switch: <your own value>
        ip_source_guard: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_managedswitch_ipsourceguard_bindingentry:
          # entry_name: <string>
          # ip: <string>
          # mac: <string>
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
        '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry',
        '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'managed-switch': {'type': 'str', 'api_name': 'managed_switch'},
        'managed_switch': {'type': 'str'},
        'ip-source-guard': {'type': 'str', 'api_name': 'ip_source_guard'},
        'ip_source_guard': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_managedswitch_ipsourceguard_bindingentry': {
            'type': 'dict', 'v_range': [['6.4.0', '6.4.1']],
            'options': {
                'entry-name': {'v_range': [['6.4.0', '6.4.1']], 'type': 'str'},
                'ip': {'v_range': [['6.4.0', '6.4.1']], 'type': 'str'},
                'mac': {'v_range': [['6.4.0', '6.4.1']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_managedswitch_ipsourceguard_bindingentry'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
