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
module: fmgr_extensioncontroller_extenderprofile_lanextension_downlinks
short_description: Config FortiExtender downlink interface for LAN extension.
version_added: "2.14.0"
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
    extensioncontroller_extenderprofile_lanextension_downlinks:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: FortiExtender LAN extension downlink config entry name.
                required: true
            port:
                type: str
                description: FortiExtender LAN extension downlink port.
                choices: ['port1', 'port2', 'port3', 'port4', 'port5', 'lan1', 'lan2', 'lan']
            pvid:
                type: int
                description: FortiExtender LAN extension downlink PVID.
            type:
                type: str
                description: FortiExtender LAN extension downlink type [port/vap].
                choices: ['port', 'vap']
            vap:
                type: list
                elements: str
                description: FortiExtender LAN extension downlink vap.
            vids:
                type: list
                elements: int
                description: FortiExtender LAN extension downlink VIDs.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Config FortiExtender downlink interface for LAN extension.
      fortinet.fortimanager.fmgr_extensioncontroller_extenderprofile_lanextension_downlinks:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        extender_profile: <your own value>
        state: present # <value in [present, absent]>
        extensioncontroller_extenderprofile_lanextension_downlinks:
          name: "your value" # Required variable, string
          # port: <value in [port1, port2, port3, ...]>
          # pvid: <integer>
          # type: <value in [port, vap]>
          # vap: <list or string>
          # vids: <list or integer>
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
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/downlinks',
        '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/downlinks'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'extender-profile': {'type': 'str', 'api_name': 'extender_profile'},
        'extender_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'extensioncontroller_extenderprofile_lanextension_downlinks': {
            'type': 'dict', 'v_range': [['7.6.0', '']],
            'options': {
                'name': {'v_range': [['7.6.0', '']], 'required': True, 'type': 'str'},
                'port': {'v_range': [['7.6.0', '']], 'choices': ['port1', 'port2', 'port3', 'port4', 'port5', 'lan1', 'lan2', 'lan'], 'type': 'str'},
                'pvid': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'type': {'v_range': [['7.6.0', '']], 'choices': ['port', 'vap'], 'type': 'str'},
                'vap': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'vids': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extenderprofile_lanextension_downlinks'),
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
