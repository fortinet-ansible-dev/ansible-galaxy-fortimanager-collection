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
module: fmgr_dynamic_interface_platformmapping
short_description: Dynamic interface platform mapping
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
    interface:
        description: The parameter (interface) in requested url.
        type: str
        required: true
    dynamic_interface_platformmapping:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            egress_shaping_profile:
                aliases: ['egress-shaping-profile']
                type: raw
                description: (list or str) Egress shaping profile.
            ingress_shaping_profile:
                aliases: ['ingress-shaping-profile']
                type: raw
                description: (list or str) Ingress shaping profile.
            intf_zone:
                aliases: ['intf-zone']
                type: str
                description: Intf zone.
            intrazone_deny:
                aliases: ['intrazone-deny']
                type: str
                description: Intrazone deny.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Name.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Dynamic interface platform mapping
      fortinet.fortimanager.fmgr_dynamic_interface_platformmapping:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        interface: <your own value>
        state: present # <value in [present, absent]>
        dynamic_interface_platformmapping:
          name: "your value" # Required variable, string
          # egress_shaping_profile: <list or string>
          # ingress_shaping_profile: <list or string>
          # intf_zone: <string>
          # intrazone_deny: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/platform_mapping',
        '/pm/config/global/obj/dynamic/interface/{interface}/platform_mapping'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'interface': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dynamic_interface_platformmapping': {
            'type': 'dict', 'v_range': [['6.4.1', '']],
            'options': {
                'egress-shaping-profile': {'v_range': [['6.4.1', '']], 'type': 'raw'},
                'ingress-shaping-profile': {'v_range': [['6.4.1', '']], 'type': 'raw'},
                'intf-zone': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'intrazone-deny': {'v_range': [['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['6.4.1', '']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dynamic_interface_platformmapping'),
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
