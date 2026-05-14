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
module: fmgr_ips_baseline_sensor_override_exemptip
short_description: Ips baseline sensor override exempt ip
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
    sensor:
        description: The parameter (sensor) in requested url.
        type: str
        required: true
    override:
        description: The parameter (override) in requested url.
        type: str
        required: true
    ips_baseline_sensor_override_exemptip:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            dst_ip:
                aliases: ['dst-ip']
                type: str
                description: Destination IP address and netmask.
            id:
                type: int
                description: Exempt IP ID.
                required: true
            src_ip:
                aliases: ['src-ip']
                type: str
                description: Source IP address and netmask.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Ips baseline sensor override exempt ip
      fortinet.fortimanager.fmgr_ips_baseline_sensor_override_exemptip:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        sensor: <your own value>
        override: <your own value>
        state: present # <value in [present, absent]>
        ips_baseline_sensor_override_exemptip:
          id: 0 # Required variable, integer
          # dst_ip: <string>
          # src_ip: <string>
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
        '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/override/{override}/exempt-ip',
        '/pm/config/global/obj/ips/baseline/sensor/{sensor}/override/{override}/exempt-ip'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'sensor': {'required': True, 'type': 'str'},
        'override': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'ips_baseline_sensor_override_exemptip': {
            'type': 'dict', 'v_range': [['7.0.1', '7.0.2']],
            'options': {
                'dst-ip': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'},
                'id': {'v_range': [['7.0.1', '7.0.2']], 'required': True, 'type': 'int'},
                'src-ip': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ips_baseline_sensor_override_exemptip'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
