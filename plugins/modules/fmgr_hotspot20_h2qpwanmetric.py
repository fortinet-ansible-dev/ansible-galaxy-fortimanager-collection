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
module: fmgr_hotspot20_h2qpwanmetric
short_description: Configure WAN metrics.
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
    hotspot20_h2qpwanmetric:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            downlink_load:
                aliases: ['downlink-load']
                type: int
                description: Downlink load.
            downlink_speed:
                aliases: ['downlink-speed']
                type: int
                description: Downlink speed
            link_at_capacity:
                aliases: ['link-at-capacity']
                type: str
                description: Link at capacity.
                choices: ['disable', 'enable']
            link_status:
                aliases: ['link-status']
                type: str
                description: Link status.
                choices: ['down', 'up', 'in-test']
            load_measurement_duration:
                aliases: ['load-measurement-duration']
                type: int
                description: Load measurement duration
            name:
                type: str
                description: WAN metric name.
                required: true
            symmetric_wan_link:
                aliases: ['symmetric-wan-link']
                type: str
                description: WAN link symmetry.
                choices: ['asymmetric', 'symmetric']
            uplink_load:
                aliases: ['uplink-load']
                type: int
                description: Uplink load.
            uplink_speed:
                aliases: ['uplink-speed']
                type: int
                description: Uplink speed
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure WAN metrics.
      fortinet.fortimanager.fmgr_hotspot20_h2qpwanmetric:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        hotspot20_h2qpwanmetric:
          name: "your value" # Required variable, string
          # downlink_load: <integer>
          # downlink_speed: <integer>
          # link_at_capacity: <value in [disable, enable]>
          # link_status: <value in [down, up, in-test]>
          # load_measurement_duration: <integer>
          # symmetric_wan_link: <value in [asymmetric, symmetric]>
          # uplink_load: <integer>
          # uplink_speed: <integer>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-wan-metric',
        '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-wan-metric'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'hotspot20_h2qpwanmetric': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'downlink-load': {'type': 'int'},
                'downlink-speed': {'type': 'int'},
                'link-at-capacity': {'choices': ['disable', 'enable'], 'type': 'str'},
                'link-status': {'choices': ['down', 'up', 'in-test'], 'type': 'str'},
                'load-measurement-duration': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'symmetric-wan-link': {'choices': ['asymmetric', 'symmetric'], 'type': 'str'},
                'uplink-load': {'type': 'int'},
                'uplink-speed': {'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'hotspot20_h2qpwanmetric'),
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
