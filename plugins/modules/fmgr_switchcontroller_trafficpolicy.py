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
module: fmgr_switchcontroller_trafficpolicy
short_description: Configure FortiSwitch traffic policy.
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
    switchcontroller_trafficpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cos_queue:
                aliases: ['cos-queue']
                type: int
                description: COS queue
            description:
                type: str
                description: Description of the traffic policy.
            guaranteed_bandwidth:
                aliases: ['guaranteed-bandwidth']
                type: int
                description: Guaranteed bandwidth in kbps
            guaranteed_burst:
                aliases: ['guaranteed-burst']
                type: int
                description: Guaranteed burst size in bytes
            id:
                type: int
                description: FSW Policer id
                required: true
            maximum_burst:
                aliases: ['maximum-burst']
                type: int
                description: Maximum burst size in bytes
            name:
                type: str
                description: Traffic policy name.
            policer_status:
                aliases: ['policer-status']
                type: str
                description: Enable/disable policer config on the traffic policy.
                choices: ['disable', 'enable']
            type:
                type: str
                description: Type.
                choices: ['ingress', 'egress']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiSwitch traffic policy.
      fortinet.fortimanager.fmgr_switchcontroller_trafficpolicy:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_trafficpolicy:
          id: 0 # Required variable, integer
          # cos_queue: <integer>
          # description: <string>
          # guaranteed_bandwidth: <integer>
          # guaranteed_burst: <integer>
          # maximum_burst: <integer>
          # name: <string>
          # policer_status: <value in [disable, enable]>
          # type: <value in [ingress, egress]>
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
        '/pm/config/adom/{adom}/obj/switch-controller/traffic-policy',
        '/pm/config/global/obj/switch-controller/traffic-policy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'switchcontroller_trafficpolicy': {
            'type': 'dict', 'v_range': [['7.2.1', '']],
            'options': {
                'cos-queue': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'description': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'guaranteed-bandwidth': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'guaranteed-burst': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'id': {'v_range': [['7.2.1', '']], 'required': True, 'type': 'int'},
                'maximum-burst': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'policer-status': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.2.1', '']], 'choices': ['ingress', 'egress'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_trafficpolicy'),
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
