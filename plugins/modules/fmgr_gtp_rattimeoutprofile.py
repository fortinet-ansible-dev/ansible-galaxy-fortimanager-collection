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
module: fmgr_gtp_rattimeoutprofile
short_description: RAT timeout profile
version_added: "2.10.0"
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
    gtp_rattimeoutprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            eutran_timeout:
                aliases: ['eutran-timeout']
                type: int
                description: Established eutran timeout in seconds
            gan_timeout:
                aliases: ['gan-timeout']
                type: int
                description: Established gan timeout in seconds
            geran_timeout:
                aliases: ['geran-timeout']
                type: int
                description: Established geran timeout in seconds
            hspa_timeout:
                aliases: ['hspa-timeout']
                type: int
                description: Established hspa timeout in seconds
            ltem_timeout:
                aliases: ['ltem-timeout']
                type: int
                description: Established ltem timeout in seconds
            name:
                type: str
                description: RAT timeout profile name.
                required: true
            nbiot_timeout:
                aliases: ['nbiot-timeout']
                type: int
                description: Established nbiot timeout in seconds
            nr_timeout:
                aliases: ['nr-timeout']
                type: int
                description: Established nr timeout in seconds
            utran_timeout:
                aliases: ['utran-timeout']
                type: int
                description: Established utran timeout in seconds
            virtual_timeout:
                aliases: ['virtual-timeout']
                type: int
                description: Established virtual timeout in seconds
            wlan_timeout:
                aliases: ['wlan-timeout']
                type: int
                description: Established wlan timeout in seconds
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: RAT timeout profile
      fortinet.fortimanager.fmgr_gtp_rattimeoutprofile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        gtp_rattimeoutprofile:
          name: "your value" # Required variable, string
          # eutran_timeout: <integer>
          # gan_timeout: <integer>
          # geran_timeout: <integer>
          # hspa_timeout: <integer>
          # ltem_timeout: <integer>
          # nbiot_timeout: <integer>
          # nr_timeout: <integer>
          # utran_timeout: <integer>
          # virtual_timeout: <integer>
          # wlan_timeout: <integer>
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
        '/pm/config/adom/{adom}/obj/gtp/rat-timeout-profile',
        '/pm/config/global/obj/gtp/rat-timeout-profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'gtp_rattimeoutprofile': {
            'type': 'dict', 'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']],
            'options': {
                'eutran-timeout': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'gan-timeout': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'geran-timeout': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'hspa-timeout': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'ltem-timeout': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'nbiot-timeout': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'nr-timeout': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'utran-timeout': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'virtual-timeout': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'wlan-timeout': {'v_range': [['7.4.7', '7.4.10'], ['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'gtp_rattimeoutprofile'),
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
