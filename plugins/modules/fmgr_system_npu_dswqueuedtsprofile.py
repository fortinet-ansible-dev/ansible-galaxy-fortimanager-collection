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
module: fmgr_system_npu_dswqueuedtsprofile
short_description: Configure NPU DSW Queue DTS profile.
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
    system_npu_dswqueuedtsprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            iport:
                type: str
                description: Set NPU DSW DTS in port.
                choices: ['EIF0', 'eif0', 'EIF1', 'eif1', 'EIF2', 'eif2', 'EIF3', 'eif3', 'EIF4',
                          'eif4', 'EIF5', 'eif5', 'EIF6', 'eif6', 'EIF7', 'eif7', 'HTX0', 'htx0',
                          'HTX1', 'htx1', 'SSE0', 'sse0', 'SSE1', 'sse1', 'SSE2', 'sse2', 'SSE3',
                          'sse3', 'RLT', 'rlt', 'DFR', 'dfr', 'IPSECI', 'ipseci', 'IPSECO',
                          'ipseco', 'IPTI', 'ipti', 'IPTO', 'ipto', 'VEP0', 'vep0', 'VEP2',
                          'vep2', 'VEP4', 'vep4', 'VEP6', 'vep6', 'IVS', 'ivs', 'L2TI1', 'l2ti1',
                          'L2TO', 'l2to', 'L2TI0', 'l2ti0', 'PLE', 'ple', 'SPATH', 'spath', 'QTM',
                          'qtm']
            name:
                type: str
                description: Name.
                required: true
            oport:
                type: str
                description: Set NPU DSW DTS out port.
                choices: ['EIF0', 'eif0', 'EIF1', 'eif1', 'EIF2', 'eif2', 'EIF3', 'eif3', 'EIF4',
                          'eif4', 'EIF5', 'eif5', 'EIF6', 'eif6', 'EIF7', 'eif7', 'HRX', 'hrx',
                          'SSE0', 'sse0', 'SSE1', 'sse1', 'SSE2', 'sse2', 'SSE3', 'sse3', 'RLT',
                          'rlt', 'DFR', 'dfr', 'IPSECI', 'ipseci', 'IPSECO', 'ipseco', 'IPTI',
                          'ipti', 'IPTO', 'ipto', 'VEP0', 'vep0', 'VEP2', 'vep2', 'VEP4', 'vep4',
                          'VEP6', 'vep6', 'IVS', 'ivs', 'L2TI1', 'l2ti1', 'L2TO', 'l2to', 'L2TI0',
                          'l2ti0', 'PLE', 'ple', 'SYNK', 'sync', 'NSS', 'nss', 'TSK', 'tsk',
                          'QTM', 'qtm', 'l2tO']
            profile_id:
                aliases: ['profile-id']
                type: int
                description: Set NPU DSW DTS profile ID.
            queue_select:
                aliases: ['queue-select']
                type: int
                description: Set NPU DSW DTS queue ID select
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure NPU DSW Queue DTS profile.
      fortinet.fortimanager.fmgr_system_npu_dswqueuedtsprofile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        system_npu_dswqueuedtsprofile:
          name: "your value" # Required variable, string
          # iport: <value in [EIF0, eif0, EIF1, ...]>
          # oport: <value in [EIF0, eif0, EIF1, ...]>
          # profile_id: <integer>
          # queue_select: <integer>
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
        '/pm/config/adom/{adom}/obj/system/npu/dsw-queue-dts-profile',
        '/pm/config/global/obj/system/npu/dsw-queue-dts-profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_npu_dswqueuedtsprofile': {
            'type': 'dict', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
            'options': {
                'iport': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': [
                        'EIF0', 'eif0', 'EIF1', 'eif1', 'EIF2', 'eif2', 'EIF3', 'eif3', 'EIF4', 'eif4', 'EIF5', 'eif5', 'EIF6', 'eif6', 'EIF7', 'eif7',
                        'HTX0', 'htx0', 'HTX1', 'htx1', 'SSE0', 'sse0', 'SSE1', 'sse1', 'SSE2', 'sse2', 'SSE3', 'sse3', 'RLT', 'rlt', 'DFR', 'dfr',
                        'IPSECI', 'ipseci', 'IPSECO', 'ipseco', 'IPTI', 'ipti', 'IPTO', 'ipto', 'VEP0', 'vep0', 'VEP2', 'vep2', 'VEP4', 'vep4', 'VEP6',
                        'vep6', 'IVS', 'ivs', 'L2TI1', 'l2ti1', 'L2TO', 'l2to', 'L2TI0', 'l2ti0', 'PLE', 'ple', 'SPATH', 'spath', 'QTM', 'qtm'
                    ],
                    'type': 'str'
                },
                'name': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'required': True, 'type': 'str'},
                'oport': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': [
                        'EIF0', 'eif0', 'EIF1', 'eif1', 'EIF2', 'eif2', 'EIF3', 'eif3', 'EIF4', 'eif4', 'EIF5', 'eif5', 'EIF6', 'eif6', 'EIF7', 'eif7',
                        'HRX', 'hrx', 'SSE0', 'sse0', 'SSE1', 'sse1', 'SSE2', 'sse2', 'SSE3', 'sse3', 'RLT', 'rlt', 'DFR', 'dfr', 'IPSECI', 'ipseci',
                        'IPSECO', 'ipseco', 'IPTI', 'ipti', 'IPTO', 'ipto', 'VEP0', 'vep0', 'VEP2', 'vep2', 'VEP4', 'vep4', 'VEP6', 'vep6', 'IVS', 'ivs',
                        'L2TI1', 'l2ti1', 'L2TO', 'l2to', 'L2TI0', 'l2ti0', 'PLE', 'ple', 'SYNK', 'sync', 'NSS', 'nss', 'TSK', 'tsk', 'QTM', 'qtm',
                        'l2tO'
                    ],
                    'type': 'str'
                },
                'profile-id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'queue-select': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_dswqueuedtsprofile'),
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
