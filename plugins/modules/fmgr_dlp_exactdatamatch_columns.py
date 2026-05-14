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
module: fmgr_dlp_exactdatamatch_columns
short_description: DLP exact-data-match column types.
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
    exact-data-match:
        description: Deprecated, please use "exact_data_match"
        type: str
    exact_data_match:
        description: The parameter (exact-data-match) in requested url.
        type: str
    dlp_exactdatamatch_columns:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            index:
                type: int
                description: Column index.
            optional:
                type: str
                description: Enable/disable optional match.
                choices: ['disable', 'enable']
            type:
                type: list
                elements: str
                description: Data-type for this column.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: DLP exact-data-match column types.
      fortinet.fortimanager.fmgr_dlp_exactdatamatch_columns:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        exact_data_match: <your own value>
        state: present # <value in [present, absent]>
        dlp_exactdatamatch_columns:
          # index: <integer>
          # optional: <value in [disable, enable]>
          # type: <list or string>
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
        '/pm/config/adom/{adom}/obj/dlp/exact-data-match/{exact-data-match}/columns',
        '/pm/config/global/obj/dlp/exact-data-match/{exact-data-match}/columns'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'exact-data-match': {'type': 'str', 'api_name': 'exact_data_match'},
        'exact_data_match': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'dlp_exactdatamatch_columns': {
            'type': 'dict', 'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']],
            'options': {
                'index': {'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']], 'type': 'int'},
                'optional': {'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.4.7', '7.4.10'], ['7.6.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_exactdatamatch_columns'),
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
