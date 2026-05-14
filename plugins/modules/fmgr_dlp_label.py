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
module: fmgr_dlp_label
short_description: Configure labels used by DLP blocking.
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
    dlp_label:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Optional comments.
            connector:
                type: list
                elements: str
                description: Name of SDN connector.
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    guid:
                        type: str
                        description: MPIP label guid.
                    id:
                        type: int
                        description: ID.
                    mpip_label_name:
                        aliases: ['mpip-label-name']
                        type: str
                        description: Name of MPIP label.
                    fortidata_label_name:
                        aliases: ['fortidata-label-name']
                        type: str
                        description: Name of FortiData label
            mpip_type:
                aliases: ['mpip-type']
                type: str
                description: MPIP label type.
                choices: ['local', 'remote']
            name:
                type: str
                description: Name of table containing the label.
                required: true
            type:
                type: str
                description: Label type.
                choices: ['mpip', 'fortidata']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure labels used by DLP blocking.
      fortinet.fortimanager.fmgr_dlp_label:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        dlp_label:
          name: "your value" # Required variable, string
          # comment: <string>
          # connector: <list or string>
          # entries:
          #   - guid: <string>
          #     id: <integer>
          #     mpip_label_name: <string>
          #     fortidata_label_name: <string>
          # mpip_type: <value in [local, remote]>
          # type: <value in [mpip, fortidata]>
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
        '/pm/config/adom/{adom}/obj/dlp/label',
        '/pm/config/global/obj/dlp/label'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dlp_label': {
            'type': 'dict', 'v_range': [['7.6.3', '']],
            'options': {
                'comment': {'v_range': [['7.6.3', '']], 'type': 'str'},
                'connector': {'v_range': [['7.6.3', '']], 'type': 'list', 'elements': 'str'},
                'entries': {
                    'v_range': [['7.6.3', '']],
                    'type': 'list',
                    'options': {
                        'guid': {'v_range': [['7.6.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.6.3', '']], 'type': 'int'},
                        'mpip-label-name': {'v_range': [['7.6.3', '']], 'type': 'str'},
                        'fortidata-label-name': {'v_range': [['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mpip-type': {'v_range': [['7.6.3', '']], 'choices': ['local', 'remote'], 'type': 'str'},
                'name': {'v_range': [['7.6.3', '']], 'required': True, 'type': 'str'},
                'type': {'v_range': [['7.6.3', '']], 'choices': ['mpip', 'fortidata'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_label'),
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
