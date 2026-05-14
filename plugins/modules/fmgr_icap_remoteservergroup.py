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
module: fmgr_icap_remoteservergroup
short_description: Icap remote server group
version_added: "2.12.0"
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
    icap_remoteservergroup:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ldb_method:
                aliases: ['ldb-method']
                type: str
                description: Ldb method.
                choices: ['weighted', 'least-session', 'active-passive']
            name:
                type: str
                description: Name.
                required: true
            server_list:
                aliases: ['server-list']
                type: list
                elements: dict
                description: Server list.
                suboptions:
                    name:
                        type: list
                        elements: str
                        description: Name.
                    weight:
                        type: int
                        description: Weight.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Icap remote server group
      fortinet.fortimanager.fmgr_icap_remoteservergroup:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        icap_remoteservergroup:
          name: "your value" # Required variable, string
          # ldb_method: <value in [weighted, least-session, active-passive]>
          # server_list:
          #   - name: <list or string>
          #     weight: <integer>
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
        '/pm/config/adom/{adom}/obj/icap/remote-server-group',
        '/pm/config/global/obj/icap/remote-server-group'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'icap_remoteservergroup': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'ldb-method': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['weighted', 'least-session', 'active-passive'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'server-list': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'weight': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'icap_remoteservergroup'),
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
