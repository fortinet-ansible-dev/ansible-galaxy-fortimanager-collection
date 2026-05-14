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
module: fmgr_user_nsx
short_description: User nsx
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
    user_nsx:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            fmgip:
                type: str
                description: Fmgip.
            fmguser:
                type: str
                description: Fmguser.
            name:
                type: str
                description: Name.
                required: true
            password:
                type: raw
                description: (list) Password.
            server:
                type: str
                description: Server.
            status:
                type: str
                description: Status.
                choices: ['disable', 'enable']
            user:
                type: str
                description: User.
            fmgpasswd:
                type: raw
                description: (list) Fmgpasswd.
            service_id:
                aliases: ['service-id']
                type: raw
                description: (list) Service id.
            if_allgroup:
                aliases: ['if-allgroup']
                type: str
                description: If allgroup.
                choices: ['disable', 'enable']
            service:
                type: list
                elements: dict
                description: Service.
                suboptions:
                    id:
                        type: str
                        description: Id.
                    integration:
                        type: str
                        description: Integration.
                        choices: ['east-west', 'north-south']
                    name:
                        type: str
                        description: Name.
                    ref_id:
                        aliases: ['ref-id']
                        type: str
                        description: Ref id.
            service_manager_id:
                aliases: ['service-manager-id']
                type: str
                description: Service manager id.
            service_manager_rev:
                aliases: ['service-manager-rev']
                type: int
                description: Service manager rev.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: User nsx
      fortinet.fortimanager.fmgr_user_nsx:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        user_nsx:
          name: "your value" # Required variable, string
          # fmgip: <string>
          # fmguser: <string>
          # password: <list or string>
          # server: <string>
          # status: <value in [disable, enable]>
          # user: <string>
          # fmgpasswd: <list or string>
          # service_id: <list or string>
          # if_allgroup: <value in [disable, enable]>
          # service:
          #   - id: <string>
          #     integration: <value in [east-west, north-south]>
          #     name: <string>
          #     ref_id: <string>
          # service_manager_id: <string>
          # service_manager_rev: <integer>
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
        '/pm/config/adom/{adom}/obj/user/nsx',
        '/pm/config/global/obj/user/nsx'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_nsx': {
            'type': 'dict', 'v_range': [['6.2.1', '']],
            'options': {
                'fmgip': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'fmguser': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'name': {'v_range': [['6.2.1', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['6.2.1', '']], 'no_log': True, 'type': 'raw'},
                'server': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'status': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'fmgpasswd': {'v_range': [['6.2.2', '']], 'no_log': True, 'type': 'raw'},
                'service-id': {'v_range': [['6.2.2', '']], 'type': 'raw'},
                'if-allgroup': {'v_range': [['7.0.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'service': {
                    'v_range': [['7.0.4', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.0.4', '']], 'type': 'str'},
                        'integration': {'v_range': [['7.0.4', '']], 'choices': ['east-west', 'north-south'], 'type': 'str'},
                        'name': {'v_range': [['7.0.4', '']], 'type': 'str'},
                        'ref-id': {'v_range': [['7.0.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'service-manager-id': {'v_range': [['7.0.4', '']], 'type': 'str'},
                'service-manager-rev': {'v_range': [['7.0.4', '7.0.16'], ['7.2.1', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_nsx'),
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
