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
module: fmgr_firewall_ippoolgrp
short_description: Configure IPv4 pool groups.
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
    firewall_ippoolgrp:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comments:
                type: str
                description: Comment.
            member:
                type: raw
                description: (list or str) Member IP pool of the group
            name:
                type: str
                description: No description
                required: true
            uuid:
                type: str
                description: Universally Unique Identifier
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv4 pool groups.
      fortinet.fortimanager.fmgr_firewall_ippoolgrp:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        firewall_ippoolgrp:
          name: "your value" # Required variable, string
          # comments: <string>
          # member: <list or string>
          # uuid: <string>
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
        '/pm/config/adom/{adom}/obj/firewall/ippool_grp',
        '/pm/config/global/obj/firewall/ippool_grp',
        '/pm/config/adom/{adom}/obj/firewall/ippool-grp',
        '/pm/config/global/obj/firewall/ippool-grp'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_ippoolgrp': {
            'type': 'dict', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
            'options': {
                'comments': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                'member': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'raw'},
                'name': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'required': True, 'type': 'str'},
                'uuid': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_ippoolgrp'),
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
