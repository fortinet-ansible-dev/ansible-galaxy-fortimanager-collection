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
module: fmgr_dvmdb_workspace_commit_pkg
short_description: Commit change
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    package_path_name:
        description: The parameter (package_path_name) in requested url.
        type: str
        required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Commit change
      fortinet.fortimanager.fmgr_dvmdb_workspace_commit_pkg:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        package_path_name: <your own value>
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
        '/dvmdb/adom/{adom}/workspace/commit/pkg/{package_path_name}',
        '/dvmdb/global/workspace/commit/pkg/{package_path_name}'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'package_path_name': {'required': True, 'type': 'str'}
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvmdb_workspace_commit_pkg'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('exec', module_arg_spec, urls_list,
                       None, None, module, connection)
    fmgr.process_exec()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
