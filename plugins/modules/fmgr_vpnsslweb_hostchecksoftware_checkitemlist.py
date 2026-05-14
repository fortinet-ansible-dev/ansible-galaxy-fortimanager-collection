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
module: fmgr_vpnsslweb_hostchecksoftware_checkitemlist
short_description: Check item list.
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
    host-check-software:
        description: Deprecated, please use "host_check_software"
        type: str
    host_check_software:
        description: The parameter (host-check-software) in requested url.
        type: str
    vpnsslweb_hostchecksoftware_checkitemlist:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action.
                choices: ['deny', 'require']
            id:
                type: int
                description: ID
                required: true
            md5s:
                type: raw
                description: (list) MD5 checksum.
            target:
                type: str
                description: Target.
            type:
                type: str
                description: Type.
                choices: ['file', 'registry', 'process']
            version:
                type: str
                description: Version.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Check item list.
      fortinet.fortimanager.fmgr_vpnsslweb_hostchecksoftware_checkitemlist:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        host_check_software: <your own value>
        state: present # <value in [present, absent]>
        vpnsslweb_hostchecksoftware_checkitemlist:
          id: 0 # Required variable, integer
          # action: <value in [deny, require]>
          # md5s: <list or string>
          # target: <string>
          # type: <value in [file, registry, process]>
          # version: <string>
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
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list',
        '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'host-check-software': {'type': 'str', 'api_name': 'host_check_software'},
        'host_check_software': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'vpnsslweb_hostchecksoftware_checkitemlist': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['deny', 'require'], 'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'md5s': {'type': 'raw'},
                'target': {'type': 'str'},
                'type': {'choices': ['file', 'registry', 'process'], 'type': 'str'},
                'version': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_hostchecksoftware_checkitemlist'),
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
