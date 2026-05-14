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
module: fmgr_system_sdnconnector_externalaccountlist
short_description: Configure AWS external account list.
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
    sdn-connector:
        description: Deprecated, please use "sdn_connector"
        type: str
    sdn_connector:
        description: The parameter (sdn-connector) in requested url.
        type: str
    system_sdnconnector_externalaccountlist:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            region_list:
                aliases: ['region-list']
                type: raw
                description: (list) AWS region name list.
            role_arn:
                aliases: ['role-arn']
                type: str
                description: AWS role ARN to assume.
            external_id:
                aliases: ['external-id']
                type: str
                description: AWS external ID.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure AWS external account list.
      fortinet.fortimanager.fmgr_system_sdnconnector_externalaccountlist:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        sdn_connector: <your own value>
        state: present # <value in [present, absent]>
        system_sdnconnector_externalaccountlist:
          # region_list: <list or string>
          # role_arn: <string>
          # external_id: <string>
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
        '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-account-list',
        '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-account-list'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'sdn-connector': {'type': 'str', 'api_name': 'sdn_connector'},
        'sdn_connector': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_sdnconnector_externalaccountlist': {
            'type': 'dict', 'v_range': [['7.0.3', '']],
            'options': {
                'region-list': {'v_range': [['7.0.3', '']], 'type': 'raw'},
                'role-arn': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'external-id': {'v_range': [['7.0.5', '7.0.16'], ['7.2.1', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sdnconnector_externalaccountlist'),
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
