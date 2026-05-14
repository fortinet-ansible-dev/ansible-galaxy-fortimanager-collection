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
module: fmgr_cloud_orchestawsconnector
short_description: Cloud orchest awsconnector
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
    cloud_orchestawsconnector:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            access_key_id:
                aliases: ['access-key-id']
                type: str
                description: Access key id.
            access_key_secret:
                aliases: ['access-key-secret']
                type: raw
                description: (list) Access key secret.
            name:
                type: str
                description: Name.
                required: true
            use_metadata_iam:
                aliases: ['use-metadata-iam']
                type: str
                description: Use metadata iam.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Cloud orchest awsconnector
      fortinet.fortimanager.fmgr_cloud_orchestawsconnector:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        cloud_orchestawsconnector:
          name: "your value" # Required variable, string
          # access_key_id: <string>
          # access_key_secret: <list or string>
          # use_metadata_iam: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/cloud/orchest-awsconnector',
        '/pm/config/global/obj/cloud/orchest-awsconnector'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'cloud_orchestawsconnector': {
            'type': 'dict', 'v_range': [['7.4.0', '']],
            'options': {
                'access-key-id': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'str'},
                'access-key-secret': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'raw'},
                'name': {'v_range': [['7.4.0', '']], 'required': True, 'type': 'str'},
                'use-metadata-iam': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cloud_orchestawsconnector'),
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
