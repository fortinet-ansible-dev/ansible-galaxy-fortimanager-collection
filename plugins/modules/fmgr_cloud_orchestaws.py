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
module: fmgr_cloud_orchestaws
short_description: Cloud orchest aws
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
    cloud_orchestaws:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            connector:
                type: str
                description: Connector.
            name:
                type: str
                description: Name.
                required: true
            region_name:
                aliases: ['region-name']
                type: str
                description: Region name.
                choices: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1',
                          'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'eu-south-2',
                          'eu-central-1', 'eu-central-2', 'ca-central-1', 'ap-southeast-1',
                          'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4', 'ap-south-1',
                          'ap-south-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
                          'af-south-1', 'me-central-1', 'me-south-1', 'sa-east-1', 'ap-east-1',
                          'us-gov-east-1', 'us-gov-west-1', 'ca-west-1', 'il-central-1',
                          'ap-southeast-5', 'ap-southeast-7', 'mx-central-1']
            template_configuration:
                aliases: ['template-configuration']
                type: str
                description: Template configuration.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Cloud orchest aws
      fortinet.fortimanager.fmgr_cloud_orchestaws:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        cloud_orchestaws:
          name: "your value" # Required variable, string
          # connector: <string>
          # region_name: <value in [us-east-1, us-east-2, us-west-1, ...]>
          # template_configuration: <string>
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
        '/pm/config/adom/{adom}/obj/cloud/orchest-aws',
        '/pm/config/global/obj/cloud/orchest-aws'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'cloud_orchestaws': {
            'type': 'dict', 'v_range': [['7.4.0', '']],
            'options': {
                'connector': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'name': {'v_range': [['7.4.0', '']], 'required': True, 'type': 'str'},
                'region-name': {
                    'v_range': [['7.4.0', '']],
                    'choices': [
                        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1',
                        'eu-south-2', 'eu-central-1', 'eu-central-2', 'ca-central-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3',
                        'ap-southeast-4', 'ap-south-1', 'ap-south-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'af-south-1', 'me-central-1',
                        'me-south-1', 'sa-east-1', 'ap-east-1', 'us-gov-east-1', 'us-gov-west-1', 'ca-west-1', 'il-central-1', 'ap-southeast-5',
                        'ap-southeast-7', 'mx-central-1'
                    ],
                    'type': 'str'
                },
                'template-configuration': {'v_range': [['7.4.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cloud_orchestaws'),
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
