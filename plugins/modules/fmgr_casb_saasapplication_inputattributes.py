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
module: fmgr_casb_saasapplication_inputattributes
short_description: SaaS application input attributes.
version_added: "2.14.0"
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
    saas-application:
        description: Deprecated, please use "saas_application"
        type: str
    saas_application:
        description: The parameter (saas-application) in requested url.
        type: str
    casb_saasapplication_inputattributes:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            attr_type:
                aliases: ['attr-type']
                type: str
                description: CASB attribute type.
                choices: ['tenant']
            default:
                type: str
                description: CASB attribute default value.
                choices: ['string', 'string-list']
            description:
                type: str
                description: CASB attribute description.
            fallback_input:
                aliases: ['fallback-input']
                type: str
                description: CASB attribute legacy input.
                choices: ['disable', 'enable']
            name:
                type: str
                description: CASB attribute name.
                required: true
            required:
                type: str
                description: CASB attribute required.
                choices: ['disable', 'enable']
            type:
                type: str
                description: CASB attribute format type.
                choices: ['string', 'string-list', 'integer', 'integer-list', 'boolean']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: SaaS application input attributes.
      fortinet.fortimanager.fmgr_casb_saasapplication_inputattributes:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        saas_application: <your own value>
        state: present # <value in [present, absent]>
        casb_saasapplication_inputattributes:
          name: "your value" # Required variable, string
          # attr_type: <value in [tenant]>
          # default: <value in [string, string-list]>
          # description: <string>
          # fallback_input: <value in [disable, enable]>
          # required: <value in [disable, enable]>
          # type: <value in [string, string-list, integer, ...]>
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
        '/pm/config/adom/{adom}/obj/casb/saas-application/{saas-application}/input-attributes',
        '/pm/config/global/obj/casb/saas-application/{saas-application}/input-attributes'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'saas-application': {'type': 'str', 'api_name': 'saas_application'},
        'saas_application': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'casb_saasapplication_inputattributes': {
            'type': 'dict', 'v_range': [['7.6.2', '']],
            'options': {
                'attr-type': {'v_range': [['7.6.2', '']], 'choices': ['tenant'], 'type': 'str'},
                'default': {'v_range': [['7.6.2', '']], 'choices': ['string', 'string-list'], 'type': 'str'},
                'description': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'fallback-input': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.6.2', '']], 'required': True, 'type': 'str'},
                'required': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.6.2', '']], 'choices': ['string', 'string-list', 'integer', 'integer-list', 'boolean'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_saasapplication_inputattributes'),
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
