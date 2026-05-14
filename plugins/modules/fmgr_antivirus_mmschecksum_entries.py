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
module: fmgr_antivirus_mmschecksum_entries
short_description: modify this MMS content checksum list
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
    mms-checksum:
        description: Deprecated, please use "mms_checksum"
        type: str
    mms_checksum:
        description: The parameter (mms-checksum) in requested url.
        type: str
    antivirus_mmschecksum_entries:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            checksum:
                type: str
                description: MMS attachment checksum value
            name:
                type: str
                description: Entry name, for administrator reference
                required: true
            status:
                type: str
                description: Apply this entry during attachment inspection
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Modify this MMS content checksum list
      fortinet.fortimanager.fmgr_antivirus_mmschecksum_entries:
        adom: FortiCarrier
        mms_checksum: "1" # id
        state: present
        antivirus_mmschecksum_entries:
          checksum: "test_checksum"
          name: "entries-name"
          status: enable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the mms-checksum entries
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "antivirus_mmschecksum_entries"
          params:
            adom: "FortiCarrier" # This is FOC-only object, data will only be returned under FortiCarrier adom
            entries: ""
            mms_checksum: "1" # id
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
        '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}/entries',
        '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}/entries'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'mms-checksum': {'type': 'str', 'api_name': 'mms_checksum'},
        'mms_checksum': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'antivirus_mmschecksum_entries': {
            'type': 'dict', 'v_range': [['6.0.0', '7.6.2']],
            'options': {
                'checksum': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'name': {'v_range': [['6.0.0', '7.6.2']], 'required': True, 'type': 'str'},
                'status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'antivirus_mmschecksum_entries'),
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
