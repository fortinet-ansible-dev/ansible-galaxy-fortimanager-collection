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
module: fmgr_system_certificate_local
short_description: Local keys and certificates.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_certificate_local:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            certificate:
                type: raw
                description: (list) Certificate.
            comment:
                type: str
                description: Local certificate comment.
            csr:
                type: raw
                description: (list) Certificate Signing Request.
            name:
                type: str
                description: Name of local certificate.
                required: true
            password:
                type: raw
                description: (list) Local certificate password.
            private_key:
                aliases: ['private-key']
                type: raw
                description: (list) Local certificate private-key.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Local keys and certificates.
      fortinet.fortimanager.fmgr_system_certificate_local:
        # workspace_locking_adom: <global or your adom name>
        state: present # <value in [present, absent]>
        system_certificate_local:
          name: "your value" # Required variable, string
          # certificate: <list or string>
          # comment: <string>
          # csr: <list or string>
          # password: <list or string>
          # private_key: <list or string>
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
        '/cli/global/system/certificate/local'
    ]
    module_arg_spec = {
        'system_certificate_local': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'certificate': {'type': 'raw'},
                'comment': {'type': 'str'},
                'csr': {'type': 'raw'},
                'name': {'required': True, 'type': 'str'},
                'password': {'no_log': True, 'type': 'raw'},
                'private-key': {'no_log': True, 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_certificate_local'),
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
