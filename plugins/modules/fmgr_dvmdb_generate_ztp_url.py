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
module: fmgr_dvmdb_generate_ztp_url
short_description: Device manager database generate ztp url
version_added: "2.16.0"
extends_documentation_fragment:
  - fortinet.fortimanager.general
options:
  adom:
    description: The parameter (adom) in requested url.
    type: str
    required: true
  dvmdb_generate_ztp_url:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      address:
        type: str
        description: Address.
      adom:
        type: list
        elements: str
        description: Adom.
      encryption:
        type: str
        description: Encryption.
        choices: ['disable', 'enable']
      scope:
        type: list
        elements: dict
        description: Scope.
        suboptions:
          name:
            type: str
            description: Name.
          vdom:
            type: str
            description: Vdom.
      script:
        type: str
        description: Script.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Device manager database generate ztp url
      fortinet.fortimanager.fmgr_dvmdb_generate_ztp_url:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        dvmdb_generate_ztp_url:
          # address: <string>
          # adom: <list or string>
          # encryption: <value in [disable, enable]>
          # scope:
          #   - name: <string>
          #     vdom: <string>
          # script: <string>
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
        '/dvmdb/adom/{adom}/generate/ztp/url',
        '/dvmdb/global/generate/ztp/url'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'dvmdb_generate_ztp_url': {
            'type': 'dict', 'v_range': [['8.0.1', '']],
            'options': {
                'address': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'adom': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                'encryption': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'scope': {
                    'v_range': [['8.0.1', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['8.0.1', '']], 'type': 'str'}, 'vdom': {'v_range': [['8.0.1', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'script': {'v_range': [['8.0.1', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('exec')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dvmdb_generate_ztp_url'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('exec', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_exec()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
