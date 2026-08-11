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
module: fmgr_system_csf_trustedlist_adom
short_description: Cli system csf trusted list adom
version_added: "2.15.0"
extends_documentation_fragment:
  - fortinet.fortimanager.general
  - fortinet.fortimanager.general.full_crud
options:
  trusted-list:
    description: Deprecated, please use "trusted_list"
    type: str
  trusted_list:
    description: The parameter (trusted-list) in requested url.
    type: str
  system_csf_trustedlist_adom:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      adom_name:
        aliases: ['adom-name']
        type: str
        description: Adom name.
'''

EXAMPLES = '''
- name: Test CSF trusted-list ADOM settings
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create the parent CSF trusted-list entry
      fortinet.fortimanager.fmgr_system_csf_trustedlist:
        enable_log: true
        state: present
        system_csf_trustedlist:
          name: "1"
          action: accept
          adom_access: specify
          authorization_type: serial
          serial: test_device

    - name: Configure a CSF trusted-list ADOM
      fortinet.fortimanager.fmgr_system_csf_trustedlist_adom:
        enable_log: true
        trusted_list: "1"
        state: present
        system_csf_trustedlist_adom:
          adom_name: root
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
        '/cli/global/system/csf/trusted-list/{trusted-list}/adom'
    ]
    module_arg_spec = {
        'trusted-list': {'type': 'str', 'api_name': 'trusted_list'},
        'trusted_list': {'type': 'str'},
        'system_csf_trustedlist_adom': {
            'type': 'dict', 'v_range': [['7.6.7', '']],
            'options': {'adom-name': {'v_range': [['7.6.7', '']], 'type': 'str'}}
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_csf_trustedlist_adom'),
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
