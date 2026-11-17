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
module: fmgr_devprof_system_ntp_keys
short_description: Configure authentication keys for this FortiGate to perform NTP server functionality.
version_added: "2.16.0"
extends_documentation_fragment:
  - fortinet.fortimanager.general
  - fortinet.fortimanager.general.full_crud
options:
  adom:
    description: The parameter (adom) in requested url.
    type: str
    required: true
  devprof:
    description: The parameter (devprof) in requested url.
    type: str
    required: true
  devprof_system_ntp_keys:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      key:
        type: list
        elements: str
        description: Key for MD5
      key_id:
        aliases: ['key-id']
        type: int
        description: Key ID for authentication.
      key_type:
        aliases: ['key-type']
        type: str
        description: Select NTP authentication type.
        choices: ['SHA1', 'SHA256', 'MD5', 'AES128']
      ntpv3:
        type: str
        description: Enable to use NTPv3 instead of NTPv4.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable to use the authentication key.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure authentication keys for this FortiGate to perform NTP server functionality.
      fortinet.fortimanager.fmgr_devprof_system_ntp_keys:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        devprof: <your own value>
        state: present # <value in [present, absent]>
        devprof_system_ntp_keys:
          # key: <list or string>
          # key_id: <integer>
          # key_type: <value in [SHA1, SHA256, MD5, ...]>
          # ntpv3: <value in [disable, enable]>
          # status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/ntp/keys'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_ntp_keys': {
            'type': 'dict', 'v_range': [['8.0.1', '']], 'no_log': False,
            'options': {
                'key': {'v_range': [['8.0.1', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'key-id': {'v_range': [['8.0.1', '']], 'no_log': True, 'type': 'int'},
                'key-type': {'v_range': [['8.0.1', '']], 'choices': ['SHA1', 'SHA256', 'MD5', 'AES128'], 'type': 'str'},
                'ntpv3': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_ntp_keys'),
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
