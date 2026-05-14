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
module: fmgr_system_webproxy
short_description: Configure system web proxy.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_webproxy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            address:
                type: str
                description: Web proxy address.
            mode:
                type: str
                description:
                    - Web proxy mode
                    - proxy - proxy mode
                    - tunnel - tunnel mode
                choices: ['proxy', 'tunnel']
            password:
                type: raw
                description: (list) The password for the user name used for authentication.
            port:
                type: int
                description: The port number of the web proxy
            status:
                type: str
                description:
                    - Enable/disable system web proxy
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            username:
                type: str
                description: The user name used for authentication.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure system web proxy.
      fortinet.fortimanager.fmgr_system_webproxy:
        # workspace_locking_adom: <global or your adom name>
        system_webproxy:
          # address: <string>
          # mode: <value in [proxy, tunnel]>
          # password: <list or string>
          # port: <integer>
          # status: <value in [disable, enable]>
          # username: <string>
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
        '/cli/global/system/web-proxy'
    ]
    module_arg_spec = {
        'system_webproxy': {
            'type': 'dict', 'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']],
            'options': {
                'address': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'str'},
                'mode': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'choices': ['proxy', 'tunnel'], 'type': 'str'},
                'password': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'no_log': True, 'type': 'raw'},
                'port': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                'status': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'username': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_webproxy'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
