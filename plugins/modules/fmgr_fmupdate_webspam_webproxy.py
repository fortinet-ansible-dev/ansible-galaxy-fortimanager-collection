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
module: fmgr_fmupdate_webspam_webproxy
short_description: Configure the web proxy for use with FortiGuard antivirus and IPS updates.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    fmupdate_webspam_webproxy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ip:
                type: str
                description: IPv4 address of the web proxy.
            ip6:
                type: str
                description: IPv6 address of the web proxy.
            mode:
                type: str
                description:
                    - Web proxy mode
                    - proxy - HTTP proxy.
                    - tunnel - HTTP tunnel.
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
                    - Enable/disable connections through the web proxy
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            username:
                type: str
                description: The user name used for authentication.
            address:
                type: str
                description: Web proxy address.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure the web proxy for use with FortiGuard antivirus and IPS updates.
      fortinet.fortimanager.fmgr_fmupdate_webspam_webproxy:
        # workspace_locking_adom: <global or your adom name>
        fmupdate_webspam_webproxy:
          # ip: <string>
          # ip6: <string>
          # mode: <value in [proxy, tunnel]>
          # password: <list or string>
          # port: <integer>
          # status: <value in [disable, enable]>
          # username: <string>
          # address: <string>
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
        '/cli/global/fmupdate/web-spam/web-proxy'
    ]
    module_arg_spec = {
        'fmupdate_webspam_webproxy': {
            'type': 'dict', 'v_range': [['6.0.0', '7.4.0']],
            'options': {
                'ip': {'v_range': [['6.0.0', '6.2.1']], 'type': 'str'},
                'ip6': {'v_range': [['6.0.0', '6.2.1']], 'type': 'str'},
                'mode': {'v_range': [['6.0.0', '7.4.0']], 'choices': ['proxy', 'tunnel'], 'type': 'str'},
                'password': {'v_range': [['6.0.0', '7.4.0']], 'no_log': True, 'type': 'raw'},
                'port': {'v_range': [['6.0.0', '7.4.0']], 'type': 'int'},
                'status': {'v_range': [['6.0.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'username': {'v_range': [['6.0.0', '7.4.0']], 'type': 'str'},
                'address': {'v_range': [['6.2.2', '7.4.0']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmupdate_webspam_webproxy'),
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
