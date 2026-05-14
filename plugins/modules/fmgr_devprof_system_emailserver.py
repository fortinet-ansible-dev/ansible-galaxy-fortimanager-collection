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
module: fmgr_devprof_system_emailserver
short_description: Configure the email server used by the FortiGate various things.
version_added: "1.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_system_emailserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            authenticate:
                type: str
                description: Enable/disable authentication.
                choices: ['disable', 'enable']
            password:
                type: raw
                description: (list) SMTP server user password for authentication.
            port:
                type: int
                description: SMTP server port.
            reply_to:
                aliases: ['reply-to']
                type: str
                description: Reply-To email address.
            security:
                type: str
                description: Connection security used by the email server.
                choices: ['none', 'starttls', 'smtps']
            server:
                type: str
                description: SMTP server IP address or hostname.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: SMTP server IPv4 source IP.
            source_ip6:
                aliases: ['source-ip6']
                type: str
                description: SMTP server IPv6 source IP.
            ssl_min_proto_version:
                aliases: ['ssl-min-proto-version']
                type: str
                description: Minimum supported protocol version for SSL/TLS connections
                choices: ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3']
            type:
                type: str
                description: Use FortiGuard Message service or custom email server.
                choices: ['custom']
            username:
                type: str
                description: SMTP server user name for authentication.
            validate_server:
                aliases: ['validate-server']
                type: str
                description: Enable/disable validation of server certificate.
                choices: ['disable', 'enable']
            interface:
                type: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices: ['auto', 'sdwan', 'specify']
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure the email server used by the FortiGate various things.
      fortinet.fortimanager.fmgr_devprof_system_emailserver:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        devprof: <your own value>
        devprof_system_emailserver:
          # authenticate: <value in [disable, enable]>
          # password: <list or string>
          # port: <integer>
          # reply_to: <string>
          # security: <value in [none, starttls, smtps]>
          # server: <string>
          # source_ip: <string>
          # source_ip6: <string>
          # ssl_min_proto_version: <value in [default, TLSv1, TLSv1-1, ...]>
          # type: <value in [custom]>
          # username: <string>
          # validate_server: <value in [disable, enable]>
          # interface: <string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # vrf_select: <integer>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/email-server'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_emailserver': {
            'type': 'dict', 'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
            'options': {
                'authenticate': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'password': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'no_log': True, 'type': 'raw'},
                'port': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'reply-to': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'security': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['none', 'starttls', 'smtps'], 'type': 'str'},
                'server': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'source-ip': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'source-ip6': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'ssl-min-proto-version': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3'],
                    'type': 'str'
                },
                'type': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['custom'], 'type': 'str'},
                'username': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'validate-server': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'interface-select-method': {'v_range': [['7.0.0', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_emailserver'),
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
