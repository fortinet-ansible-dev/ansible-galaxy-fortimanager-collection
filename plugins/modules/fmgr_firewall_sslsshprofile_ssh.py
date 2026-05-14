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
module: fmgr_firewall_sslsshprofile_ssh
short_description: Configure SSH options.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    ssl-ssh-profile:
        description: Deprecated, please use "ssl_ssh_profile"
        type: str
    ssl_ssh_profile:
        description: The parameter (ssl-ssh-profile) in requested url.
        type: str
    firewall_sslsshprofile_ssh:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            inspect_all:
                aliases: ['inspect-all']
                type: str
                description: Level of SSL inspection.
                choices: ['disable', 'deep-inspection']
            ports:
                type: raw
                description: (list) Ports to use for scanning
            ssh_algorithm:
                aliases: ['ssh-algorithm']
                type: str
                description: Relative strength of encryption algorithms accepted during negotiation.
                choices: ['compatible', 'high-encryption']
            ssh_policy_check:
                aliases: ['ssh-policy-check']
                type: str
                description: Enable/disable SSH policy check.
                choices: ['disable', 'enable']
            ssh_tun_policy_check:
                aliases: ['ssh-tun-policy-check']
                type: str
                description: Enable/disable SSH tunnel policy check.
                choices: ['disable', 'enable']
            status:
                type: str
                description: Configure protocol inspection status.
                choices: ['disable', 'deep-inspection']
            unsupported_version:
                aliases: ['unsupported-version']
                type: str
                description: Action based on SSH version being unsupported.
                choices: ['block', 'bypass']
            block:
                type: list
                elements: str
                description: SSH blocking options.
                choices: ['x11-filter', 'ssh-shell', 'exec', 'port-forward']
            log:
                type: list
                elements: str
                description: SSH logging options.
                choices: ['x11-filter', 'ssh-shell', 'exec', 'port-forward']
            proxy_after_tcp_handshake:
                aliases: ['proxy-after-tcp-handshake']
                type: str
                description: Proxy traffic after the TCP 3-way handshake has been established
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure SSH options.
      fortinet.fortimanager.fmgr_firewall_sslsshprofile_ssh:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        ssl_ssh_profile: <your own value>
        firewall_sslsshprofile_ssh:
          # inspect_all: <value in [disable, deep-inspection]>
          # ports: <list or integer>
          # ssh_algorithm: <value in [compatible, high-encryption]>
          # ssh_policy_check: <value in [disable, enable]>
          # ssh_tun_policy_check: <value in [disable, enable]>
          # status: <value in [disable, deep-inspection]>
          # unsupported_version: <value in [block, bypass]>
          # block: ["x11-filter", "ssh-shell", "exec", "port-forward"]
          # log: ["x11-filter", "ssh-shell", "exec", "port-forward"]
          # proxy_after_tcp_handshake: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssh',
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssh'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'ssl-ssh-profile': {'type': 'str', 'api_name': 'ssl_ssh_profile'},
        'ssl_ssh_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_sslsshprofile_ssh': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'inspect-all': {'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                'ports': {'type': 'raw'},
                'ssh-algorithm': {'choices': ['compatible', 'high-encryption'], 'type': 'str'},
                'ssh-policy-check': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-tun-policy-check': {'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                'unsupported-version': {'choices': ['block', 'bypass'], 'type': 'str'},
                'block': {
                    'v_range': [['6.2.0', '6.4.15']],
                    'type': 'list',
                    'choices': ['x11-filter', 'ssh-shell', 'exec', 'port-forward'],
                    'elements': 'str'
                },
                'log': {
                    'v_range': [['6.2.0', '6.4.15']],
                    'type': 'list',
                    'choices': ['x11-filter', 'ssh-shell', 'exec', 'port-forward'],
                    'elements': 'str'
                },
                'proxy-after-tcp-handshake': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslsshprofile_ssh'),
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
