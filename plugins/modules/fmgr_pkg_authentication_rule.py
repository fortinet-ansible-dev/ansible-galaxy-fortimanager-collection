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
module: fmgr_pkg_authentication_rule
short_description: Configure Authentication Rules.
version_added: "2.1.0"
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_authentication_rule:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            active_auth_method:
                aliases: ['active-auth-method']
                type: str
                description: Select an active authentication method.
            comments:
                type: str
                description: Comment.
            ip_based:
                aliases: ['ip-based']
                type: str
                description: Enable/disable IP-based authentication.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Authentication rule name.
                required: true
            protocol:
                type: str
                description: Select the protocol to use for authentication
                choices: ['http', 'ftp', 'socks', 'ssh', 'ztna-portal']
            srcaddr:
                type: raw
                description: (list or str) Select an IPv4 source address from available options.
            srcaddr6:
                type: raw
                description: (list or str) Select an IPv6 source address.
            sso_auth_method:
                aliases: ['sso-auth-method']
                type: str
                description: Select a single-sign on
            status:
                type: str
                description: Enable/disable this authentication rule.
                choices: ['disable', 'enable']
            transaction_based:
                aliases: ['transaction-based']
                type: str
                description: Enable/disable transaction based authentication
                choices: ['disable', 'enable']
            web_auth_cookie:
                aliases: ['web-auth-cookie']
                type: str
                description: Enable/disable Web authentication cookies
                choices: ['disable', 'enable']
            web_portal:
                aliases: ['web-portal']
                type: str
                description: Enable/disable web portal for proxy transparent policy
                choices: ['disable', 'enable']
            dstaddr:
                type: raw
                description: (list or str) Select an IPv4 destination address from available options.
            dstaddr6:
                type: raw
                description: (list or str) Select an IPv6 destination address from available options.
            srcintf:
                type: raw
                description: (list or str) Incoming
            cors_depth:
                aliases: ['cors-depth']
                type: int
                description: Depth to allow CORS access
            cors_stateful:
                aliases: ['cors-stateful']
                type: str
                description: Enable/disable allowance of CORS access
                choices: ['disable', 'enable']
            cert_auth_cookie:
                aliases: ['cert-auth-cookie']
                type: str
                description: Enable/disable to use device certificate as authentication cookie
                choices: ['disable', 'enable']
            form_auth_fallback:
                aliases: ['form-auth-fallback']
                type: str
                description: Form auth fallback.
                choices: ['disable', 'enable']
            web_proxy:
                aliases: ['web-proxy']
                type: raw
                description: (list) Web proxy.
            session_logout:
                aliases: ['session-logout']
                type: str
                description: Enable/disable logout of a user from the current session.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Authentication Rules.
      fortinet.fortimanager.fmgr_pkg_authentication_rule:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        pkg: <your own value>
        state: present # <value in [present, absent]>
        pkg_authentication_rule:
          name: "your value" # Required variable, string
          # active_auth_method: <string>
          # comments: <string>
          # ip_based: <value in [disable, enable]>
          # protocol: <value in [http, ftp, socks, ...]>
          # srcaddr: <list or string>
          # srcaddr6: <list or string>
          # sso_auth_method: <string>
          # status: <value in [disable, enable]>
          # transaction_based: <value in [disable, enable]>
          # web_auth_cookie: <value in [disable, enable]>
          # web_portal: <value in [disable, enable]>
          # dstaddr: <list or string>
          # dstaddr6: <list or string>
          # srcintf: <list or string>
          # cors_depth: <integer>
          # cors_stateful: <value in [disable, enable]>
          # cert_auth_cookie: <value in [disable, enable]>
          # form_auth_fallback: <value in [disable, enable]>
          # web_proxy: <list or string>
          # session_logout: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/pkg/{pkg}/authentication/rule'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_authentication_rule': {
            'type': 'dict', 'v_range': [['6.2.1', '']],
            'options': {
                'active-auth-method': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'comments': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'ip-based': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['6.2.1', '']], 'required': True, 'type': 'str'},
                'protocol': {'v_range': [['6.2.1', '']], 'choices': ['http', 'ftp', 'socks', 'ssh', 'ztna-portal'], 'type': 'str'},
                'srcaddr': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'srcaddr6': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'sso-auth-method': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'status': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'transaction-based': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'web-auth-cookie': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'web-portal': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'dstaddr6': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'srcintf': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'cors-depth': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'cors-stateful': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cert-auth-cookie': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'form-auth-fallback': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'web-proxy': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'raw'},
                'session-logout': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_authentication_rule'),
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
