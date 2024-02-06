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
module: fmgr_user_exchange
short_description: Configure MS Exchange server entries.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    user_exchange:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            addr-type:
                type: str
                description: Deprecated, please rename it to addr_type. Indicate whether the server IP-address is IPv4 or IPv6.
                choices:
                    - 'ipv4'
                    - 'ipv6'
            auth-level:
                type: str
                description: Deprecated, please rename it to auth_level. Authentication security level used for the RPC protocol layer.
                choices:
                    - 'low'
                    - 'medium'
                    - 'normal'
                    - 'high'
                    - 'connect'
                    - 'call'
                    - 'packet'
                    - 'integrity'
                    - 'privacy'
            auth-type:
                type: str
                description: Deprecated, please rename it to auth_type. Authentication security type used for the RPC protocol layer.
                choices:
                    - 'spnego'
                    - 'ntlm'
                    - 'kerberos'
            connect-protocol:
                type: str
                description: Deprecated, please rename it to connect_protocol. Connection protocol used to connect to MS Exchange service.
                choices:
                    - 'rpc-over-tcp'
                    - 'rpc-over-http'
                    - 'rpc-over-https'
            domain-name:
                type: str
                description: Deprecated, please rename it to domain_name. MS Exchange server fully qualified domain name.
            http-auth-type:
                type: str
                description: Deprecated, please rename it to http_auth_type. Authentication security type used for the HTTP transport.
                choices:
                    - 'ntlm'
                    - 'basic'
            ip:
                type: str
                description: Server IPv4 address.
            ip6:
                type: str
                description: Server IPv6 address.
            kdc-ip:
                type: raw
                description: (list) Deprecated, please rename it to kdc_ip. KDC IPv4 addresses for Kerberos authentication.
            name:
                type: str
                description: MS Exchange server entry name.
                required: true
            password:
                type: raw
                description: (list) Password for the specified username.
            server-name:
                type: str
                description: Deprecated, please rename it to server_name. MS Exchange server hostname.
            ssl-min-proto-version:
                type: str
                description: Deprecated, please rename it to ssl_min_proto_version. Minimum SSL/TLS protocol version for HTTPS transport
                choices:
                    - 'default'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'SSLv3'
                    - 'TLSv1'
                    - 'TLSv1-3'
            username:
                type: str
                description: User name used to sign in to the server.
            auto-discover-kdc:
                type: str
                description: Deprecated, please rename it to auto_discover_kdc. Enable/disable automatic discovery of KDC IP addresses.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure MS Exchange server entries.
      fortinet.fortimanager.fmgr_user_exchange:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        user_exchange:
          addr_type: <value in [ipv4, ipv6]>
          auth_level: <value in [low, medium, normal, ...]>
          auth_type: <value in [spnego, ntlm, kerberos]>
          connect_protocol: <value in [rpc-over-tcp, rpc-over-http, rpc-over-https]>
          domain_name: <string>
          http_auth_type: <value in [ntlm, basic]>
          ip: <string>
          ip6: <string>
          kdc_ip: <list or string>
          name: <string>
          password: <list or string>
          server_name: <string>
          ssl_min_proto_version: <value in [default, TLSv1-1, TLSv1-2, ...]>
          username: <string>
          auto_discover_kdc: <value in [disable, enable]>
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/user/exchange',
        '/pm/config/global/obj/user/exchange'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/user/exchange/{exchange}',
        '/pm/config/global/obj/user/exchange/{exchange}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'user_exchange': {
            'type': 'dict',
            'v_range': [['6.2.0', '']],
            'options': {
                'addr-type': {'v_range': [['6.2.0', '7.2.0']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'auth-level': {
                    'v_range': [['6.2.0', '']],
                    'choices': ['low', 'medium', 'normal', 'high', 'connect', 'call', 'packet', 'integrity', 'privacy'],
                    'type': 'str'
                },
                'auth-type': {'v_range': [['6.2.1', '']], 'choices': ['spnego', 'ntlm', 'kerberos'], 'type': 'str'},
                'connect-protocol': {'v_range': [['6.2.0', '']], 'choices': ['rpc-over-tcp', 'rpc-over-http', 'rpc-over-https'], 'type': 'str'},
                'domain-name': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'http-auth-type': {'v_range': [['6.2.1', '']], 'choices': ['ntlm', 'basic'], 'type': 'str'},
                'ip': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'ip6': {'v_range': [['6.2.0', '7.2.0']], 'type': 'str'},
                'kdc-ip': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'name': {'v_range': [['6.2.0', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['6.2.0', '']], 'no_log': True, 'type': 'raw'},
                'server-name': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'ssl-min-proto-version': {
                    'v_range': [['6.2.1', '']],
                    'choices': ['default', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3'],
                    'type': 'str'
                },
                'username': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'auto-discover-kdc': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_exchange'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
