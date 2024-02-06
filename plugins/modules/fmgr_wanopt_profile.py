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
module: fmgr_wanopt_profile
short_description: Configure WAN optimization profiles.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    wanopt_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth-group:
                type: str
                description: Deprecated, please rename it to auth_group. Optionally add an authentication group to restrict access to the WAN Optimizat...
            comments:
                type: str
                description: Comment.
            name:
                type: str
                description: Profile name.
                required: true
            transparent:
                type: str
                description: Enable/disable transparent mode.
                choices:
                    - 'disable'
                    - 'enable'
            cifs:
                type: dict
                description: No description.
                suboptions:
                    byte-caching:
                        type: str
                        description: Deprecated, please rename it to byte_caching. Enable/disable byte-caching.
                        choices:
                            - 'disable'
                            - 'enable'
                    log-traffic:
                        type: str
                        description: Deprecated, please rename it to log_traffic. Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    prefer-chunking:
                        type: str
                        description: Deprecated, please rename it to prefer_chunking. Select dynamic or fixed-size data chunking for WAN Optimization.
                        choices:
                            - 'dynamic'
                            - 'fix'
                    protocol-opt:
                        type: str
                        description: Deprecated, please rename it to protocol_opt. Select Protocol specific optimitation or generic TCP optimization.
                        choices:
                            - 'protocol'
                            - 'tcp'
                    secure-tunnel:
                        type: str
                        description: Deprecated, please rename it to secure_tunnel. Enable/disable securing the WAN Opt tunnel using SSL.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable WAN Optimization.
                        choices:
                            - 'disable'
                            - 'enable'
                    tunnel-sharing:
                        type: str
                        description: Deprecated, please rename it to tunnel_sharing. Tunnel sharing mode for aggressive/non-aggressive and/or interacti...
                        choices:
                            - 'private'
                            - 'shared'
                            - 'express-shared'
                    port:
                        type: raw
                        description: (list) No description.
            ftp:
                type: dict
                description: No description.
                suboptions:
                    byte-caching:
                        type: str
                        description: Deprecated, please rename it to byte_caching. Enable/disable byte-caching.
                        choices:
                            - 'disable'
                            - 'enable'
                    log-traffic:
                        type: str
                        description: Deprecated, please rename it to log_traffic. Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    prefer-chunking:
                        type: str
                        description: Deprecated, please rename it to prefer_chunking. Select dynamic or fixed-size data chunking for WAN Optimization.
                        choices:
                            - 'dynamic'
                            - 'fix'
                    protocol-opt:
                        type: str
                        description: Deprecated, please rename it to protocol_opt. Select Protocol specific optimitation or generic TCP optimization.
                        choices:
                            - 'protocol'
                            - 'tcp'
                    secure-tunnel:
                        type: str
                        description: Deprecated, please rename it to secure_tunnel. Enable/disable securing the WAN Opt tunnel using SSL.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl:
                        type: str
                        description: Enable/disable SSL/TLS offloading
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable WAN Optimization.
                        choices:
                            - 'disable'
                            - 'enable'
                    tunnel-sharing:
                        type: str
                        description: Deprecated, please rename it to tunnel_sharing. Tunnel sharing mode for aggressive/non-aggressive and/or interacti...
                        choices:
                            - 'private'
                            - 'shared'
                            - 'express-shared'
                    port:
                        type: raw
                        description: (list) No description.
            http:
                type: dict
                description: No description.
                suboptions:
                    byte-caching:
                        type: str
                        description: Deprecated, please rename it to byte_caching. Enable/disable byte-caching.
                        choices:
                            - 'disable'
                            - 'enable'
                    log-traffic:
                        type: str
                        description: Deprecated, please rename it to log_traffic. Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    prefer-chunking:
                        type: str
                        description: Deprecated, please rename it to prefer_chunking. Select dynamic or fixed-size data chunking for WAN Optimization.
                        choices:
                            - 'dynamic'
                            - 'fix'
                    protocol-opt:
                        type: str
                        description: Deprecated, please rename it to protocol_opt. Select Protocol specific optimitation or generic TCP optimization.
                        choices:
                            - 'protocol'
                            - 'tcp'
                    secure-tunnel:
                        type: str
                        description: Deprecated, please rename it to secure_tunnel. Enable/disable securing the WAN Opt tunnel using SSL.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl:
                        type: str
                        description: Enable/disable SSL/TLS offloading
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable WAN Optimization.
                        choices:
                            - 'disable'
                            - 'enable'
                    tunnel-sharing:
                        type: str
                        description: Deprecated, please rename it to tunnel_sharing. Tunnel sharing mode for aggressive/non-aggressive and/or interacti...
                        choices:
                            - 'private'
                            - 'shared'
                            - 'express-shared'
                    tunnel-non-http:
                        type: str
                        description: Deprecated, please rename it to tunnel_non_http. Configure how to process non-HTTP traffic when a profile configur...
                        choices:
                            - 'disable'
                            - 'enable'
                    unknown-http-version:
                        type: str
                        description: Deprecated, please rename it to unknown_http_version. How to handle HTTP sessions that do not comply with HTTP 0.
                        choices:
                            - 'best-effort'
                            - 'reject'
                            - 'tunnel'
                    port:
                        type: raw
                        description: (list) No description.
                    ssl-port:
                        type: raw
                        description: (list) Deprecated, please rename it to ssl_port.
            mapi:
                type: dict
                description: No description.
                suboptions:
                    byte-caching:
                        type: str
                        description: Deprecated, please rename it to byte_caching. Enable/disable byte-caching.
                        choices:
                            - 'disable'
                            - 'enable'
                    log-traffic:
                        type: str
                        description: Deprecated, please rename it to log_traffic. Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    secure-tunnel:
                        type: str
                        description: Deprecated, please rename it to secure_tunnel. Enable/disable securing the WAN Opt tunnel using SSL.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable WAN Optimization.
                        choices:
                            - 'disable'
                            - 'enable'
                    tunnel-sharing:
                        type: str
                        description: Deprecated, please rename it to tunnel_sharing. Tunnel sharing mode for aggressive/non-aggressive and/or interacti...
                        choices:
                            - 'private'
                            - 'shared'
                            - 'express-shared'
                    port:
                        type: raw
                        description: (list) No description.
            tcp:
                type: dict
                description: No description.
                suboptions:
                    byte-caching:
                        type: str
                        description: Deprecated, please rename it to byte_caching. Enable/disable byte-caching.
                        choices:
                            - 'disable'
                            - 'enable'
                    byte-caching-opt:
                        type: str
                        description: Deprecated, please rename it to byte_caching_opt. Select whether TCP byte-caching uses system memory only or both ...
                        choices:
                            - 'mem-only'
                            - 'mem-disk'
                    log-traffic:
                        type: str
                        description: Deprecated, please rename it to log_traffic. Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    port:
                        type: str
                        description: Port numbers or port number ranges for TCP.
                    secure-tunnel:
                        type: str
                        description: Deprecated, please rename it to secure_tunnel. Enable/disable securing the WAN Opt tunnel using SSL.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl:
                        type: str
                        description: Enable/disable SSL/TLS offloading
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-port:
                        type: raw
                        description: (list) Deprecated, please rename it to ssl_port. Port numbers or port number ranges on which to expect HTTPS traff...
                    status:
                        type: str
                        description: Enable/disable WAN Optimization.
                        choices:
                            - 'disable'
                            - 'enable'
                    tunnel-sharing:
                        type: str
                        description: Deprecated, please rename it to tunnel_sharing. Tunnel sharing mode for aggressive/non-aggressive and/or interacti...
                        choices:
                            - 'private'
                            - 'shared'
                            - 'express-shared'
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
    - name: Configure WAN optimization profiles.
      fortinet.fortimanager.fmgr_wanopt_profile:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        wanopt_profile:
          auth_group: <string>
          comments: <string>
          name: <string>
          transparent: <value in [disable, enable]>
          cifs:
            byte_caching: <value in [disable, enable]>
            log_traffic: <value in [disable, enable]>
            prefer_chunking: <value in [dynamic, fix]>
            protocol_opt: <value in [protocol, tcp]>
            secure_tunnel: <value in [disable, enable]>
            status: <value in [disable, enable]>
            tunnel_sharing: <value in [private, shared, express-shared]>
            port: <list or integer>
          ftp:
            byte_caching: <value in [disable, enable]>
            log_traffic: <value in [disable, enable]>
            prefer_chunking: <value in [dynamic, fix]>
            protocol_opt: <value in [protocol, tcp]>
            secure_tunnel: <value in [disable, enable]>
            ssl: <value in [disable, enable]>
            status: <value in [disable, enable]>
            tunnel_sharing: <value in [private, shared, express-shared]>
            port: <list or integer>
          http:
            byte_caching: <value in [disable, enable]>
            log_traffic: <value in [disable, enable]>
            prefer_chunking: <value in [dynamic, fix]>
            protocol_opt: <value in [protocol, tcp]>
            secure_tunnel: <value in [disable, enable]>
            ssl: <value in [disable, enable]>
            status: <value in [disable, enable]>
            tunnel_sharing: <value in [private, shared, express-shared]>
            tunnel_non_http: <value in [disable, enable]>
            unknown_http_version: <value in [best-effort, reject, tunnel]>
            port: <list or integer>
            ssl_port: <list or integer>
          mapi:
            byte_caching: <value in [disable, enable]>
            log_traffic: <value in [disable, enable]>
            secure_tunnel: <value in [disable, enable]>
            status: <value in [disable, enable]>
            tunnel_sharing: <value in [private, shared, express-shared]>
            port: <list or integer>
          tcp:
            byte_caching: <value in [disable, enable]>
            byte_caching_opt: <value in [mem-only, mem-disk]>
            log_traffic: <value in [disable, enable]>
            port: <string>
            secure_tunnel: <value in [disable, enable]>
            ssl: <value in [disable, enable]>
            ssl_port: <list or integer>
            status: <value in [disable, enable]>
            tunnel_sharing: <value in [private, shared, express-shared]>
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
        '/pm/config/adom/{adom}/obj/wanopt/profile',
        '/pm/config/global/obj/wanopt/profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}',
        '/pm/config/global/obj/wanopt/profile/{profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'wanopt_profile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'auth-group': {'type': 'str'},
                'comments': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'transparent': {'choices': ['disable', 'enable'], 'type': 'str'},
                'cifs': {
                    'type': 'dict',
                    'options': {
                        'byte-caching': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-traffic': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'prefer-chunking': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['dynamic', 'fix'], 'type': 'str'},
                        'protocol-opt': {'v_range': [['6.4.5', '']], 'choices': ['protocol', 'tcp'], 'type': 'str'},
                        'secure-tunnel': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tunnel-sharing': {
                            'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                            'choices': ['private', 'shared', 'express-shared'],
                            'type': 'str'
                        },
                        'port': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'raw'}
                    }
                },
                'ftp': {
                    'type': 'dict',
                    'options': {
                        'byte-caching': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-traffic': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'prefer-chunking': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['dynamic', 'fix'], 'type': 'str'},
                        'protocol-opt': {'v_range': [['6.4.5', '']], 'choices': ['protocol', 'tcp'], 'type': 'str'},
                        'secure-tunnel': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tunnel-sharing': {
                            'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                            'choices': ['private', 'shared', 'express-shared'],
                            'type': 'str'
                        },
                        'port': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'raw'}
                    }
                },
                'http': {
                    'type': 'dict',
                    'options': {
                        'byte-caching': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-traffic': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'prefer-chunking': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['dynamic', 'fix'], 'type': 'str'},
                        'protocol-opt': {'v_range': [['6.4.5', '']], 'choices': ['protocol', 'tcp'], 'type': 'str'},
                        'secure-tunnel': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tunnel-sharing': {
                            'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                            'choices': ['private', 'shared', 'express-shared'],
                            'type': 'str'
                        },
                        'tunnel-non-http': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'unknown-http-version': {
                            'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                            'choices': ['best-effort', 'reject', 'tunnel'],
                            'type': 'str'
                        },
                        'port': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'raw'},
                        'ssl-port': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'raw'}
                    }
                },
                'mapi': {
                    'type': 'dict',
                    'options': {
                        'byte-caching': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-traffic': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'secure-tunnel': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tunnel-sharing': {
                            'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                            'choices': ['private', 'shared', 'express-shared'],
                            'type': 'str'
                        },
                        'port': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'raw'}
                    }
                },
                'tcp': {
                    'type': 'dict',
                    'options': {
                        'byte-caching': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'byte-caching-opt': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['mem-only', 'mem-disk'], 'type': 'str'},
                        'log-traffic': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'port': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                        'secure-tunnel': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-port': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'raw'},
                        'status': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tunnel-sharing': {
                            'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']],
                            'choices': ['private', 'shared', 'express-shared'],
                            'type': 'str'
                        }
                    }
                }
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanopt_profile'),
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
