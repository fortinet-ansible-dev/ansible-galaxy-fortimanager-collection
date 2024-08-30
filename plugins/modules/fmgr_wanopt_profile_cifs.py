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
module: fmgr_wanopt_profile_cifs
short_description: Enable/disable CIFS
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    wanopt_profile_cifs:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            byte-caching:
                type: str
                description: Deprecated, please rename it to byte_caching. Enable/disable byte-caching for HTTP.
                choices:
                    - 'disable'
                    - 'enable'
            log-traffic:
                type: str
                description: Deprecated, please rename it to log_traffic. Enable/disable logging.
                choices:
                    - 'disable'
                    - 'enable'
            port:
                type: raw
                description: (list) Single port number or port number range for CIFS.
            prefer-chunking:
                type: str
                description: Deprecated, please rename it to prefer_chunking. Select dynamic or fixed-size data chunking for HTTP WAN Optimization.
                choices:
                    - 'dynamic'
                    - 'fix'
            secure-tunnel:
                type: str
                description: Deprecated, please rename it to secure_tunnel. Enable/disable securing the WAN Opt tunnel using SSL.
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description: Enable/disable HTTP WAN Optimization.
                choices:
                    - 'disable'
                    - 'enable'
            tunnel-sharing:
                type: str
                description: Deprecated, please rename it to tunnel_sharing. Tunnel sharing mode for aggressive/non-aggressive and/or interactive/non-i...
                choices:
                    - 'private'
                    - 'shared'
                    - 'express-shared'
            protocol-opt:
                type: str
                description: Deprecated, please rename it to protocol_opt. Select Protocol specific optimitation or generic TCP optimization.
                choices:
                    - 'protocol'
                    - 'tcp'
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
    - name: Enable/disable CIFS
      fortinet.fortimanager.fmgr_wanopt_profile_cifs:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        profile: <your own value>
        wanopt_profile_cifs:
          byte_caching: <value in [disable, enable]>
          log_traffic: <value in [disable, enable]>
          port: <list or integer>
          prefer_chunking: <value in [dynamic, fix]>
          secure_tunnel: <value in [disable, enable]>
          status: <value in [disable, enable]>
          tunnel_sharing: <value in [private, shared, express-shared]>
          protocol_opt: <value in [protocol, tcp]>
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
        '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/cifs',
        '/pm/config/global/obj/wanopt/profile/{profile}/cifs'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/cifs/{cifs}',
        '/pm/config/global/obj/wanopt/profile/{profile}/cifs/{cifs}'
    ]

    url_params = ['adom', 'profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'wanopt_profile_cifs': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'byte-caching': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log-traffic': {'choices': ['disable', 'enable'], 'type': 'str'},
                'port': {'type': 'raw'},
                'prefer-chunking': {'choices': ['dynamic', 'fix'], 'type': 'str'},
                'secure-tunnel': {'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-sharing': {'choices': ['private', 'shared', 'express-shared'], 'type': 'str'},
                'protocol-opt': {'v_range': [['6.4.0', '']], 'choices': ['protocol', 'tcp'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanopt_profile_cifs'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
