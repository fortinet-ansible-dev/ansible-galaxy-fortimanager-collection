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
module: fmgr_firewall_profileprotocoloptions_ssh
short_description: Configure SFTP and SCP protocol options.
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
    profile-protocol-options:
        description: Deprecated, please use "profile_protocol_options"
        type: str
    profile_protocol_options:
        description: The parameter (profile-protocol-options) in requested url.
        type: str
    firewall_profileprotocoloptions_ssh:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comfort_amount:
                aliases: ['comfort-amount']
                type: int
                description: Amount of data to send in a transmission for client comforting
            comfort_interval:
                aliases: ['comfort-interval']
                type: int
                description: Period of time between start, or last transmission, and the next client comfort transmission of data
            options:
                type: list
                elements: str
                description: One or more options that can be applied to the session.
                choices:
                    - 'oversize'
                    - 'clientcomfort'
                    - 'servercomfort'
            oversize_limit:
                aliases: ['oversize-limit']
                type: int
                description: Maximum in-memory file size that can be scanned
            scan_bzip2:
                aliases: ['scan-bzip2']
                type: str
                description: Enable/disable scanning of BZip2 compressed files.
                choices:
                    - 'disable'
                    - 'enable'
            uncompressed_nest_limit:
                aliases: ['uncompressed-nest-limit']
                type: int
                description: Maximum nested levels of compression that can be uncompressed and scanned
            uncompressed_oversize_limit:
                aliases: ['uncompressed-oversize-limit']
                type: int
                description: Maximum in-memory uncompressed file size that can be scanned
            ssl_offloaded:
                aliases: ['ssl-offloaded']
                type: str
                description: SSL decryption and encryption performed by an external device.
                choices:
                    - 'no'
                    - 'yes'
            stream_based_uncompressed_limit:
                aliases: ['stream-based-uncompressed-limit']
                type: int
                description: Maximum stream-based uncompressed data size that will be scanned
            tcp_window_maximum:
                aliases: ['tcp-window-maximum']
                type: int
                description: Maximum dynamic TCP window size.
            tcp_window_minimum:
                aliases: ['tcp-window-minimum']
                type: int
                description: Minimum dynamic TCP window size.
            tcp_window_size:
                aliases: ['tcp-window-size']
                type: int
                description: Set TCP static window size.
            tcp_window_type:
                aliases: ['tcp-window-type']
                type: str
                description: TCP window type to use for this protocol.
                choices:
                    - 'system'
                    - 'static'
                    - 'dynamic'
                    - 'auto-tuning'
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
    - name: Configure SFTP and SCP protocol options.
      fortinet.fortimanager.fmgr_firewall_profileprotocoloptions_ssh:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        profile_protocol_options: <your own value>
        firewall_profileprotocoloptions_ssh:
          comfort_amount: <integer>
          comfort_interval: <integer>
          options:
            - "oversize"
            - "clientcomfort"
            - "servercomfort"
          oversize_limit: <integer>
          scan_bzip2: <value in [disable, enable]>
          uncompressed_nest_limit: <integer>
          uncompressed_oversize_limit: <integer>
          ssl_offloaded: <value in [no, yes]>
          stream_based_uncompressed_limit: <integer>
          tcp_window_maximum: <integer>
          tcp_window_minimum: <integer>
          tcp_window_size: <integer>
          tcp_window_type: <value in [system, static, dynamic, ...]>
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
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/ssh',
        '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/ssh'
    ]
    url_params = ['adom', 'profile-protocol-options']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile-protocol-options': {'type': 'str', 'api_name': 'profile_protocol_options'},
        'profile_protocol_options': {'type': 'str'},
        'firewall_profileprotocoloptions_ssh': {
            'type': 'dict',
            'v_range': [['6.2.2', '']],
            'options': {
                'comfort-amount': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'comfort-interval': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'options': {'v_range': [['6.2.2', '']], 'type': 'list', 'choices': ['oversize', 'clientcomfort', 'servercomfort'], 'elements': 'str'},
                'oversize-limit': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'scan-bzip2': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uncompressed-nest-limit': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'uncompressed-oversize-limit': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'ssl-offloaded': {'v_range': [['7.0.0', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'stream-based-uncompressed-limit': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'tcp-window-maximum': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'tcp-window-minimum': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'tcp-window-size': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'tcp-window-type': {'v_range': [['7.0.0', '']], 'choices': ['system', 'static', 'dynamic', 'auto-tuning'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profileprotocoloptions_ssh'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
