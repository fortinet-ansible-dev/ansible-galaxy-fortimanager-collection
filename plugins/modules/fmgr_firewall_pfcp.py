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
module: fmgr_firewall_pfcp
short_description: Configure PFCP.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "2.12.0"
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
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
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
    firewall_pfcp:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            denied_log:
                aliases: ['denied-log']
                type: str
                description: Enable/disable logging denied PFCP packets.
                choices:
                    - 'disable'
                    - 'enable'
            forwarded_log:
                aliases: ['forwarded-log']
                type: str
                description: Enable/disable logging forwarded PFCP packets.
                choices:
                    - 'disable'
                    - 'enable'
            invalid_reserved_field:
                aliases: ['invalid-reserved-field']
                type: str
                description: Allow or deny invalid reserved field in PFCP header packets.
                choices:
                    - 'deny'
                    - 'allow'
            log_freq:
                aliases: ['log-freq']
                type: int
                description: Logging frequency of PFCP packets.
            max_message_length:
                aliases: ['max-message-length']
                type: int
                description: Maximum message length.
            message_filter:
                aliases: ['message-filter']
                type: list
                elements: str
                description: PFCP message filter.
            min_message_length:
                aliases: ['min-message-length']
                type: int
                description: Minimum message length.
            monitor_mode:
                aliases: ['monitor-mode']
                type: str
                description: PFCP monitor mode.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'vdom'
            name:
                type: str
                description: PFCP profile name.
                required: true
            pfcp_timeout:
                aliases: ['pfcp-timeout']
                type: int
                description: Set PFCP timeout
            traffic_count_log:
                aliases: ['traffic-count-log']
                type: str
                description: Enable/disable logging session traffic counter.
                choices:
                    - 'disable'
                    - 'enable'
            unknown_version:
                aliases: ['unknown-version']
                type: str
                description: Allow or deny unknown version packets.
                choices:
                    - 'deny'
                    - 'allow'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure PFCP.
      fortinet.fortimanager.fmgr_firewall_pfcp:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        firewall_pfcp:
          name: "your value" # Required variable, string
          # denied_log: <value in [disable, enable]>
          # forwarded_log: <value in [disable, enable]>
          # invalid_reserved_field: <value in [deny, allow]>
          # log_freq: <integer>
          # max_message_length: <integer>
          # message_filter: <list or string>
          # min_message_length: <integer>
          # monitor_mode: <value in [disable, enable, vdom]>
          # pfcp_timeout: <integer>
          # traffic_count_log: <value in [disable, enable]>
          # unknown_version: <value in [deny, allow]>
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
        '/pm/config/adom/{adom}/obj/firewall/pfcp',
        '/pm/config/global/obj/firewall/pfcp'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_pfcp': {
            'type': 'dict',
            'v_range': [['7.6.4', '']],
            'options': {
                'denied-log': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forwarded-log': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'invalid-reserved-field': {'v_range': [['7.6.4', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                'log-freq': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'max-message-length': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'message-filter': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'min-message-length': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'monitor-mode': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable', 'vdom'], 'type': 'str'},
                'name': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'str'},
                'pfcp-timeout': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'traffic-count-log': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unknown-version': {'v_range': [['7.6.4', '']], 'choices': ['deny', 'allow'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_pfcp'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
