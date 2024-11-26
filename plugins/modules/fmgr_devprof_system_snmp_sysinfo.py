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
module: fmgr_devprof_system_snmp_sysinfo
short_description: SNMP system info configuration.
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
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_system_snmp_sysinfo:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            status:
                type: str
                description: Enable/disable SNMP.
                choices:
                    - 'disable'
                    - 'enable'
            append_index:
                aliases: ['append-index']
                type: str
                description: Enable/disable allowance of appending vdom or interface index in some RFC tables.
                choices:
                    - 'disable'
                    - 'enable'
            trap_high_cpu_threshold:
                aliases: ['trap-high-cpu-threshold']
                type: int
                description: CPU usage when trap is sent.
            trap_log_full_threshold:
                aliases: ['trap-log-full-threshold']
                type: int
                description: Log disk usage when trap is sent.
            engine_id:
                aliases: ['engine-id']
                type: str
                description: Local SNMP engineID string
            trap_freeable_memory_threshold:
                aliases: ['trap-freeable-memory-threshold']
                type: int
                description: Freeable memory usage when trap is sent.
            contact_info:
                aliases: ['contact-info']
                type: str
                description: Contact information.
            engine_id_type:
                aliases: ['engine-id-type']
                type: str
                description: Local SNMP engineID type
                choices:
                    - 'text'
                    - 'hex'
                    - 'mac'
            description:
                type: str
                description: System description.
            trap_free_memory_threshold:
                aliases: ['trap-free-memory-threshold']
                type: int
                description: Free memory usage when trap is sent.
            trap_low_memory_threshold:
                aliases: ['trap-low-memory-threshold']
                type: int
                description: Memory usage when trap is sent.
            location:
                type: str
                description: System location.
            non_mgmt_vdom_query:
                aliases: ['non-mgmt-vdom-query']
                type: str
                description: Enable/disable allowance of SNMPv3 query from non-management vdoms.
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
    - name: SNMP system info configuration.
      fortinet.fortimanager.fmgr_devprof_system_snmp_sysinfo:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        devprof: <your own value>
        devprof_system_snmp_sysinfo:
          status: <value in [disable, enable]>
          append_index: <value in [disable, enable]>
          trap_high_cpu_threshold: <integer>
          trap_log_full_threshold: <integer>
          engine_id: <string>
          trap_freeable_memory_threshold: <integer>
          contact_info: <string>
          engine_id_type: <value in [text, hex, mac]>
          description: <string>
          trap_free_memory_threshold: <integer>
          trap_low_memory_threshold: <integer>
          location: <string>
          non_mgmt_vdom_query: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/sysinfo'
    ]
    url_params = ['adom', 'devprof']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_snmp_sysinfo': {
            'type': 'dict',
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
            'options': {
                'status': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'append-index': {'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trap-high-cpu-threshold': {'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '']], 'type': 'int'},
                'trap-log-full-threshold': {'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '']], 'type': 'int'},
                'engine-id': {'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '']], 'type': 'str'},
                'trap-freeable-memory-threshold': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'contact-info': {'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '']], 'type': 'str'},
                'engine-id-type': {'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '']], 'choices': ['text', 'hex', 'mac'], 'type': 'str'},
                'description': {'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '']], 'type': 'str'},
                'trap-free-memory-threshold': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'trap-low-memory-threshold': {'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '']], 'type': 'int'},
                'location': {'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '']], 'type': 'str'},
                'non-mgmt-vdom-query': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_snmp_sysinfo'),
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
