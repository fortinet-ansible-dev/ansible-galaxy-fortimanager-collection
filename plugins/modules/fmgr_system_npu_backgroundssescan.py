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
module: fmgr_system_npu_backgroundssescan
short_description: Configure driver background scan for SSE.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    system_npu_backgroundssescan:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            scan:
                type: str
                description: Enable/disable background SSE scan by driver thread
                choices:
                    - 'disable'
                    - 'enable'
            stats_update_interval:
                aliases: ['stats-update-interval']
                type: int
                description: Stats update interval
            udp_keepalive_interval:
                aliases: ['udp-keepalive-interval']
                type: int
                description: UDP keepalive interval
            scan_stale:
                aliases: ['scan-stale']
                type: int
                description: Configure scanning of active or stale sessions
            scan_vt:
                aliases: ['scan-vt']
                type: int
                description: Select version/type to scan
            stats_qual_access:
                aliases: ['stats-qual-access']
                type: int
                description: Statistics update access qualification in seconds
            stats_qual_duration:
                aliases: ['stats-qual-duration']
                type: int
                description: Statistics update duration qualification in seconds
            udp_qual_access:
                aliases: ['udp-qual-access']
                type: int
                description: UDP keepalive access qualification in seconds
            udp_qual_duration:
                aliases: ['udp-qual-duration']
                type: int
                description: UDP keepalive duration qualification in seconds
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
    - name: Configure driver background scan for SSE.
      fortinet.fortimanager.fmgr_system_npu_backgroundssescan:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        system_npu_backgroundssescan:
          scan: <value in [disable, enable]>
          stats_update_interval: <integer>
          udp_keepalive_interval: <integer>
          scan_stale: <integer>
          scan_vt: <integer>
          stats_qual_access: <integer>
          stats_qual_duration: <integer>
          udp_qual_access: <integer>
          udp_qual_duration: <integer>
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
        '/pm/config/adom/{adom}/obj/system/npu/background-sse-scan',
        '/pm/config/global/obj/system/npu/background-sse-scan'
    ]
    url_params = ['adom']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'system_npu_backgroundssescan': {
            'type': 'dict',
            'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']],
            'options': {
                'scan': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'stats-update-interval': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                'udp-keepalive-interval': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                'scan-stale': {'v_range': [['7.0.12', '7.0.13'], ['7.2.6', '7.2.8'], ['7.4.1', '']], 'type': 'int'},
                'scan-vt': {'v_range': [['7.0.12', '7.0.13'], ['7.2.6', '7.2.8'], ['7.4.1', '']], 'type': 'int'},
                'stats-qual-access': {'v_range': [['7.0.12', '7.0.13'], ['7.2.6', '7.2.8'], ['7.4.1', '']], 'type': 'int'},
                'stats-qual-duration': {'v_range': [['7.0.12', '7.0.13'], ['7.2.6', '7.2.8'], ['7.4.1', '']], 'type': 'int'},
                'udp-qual-access': {'v_range': [['7.0.12', '7.0.13'], ['7.2.6', '7.2.8'], ['7.4.1', '']], 'type': 'int'},
                'udp-qual-duration': {'v_range': [['7.0.12', '7.0.13'], ['7.2.6', '7.2.8'], ['7.4.1', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_backgroundssescan'),
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
