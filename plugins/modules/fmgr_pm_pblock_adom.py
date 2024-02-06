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
module: fmgr_pm_pblock_adom
short_description: no description
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
    pm_pblock_adom:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: No description.
            oid:
                type: int
                description: No description.
            package settings:
                type: dict
                description: Deprecated, please rename it to package_settings.
                suboptions:
                    central-nat:
                        type: str
                        description: Deprecated, please rename it to central_nat.
                        choices:
                            - 'disable'
                            - 'enable'
                    consolidated-firewall-mode:
                        type: str
                        description: Deprecated, please rename it to consolidated_firewall_mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    fwpolicy-implicit-log:
                        type: str
                        description: Deprecated, please rename it to fwpolicy_implicit_log.
                        choices:
                            - 'disable'
                            - 'enable'
                    fwpolicy6-implicit-log:
                        type: str
                        description: Deprecated, please rename it to fwpolicy6_implicit_log.
                        choices:
                            - 'disable'
                            - 'enable'
                    inspection-mode:
                        type: str
                        description: Deprecated, please rename it to inspection_mode.
                        choices:
                            - 'proxy'
                            - 'flow'
                    ngfw-mode:
                        type: str
                        description: Deprecated, please rename it to ngfw_mode.
                        choices:
                            - 'profile-based'
                            - 'policy-based'
                    policy-offload-level:
                        type: str
                        description: Deprecated, please rename it to policy_offload_level.
                        choices:
                            - 'disable'
                            - 'default'
                            - 'dos-offload'
                            - 'full-offload'
                    ssl-ssh-profile:
                        type: str
                        description: Deprecated, please rename it to ssl_ssh_profile.
            type:
                type: str
                description: No description.
                choices:
                    - 'pblock'
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
    - name: No description
      fortinet.fortimanager.fmgr_pm_pblock_adom:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        pm_pblock_adom:
          name: <string>
          oid: <integer>
          package_settings:
            central_nat: <value in [disable, enable]>
            consolidated_firewall_mode: <value in [disable, enable]>
            fwpolicy_implicit_log: <value in [disable, enable]>
            fwpolicy6_implicit_log: <value in [disable, enable]>
            inspection_mode: <value in [proxy, flow]>
            ngfw_mode: <value in [profile-based, policy-based]>
            policy_offload_level: <value in [disable, default, dos-offload, ...]>
            ssl_ssh_profile: <string>
          type: <value in [pblock]>
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
        '/pm/pblock/adom/{adom}'
    ]

    perobject_jrpc_urls = [
        '/pm/pblock/adom/{adom}'
    ]

    url_params = ['adom']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pm_pblock_adom': {
            'type': 'dict',
            'v_range': [['7.0.3', '']],
            'options': {
                'name': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'oid': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'package settings': {
                    'type': 'dict',
                    'options': {
                        'central-nat': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'consolidated-firewall-mode': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwpolicy-implicit-log': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwpolicy6-implicit-log': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'inspection-mode': {'v_range': [['7.0.3', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                        'ngfw-mode': {'v_range': [['7.0.3', '']], 'choices': ['profile-based', 'policy-based'], 'type': 'str'},
                        'policy-offload-level': {
                            'v_range': [['7.0.3', '']],
                            'choices': ['disable', 'default', 'dos-offload', 'full-offload'],
                            'type': 'str'
                        },
                        'ssl-ssh-profile': {'v_range': [['7.0.3', '']], 'type': 'str'}
                    }
                },
                'type': {'v_range': [['7.0.3', '']], 'choices': ['pblock'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pm_pblock_adom'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
