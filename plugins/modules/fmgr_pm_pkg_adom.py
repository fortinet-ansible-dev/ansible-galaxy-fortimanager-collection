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
module: fmgr_pm_pkg_adom
short_description: Policy package or folder.
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
    pm_pkg_adom:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            name:
                type: str
                description: No description.
            obj ver:
                type: int
                description: Deprecated, please rename it to obj_ver.
            oid:
                type: int
                description: No description.
            package setting:
                type: dict
                description: Deprecated, please rename it to package_setting.
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
                    ssl-ssh-profile:
                        type: str
                        description: Deprecated, please rename it to ssl_ssh_profile.
            scope member:
                type: list
                elements: dict
                description: Deprecated, please rename it to scope_member.
                suboptions:
                    name:
                        type: str
                        description: No description.
                    vdom:
                        type: str
                        description: No description.
            type:
                type: str
                description: No description.
                choices:
                    - 'pkg'
                    - 'folder'
            package settings:
                type: dict
                description: Deprecated, please rename it to package_settings.
                suboptions:
                    central-nat:
                        type: str
                        description:
                            - Deprecated, please rename it to central_nat.
                            - disable -
                            - enable -
                        choices:
                            - 'disable'
                            - 'enable'
                    consolidated-firewall-mode:
                        type: str
                        description:
                            - Deprecated, please rename it to consolidated_firewall_mode.
                            - For flow-based policy package.
                            - disable -
                            - enable -
                        choices:
                            - 'disable'
                            - 'enable'
                    fwpolicy-implicit-log:
                        type: str
                        description:
                            - Deprecated, please rename it to fwpolicy_implicit_log.
                            - disable -
                            - enable -
                        choices:
                            - 'disable'
                            - 'enable'
                    fwpolicy6-implicit-log:
                        type: str
                        description:
                            - Deprecated, please rename it to fwpolicy6_implicit_log.
                            - disable -
                            - enable -
                        choices:
                            - 'disable'
                            - 'enable'
                    inspection-mode:
                        type: str
                        description:
                            - Deprecated, please rename it to inspection_mode.
                            - proxy -
                            - flow -
                        choices:
                            - 'proxy'
                            - 'flow'
                    ngfw-mode:
                        type: str
                        description:
                            - Deprecated, please rename it to ngfw_mode.
                            - For flow-based policy package.
                            - profile-based -
                            - policy-based -
                        choices:
                            - 'profile-based'
                            - 'policy-based'
                    policy-offload-level:
                        type: str
                        description:
                            - Deprecated, please rename it to policy_offload_level.
                            - disable -
                            - default -
                            - dos-offload -
                            - full-offload -
                        choices:
                            - 'disable'
                            - 'default'
                            - 'dos-offload'
                            - 'full-offload'
                    ssl-ssh-profile:
                        type: str
                        description: Deprecated, please rename it to ssl_ssh_profile. SSL-SSH profile required for NGFW-mode policy package.
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Create a package in a adom
      fortinet.fortimanager.fmgr_pm_pkg_adom:
        adom: "ansible"
        pm_pkg_adom:
          name: "ansible"
          type: "pkg"

    - name: Create a package in global adom
      fortinet.fortimanager.fmgr_pm_pkg_global:
        pm_pkg_global:
          name: "ansible"
          type: "pkg"
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
        '/pm/pkg/adom/{adom}'
    ]

    perobject_jrpc_urls = [
        '/pm/pkg/adom/{adom}'
    ]

    url_params = ['adom']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pm_pkg_adom': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'name': {'type': 'str'},
                'obj ver': {'type': 'int'},
                'oid': {'type': 'int'},
                'package setting': {
                    'type': 'dict',
                    'options': {
                        'central-nat': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'consolidated-firewall-mode': {
                            'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'fwpolicy-implicit-log': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwpolicy6-implicit-log': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'inspection-mode': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                        'ngfw-mode': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'choices': ['profile-based', 'policy-based'], 'type': 'str'},
                        'ssl-ssh-profile': {'v_range': [['6.0.0', '6.4.6'], ['7.0.0', '7.0.0']], 'type': 'str'}
                    }
                },
                'scope member': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                'type': {'choices': ['pkg', 'folder'], 'type': 'str'},
                'package settings': {
                    'type': 'dict',
                    'options': {
                        'central-nat': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'consolidated-firewall-mode': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwpolicy-implicit-log': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwpolicy6-implicit-log': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'inspection-mode': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                        'ngfw-mode': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'choices': ['profile-based', 'policy-based'], 'type': 'str'},
                        'policy-offload-level': {
                            'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']],
                            'choices': ['disable', 'default', 'dos-offload', 'full-offload'],
                            'type': 'str'
                        },
                        'ssl-ssh-profile': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'type': 'str'}
                    }
                }
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pm_pkg_adom'),
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
