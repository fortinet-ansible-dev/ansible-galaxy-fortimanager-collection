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
module: fmgr_webfilter_profile_antiphish
short_description: AntiPhishing profile.
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    webfilter_profile_antiphish:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            check-basic-auth:
                type: str
                description: Deprecated, please rename it to check_basic_auth. Enable/disable checking of HTTP Basic Auth field for known credentials.
                choices:
                    - 'disable'
                    - 'enable'
            check-uri:
                type: str
                description: Deprecated, please rename it to check_uri. Enable/disable checking of GET URI parameters for known credentials.
                choices:
                    - 'disable'
                    - 'enable'
            custom-patterns:
                type: list
                elements: dict
                description: Deprecated, please rename it to custom_patterns.
                suboptions:
                    category:
                        type: str
                        description: Category that the pattern matches.
                        choices:
                            - 'username'
                            - 'password'
                    pattern:
                        type: str
                        description: Target pattern.
                    type:
                        type: str
                        description: Pattern will be treated either as a regex pattern or literal string.
                        choices:
                            - 'regex'
                            - 'literal'
            default-action:
                type: str
                description: Deprecated, please rename it to default_action. Action to be taken when there is no matching rule.
                choices:
                    - 'log'
                    - 'block'
                    - 'exempt'
            domain-controller:
                type: str
                description: Deprecated, please rename it to domain_controller. Domain for which to verify received credentials against.
            inspection-entries:
                type: list
                elements: dict
                description: Deprecated, please rename it to inspection_entries.
                suboptions:
                    action:
                        type: str
                        description: Action to be taken upon an AntiPhishing match.
                        choices:
                            - 'log'
                            - 'block'
                            - 'exempt'
                    fortiguard-category:
                        type: raw
                        description: (list) Deprecated, please rename it to fortiguard_category.
                    name:
                        type: str
                        description: Inspection target name.
            max-body-len:
                type: int
                description: Deprecated, please rename it to max_body_len. Maximum size of a POST body to check for credentials.
            status:
                type: str
                description: Toggle AntiPhishing functionality.
                choices:
                    - 'disable'
                    - 'enable'
            check-username-only:
                type: str
                description: Deprecated, please rename it to check_username_only. Enable/disable acting only on valid username credentials.
                choices:
                    - 'disable'
                    - 'enable'
            authentication:
                type: str
                description: Authentication methods.
                choices:
                    - 'domain-controller'
                    - 'ldap'
            ldap:
                type: str
                description: LDAP server for which to verify received credentials against.
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
    - name: AntiPhishing profile.
      fortinet.fortimanager.fmgr_webfilter_profile_antiphish:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        profile: <your own value>
        webfilter_profile_antiphish:
          check_basic_auth: <value in [disable, enable]>
          check_uri: <value in [disable, enable]>
          custom_patterns:
            -
              category: <value in [username, password]>
              pattern: <string>
              type: <value in [regex, literal]>
          default_action: <value in [log, block, exempt]>
          domain_controller: <string>
          inspection_entries:
            -
              action: <value in [log, block, exempt]>
              fortiguard_category: <list or string>
              name: <string>
          max_body_len: <integer>
          status: <value in [disable, enable]>
          check_username_only: <value in [disable, enable]>
          authentication: <value in [domain-controller, ldap]>
          ldap: <string>
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
        '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish',
        '/pm/config/global/obj/webfilter/profile/{profile}/antiphish'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish/{antiphish}',
        '/pm/config/global/obj/webfilter/profile/{profile}/antiphish/{antiphish}'
    ]

    url_params = ['adom', 'profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'webfilter_profile_antiphish': {
            'type': 'dict',
            'v_range': [['6.4.0', '']],
            'options': {
                'check-basic-auth': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'check-uri': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'custom-patterns': {
                    'v_range': [['6.4.0', '']],
                    'type': 'list',
                    'options': {
                        'category': {'v_range': [['6.4.0', '']], 'choices': ['username', 'password'], 'type': 'str'},
                        'pattern': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'type': {'v_range': [['7.0.0', '']], 'choices': ['regex', 'literal'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'default-action': {'v_range': [['6.4.0', '']], 'choices': ['log', 'block', 'exempt'], 'type': 'str'},
                'domain-controller': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'inspection-entries': {
                    'v_range': [['6.4.0', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.4.0', '']], 'choices': ['log', 'block', 'exempt'], 'type': 'str'},
                        'fortiguard-category': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                        'name': {'v_range': [['6.4.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'max-body-len': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'status': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'check-username-only': {'v_range': [['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'authentication': {'v_range': [['7.0.0', '']], 'choices': ['domain-controller', 'ldap'], 'type': 'str'},
                'ldap': {'v_range': [['7.0.0', '']], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile_antiphish'),
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
