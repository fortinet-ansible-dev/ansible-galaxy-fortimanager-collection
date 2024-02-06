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
module: fmgr_waf_profile_urlaccess
short_description: URL access list
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    waf_profile_urlaccess:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            access-pattern:
                type: list
                elements: dict
                description: Deprecated, please rename it to access_pattern.
                suboptions:
                    id:
                        type: int
                        description: URL access pattern ID.
                    negate:
                        type: str
                        description: Enable/disable match negation.
                        choices:
                            - 'disable'
                            - 'enable'
                    pattern:
                        type: str
                        description: URL pattern.
                    regex:
                        type: str
                        description: Enable/disable regular expression based pattern match.
                        choices:
                            - 'disable'
                            - 'enable'
                    srcaddr:
                        type: str
                        description: Source address.
            action:
                type: str
                description: Action.
                choices:
                    - 'bypass'
                    - 'permit'
                    - 'block'
            address:
                type: str
                description: Host address.
            id:
                type: int
                description: URL access ID.
                required: true
            log:
                type: str
                description: Enable/disable logging.
                choices:
                    - 'disable'
                    - 'enable'
            severity:
                type: str
                description: Severity.
                choices:
                    - 'low'
                    - 'medium'
                    - 'high'
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
    - name: URL access list
      fortinet.fortimanager.fmgr_waf_profile_urlaccess:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        profile: <your own value>
        state: present # <value in [present, absent]>
        waf_profile_urlaccess:
          access_pattern:
            -
              id: <integer>
              negate: <value in [disable, enable]>
              pattern: <string>
              regex: <value in [disable, enable]>
              srcaddr: <string>
          action: <value in [bypass, permit, block]>
          address: <string>
          id: <integer>
          log: <value in [disable, enable]>
          severity: <value in [low, medium, high]>
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
        '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access',
        '/pm/config/global/obj/waf/profile/{profile}/url-access'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}',
        '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}'
    ]

    url_params = ['adom', 'profile']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'waf_profile_urlaccess': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'access-pattern': {
                    'type': 'list',
                    'options': {
                        'id': {'type': 'int'},
                        'negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'pattern': {'type': 'str'},
                        'regex': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'srcaddr': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'action': {'choices': ['bypass', 'permit', 'block'], 'type': 'str'},
                'address': {'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'severity': {'choices': ['low', 'medium', 'high'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'waf_profile_urlaccess'),
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
