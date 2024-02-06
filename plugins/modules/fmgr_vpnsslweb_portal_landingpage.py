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
module: fmgr_vpnsslweb_portal_landingpage
short_description: Landing page options.
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
    portal:
        description: The parameter (portal) in requested url.
        type: str
        required: true
    vpnsslweb_portal_landingpage:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            form-data:
                type: list
                elements: dict
                description: Deprecated, please rename it to form_data.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    value:
                        type: str
                        description: Value.
            logout-url:
                type: str
                description: Deprecated, please rename it to logout_url. Landing page log out URL.
            sso:
                type: str
                description: Single sign-on.
                choices:
                    - 'disable'
                    - 'static'
                    - 'auto'
            sso-credential:
                type: str
                description: Deprecated, please rename it to sso_credential. Single sign-on credentials.
                choices:
                    - 'sslvpn-login'
                    - 'alternative'
            sso-password:
                type: raw
                description: (list) Deprecated, please rename it to sso_password.
            sso-username:
                type: str
                description: Deprecated, please rename it to sso_username. SSO user name.
            url:
                type: str
                description: Landing page URL.
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
    - name: Landing page options.
      fortinet.fortimanager.fmgr_vpnsslweb_portal_landingpage:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        portal: <your own value>
        vpnsslweb_portal_landingpage:
          form_data:
            -
              name: <string>
              value: <string>
          logout_url: <string>
          sso: <value in [disable, static, auto]>
          sso_credential: <value in [sslvpn-login, alternative]>
          sso_password: <list or string>
          sso_username: <string>
          url: <string>
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
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/landing-page',
        '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/landing-page'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/landing-page/{landing-page}',
        '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/landing-page/{landing-page}'
    ]

    url_params = ['adom', 'portal']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'portal': {'required': True, 'type': 'str'},
        'vpnsslweb_portal_landingpage': {
            'type': 'dict',
            'v_range': [['7.4.0', '']],
            'options': {
                'form-data': {
                    'v_range': [['7.4.0', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['7.4.0', '']], 'type': 'str'}, 'value': {'v_range': [['7.4.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'logout-url': {'v_range': [['7.4.0', '7.4.1']], 'type': 'str'},
                'sso': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'static', 'auto'], 'type': 'str'},
                'sso-credential': {'v_range': [['7.4.0', '']], 'choices': ['sslvpn-login', 'alternative'], 'type': 'str'},
                'sso-password': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'raw'},
                'sso-username': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'url': {'v_range': [['7.4.0', '']], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_portal_landingpage'),
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
