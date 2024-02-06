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
module: fmgr_pkg_authentication_setting
short_description: Configure authentication setting.
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_authentication_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            active-auth-scheme:
                type: str
                description: Deprecated, please rename it to active_auth_scheme. Active authentication method
            auth-https:
                type: str
                description: Deprecated, please rename it to auth_https. Enable/disable redirecting HTTP user authentication to HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            captive-portal:
                type: str
                description: Deprecated, please rename it to captive_portal. Captive portal host name.
            captive-portal-ip:
                type: str
                description: Deprecated, please rename it to captive_portal_ip. Captive portal IP address.
            captive-portal-ip6:
                type: str
                description: Deprecated, please rename it to captive_portal_ip6. Captive portal IPv6 address.
            captive-portal-port:
                type: int
                description: Deprecated, please rename it to captive_portal_port. Captive portal port number
            captive-portal-ssl-port:
                type: int
                description: Deprecated, please rename it to captive_portal_ssl_port. Captive portal SSL port number
            captive-portal-type:
                type: str
                description: Deprecated, please rename it to captive_portal_type. Captive portal type.
                choices:
                    - 'fqdn'
                    - 'ip'
            captive-portal6:
                type: str
                description: Deprecated, please rename it to captive_portal6. IPv6 captive portal host name.
            rewrite-https-port:
                type: int
                description: Deprecated, please rename it to rewrite_https_port. Rewrite to HTTPS port
            sso-auth-scheme:
                type: str
                description: Deprecated, please rename it to sso_auth_scheme. Single-Sign-On authentication method
            dev-range:
                type: raw
                description: (list or str) Deprecated, please rename it to dev_range. Address range for the IP based device query.
            user-cert-ca:
                type: raw
                description: (list or str) Deprecated, please rename it to user_cert_ca. CA certificate used for client certificate verification.
            cert-auth:
                type: str
                description: Deprecated, please rename it to cert_auth. Enable/disable redirecting certificate authentication to HTTPS portal.
                choices:
                    - 'disable'
                    - 'enable'
            cert-captive-portal:
                type: str
                description: Deprecated, please rename it to cert_captive_portal. Certificate captive portal host name.
            cert-captive-portal-ip:
                type: str
                description: Deprecated, please rename it to cert_captive_portal_ip. Certificate captive portal IP address.
            cert-captive-portal-port:
                type: int
                description: Deprecated, please rename it to cert_captive_portal_port. Certificate captive portal port number
            cookie-max-age:
                type: int
                description: Deprecated, please rename it to cookie_max_age. Persistent web portal cookie maximum age in minutes
            cookie-refresh-div:
                type: int
                description: Deprecated, please rename it to cookie_refresh_div. Refresh rate divider of persistent web portal cookie
            ip-auth-cookie:
                type: str
                description: Deprecated, please rename it to ip_auth_cookie. Enable/disable persistent cookie on IP based web portal authentication
                choices:
                    - 'disable'
                    - 'enable'
            persistent-cookie:
                type: str
                description: Deprecated, please rename it to persistent_cookie. Enable/disable persistent cookie on web portal authentication
                choices:
                    - 'disable'
                    - 'enable'
            update-time:
                type: str
                description: Deprecated, please rename it to update_time. Time of the last update.
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
    - name: Configure authentication setting.
      fortinet.fortimanager.fmgr_pkg_authentication_setting:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        pkg: <your own value>
        pkg_authentication_setting:
          active_auth_scheme: <string>
          auth_https: <value in [disable, enable]>
          captive_portal: <string>
          captive_portal_ip: <string>
          captive_portal_ip6: <string>
          captive_portal_port: <integer>
          captive_portal_ssl_port: <integer>
          captive_portal_type: <value in [fqdn, ip]>
          captive_portal6: <string>
          rewrite_https_port: <integer>
          sso_auth_scheme: <string>
          dev_range: <list or string>
          user_cert_ca: <list or string>
          cert_auth: <value in [disable, enable]>
          cert_captive_portal: <string>
          cert_captive_portal_ip: <string>
          cert_captive_portal_port: <integer>
          cookie_max_age: <integer>
          cookie_refresh_div: <integer>
          ip_auth_cookie: <value in [disable, enable]>
          persistent_cookie: <value in [disable, enable]>
          update_time: <string>
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
        '/pm/config/adom/{adom}/pkg/{pkg}/authentication/setting'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/authentication/setting/{setting}'
    ]

    url_params = ['adom', 'pkg']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'pkg_authentication_setting': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'active-auth-scheme': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'auth-https': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'captive-portal': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'captive-portal-ip': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'captive-portal-ip6': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'captive-portal-port': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'captive-portal-ssl-port': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'captive-portal-type': {'v_range': [['6.2.1', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                'captive-portal6': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'rewrite-https-port': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'sso-auth-scheme': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'dev-range': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'user-cert-ca': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'cert-auth': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cert-captive-portal': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'cert-captive-portal-ip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'cert-captive-portal-port': {'v_range': [['7.0.1', '']], 'type': 'int'},
                'cookie-max-age': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'cookie-refresh-div': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'ip-auth-cookie': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'persistent-cookie': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-time': {'v_range': [['7.2.0', '']], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_authentication_setting'),
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
