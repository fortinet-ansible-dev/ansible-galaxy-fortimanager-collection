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
module: fmgr_system_saml
short_description: Global settings for SAML authentication.
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
    system_saml:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            acs-url:
                type: str
                description: Deprecated, please rename it to acs_url. SP ACS
            cert:
                type: str
                description: Certificate name.
            entity-id:
                type: str
                description: Deprecated, please rename it to entity_id. SP entity ID.
            idp-cert:
                type: str
                description: Deprecated, please rename it to idp_cert. IDP Certificate name.
            idp-entity-id:
                type: str
                description: Deprecated, please rename it to idp_entity_id. IDP entity ID.
            idp-single-logout-url:
                type: str
                description: Deprecated, please rename it to idp_single_logout_url. IDP single logout url.
            idp-single-sign-on-url:
                type: str
                description: Deprecated, please rename it to idp_single_sign_on_url. IDP single sign-on URL.
            login-auto-redirect:
                type: str
                description:
                    - Deprecated, please rename it to login_auto_redirect.
                    - Enable/Disable auto redirect to IDP login page.
                    - disable - Disable auto redirect to IDP Login Page.
                    - enable - Enable auto redirect to IDP Login Page.
                choices:
                    - 'disable'
                    - 'enable'
            role:
                type: str
                description:
                    - SAML role.
                    - IDP - IDentiy Provider.
                    - SP - Service Provider.
                choices:
                    - 'IDP'
                    - 'SP'
                    - 'FAB-SP'
            server-address:
                type: str
                description: Deprecated, please rename it to server_address. Server address.
            service-providers:
                type: list
                elements: dict
                description: Deprecated, please rename it to service_providers. Service-Providers.
                suboptions:
                    idp-entity-id:
                        type: str
                        description: Deprecated, please rename it to idp_entity_id. IDP Entity ID.
                    idp-single-logout-url:
                        type: str
                        description: Deprecated, please rename it to idp_single_logout_url. IDP single logout url.
                    idp-single-sign-on-url:
                        type: str
                        description: Deprecated, please rename it to idp_single_sign_on_url. IDP single sign-on URL.
                    name:
                        type: str
                        description: Name.
                    prefix:
                        type: str
                        description: Prefix.
                    sp-cert:
                        type: str
                        description: Deprecated, please rename it to sp_cert. SP certificate name.
                    sp-entity-id:
                        type: str
                        description: Deprecated, please rename it to sp_entity_id. SP Entity ID.
                    sp-single-logout-url:
                        type: str
                        description: Deprecated, please rename it to sp_single_logout_url. SP single logout URL.
                    sp-single-sign-on-url:
                        type: str
                        description: Deprecated, please rename it to sp_single_sign_on_url. SP single sign-on URL.
                    sp-adom:
                        type: str
                        description: Deprecated, please rename it to sp_adom. SP adom name.
                    sp-profile:
                        type: str
                        description: Deprecated, please rename it to sp_profile. SP profile name.
            sls-url:
                type: str
                description: Deprecated, please rename it to sls_url. SP SLS
            status:
                type: str
                description:
                    - Enable/disable SAML authentication
                    - disable - Disable SAML authentication.
                    - enable - Enabld SAML authentication.
                choices:
                    - 'disable'
                    - 'enable'
            default-profile:
                type: str
                description: Deprecated, please rename it to default_profile. Default Profile Name.
            fabric-idp:
                type: list
                elements: dict
                description: Deprecated, please rename it to fabric_idp. Fabric-Idp.
                suboptions:
                    dev-id:
                        type: str
                        description: Deprecated, please rename it to dev_id. IDP Device ID.
                    idp-cert:
                        type: str
                        description: Deprecated, please rename it to idp_cert. IDP Certificate name.
                    idp-entity-id:
                        type: str
                        description: Deprecated, please rename it to idp_entity_id. IDP entity ID.
                    idp-single-logout-url:
                        type: str
                        description: Deprecated, please rename it to idp_single_logout_url. IDP single logout url.
                    idp-single-sign-on-url:
                        type: str
                        description: Deprecated, please rename it to idp_single_sign_on_url. IDP single sign-on URL.
                    idp-status:
                        type: str
                        description:
                            - Deprecated, please rename it to idp_status.
                            - Enable/disable SAML authentication
                            - disable - Disable SAML authentication.
                            - enable - Enabld SAML authentication.
                        choices:
                            - 'disable'
                            - 'enable'
            forticloud-sso:
                type: str
                description:
                    - Deprecated, please rename it to forticloud_sso.
                    - Enable/disable FortiCloud SSO
                    - disable - Disable Forticloud SSO.
                    - enable - Enabld Forticloud SSO.
                choices:
                    - 'disable'
                    - 'enable'
            user-auto-create:
                type: str
                description:
                    - Deprecated, please rename it to user_auto_create.
                    - Enable/disable user auto creation
                    - disable - Disable auto create user.
                    - enable - Enable auto create user.
                choices:
                    - 'disable'
                    - 'enable'
            auth-request-signed:
                type: str
                description:
                    - Deprecated, please rename it to auth_request_signed.
                    - Enable/Disable auth request signed.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            want-assertions-signed:
                type: str
                description:
                    - Deprecated, please rename it to want_assertions_signed.
                    - Enable/Disable want assertions signed.
                    - disable - Disable setting.
                    - enable - Enable setting.
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
    - name: Global settings for SAML authentication.
      fortinet.fortimanager.fmgr_system_saml:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        system_saml:
          acs_url: <string>
          cert: <string>
          entity_id: <string>
          idp_cert: <string>
          idp_entity_id: <string>
          idp_single_logout_url: <string>
          idp_single_sign_on_url: <string>
          login_auto_redirect: <value in [disable, enable]>
          role: <value in [IDP, SP, FAB-SP]>
          server_address: <string>
          service_providers:
            -
              idp_entity_id: <string>
              idp_single_logout_url: <string>
              idp_single_sign_on_url: <string>
              name: <string>
              prefix: <string>
              sp_cert: <string>
              sp_entity_id: <string>
              sp_single_logout_url: <string>
              sp_single_sign_on_url: <string>
              sp_adom: <string>
              sp_profile: <string>
          sls_url: <string>
          status: <value in [disable, enable]>
          default_profile: <string>
          fabric_idp:
            -
              dev_id: <string>
              idp_cert: <string>
              idp_entity_id: <string>
              idp_single_logout_url: <string>
              idp_single_sign_on_url: <string>
              idp_status: <value in [disable, enable]>
          forticloud_sso: <value in [disable, enable]>
          user_auto_create: <value in [disable, enable]>
          auth_request_signed: <value in [disable, enable]>
          want_assertions_signed: <value in [disable, enable]>
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
        '/cli/global/system/saml'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/saml/{saml}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'system_saml': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'acs-url': {'type': 'str'},
                'cert': {'type': 'str'},
                'entity-id': {'type': 'str'},
                'idp-cert': {'type': 'str'},
                'idp-entity-id': {'type': 'str'},
                'idp-single-logout-url': {'type': 'str'},
                'idp-single-sign-on-url': {'type': 'str'},
                'login-auto-redirect': {'choices': ['disable', 'enable'], 'type': 'str'},
                'role': {'choices': ['IDP', 'SP', 'FAB-SP'], 'type': 'str'},
                'server-address': {'type': 'str'},
                'service-providers': {
                    'type': 'list',
                    'options': {
                        'idp-entity-id': {'type': 'str'},
                        'idp-single-logout-url': {'type': 'str'},
                        'idp-single-sign-on-url': {'type': 'str'},
                        'name': {'type': 'str'},
                        'prefix': {'type': 'str'},
                        'sp-cert': {'type': 'str'},
                        'sp-entity-id': {'type': 'str'},
                        'sp-single-logout-url': {'type': 'str'},
                        'sp-single-sign-on-url': {'type': 'str'},
                        'sp-adom': {'v_range': [['7.2.0', '']], 'type': 'str'},
                        'sp-profile': {'v_range': [['7.2.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'sls-url': {'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'default-profile': {'v_range': [['6.2.5', '']], 'type': 'str'},
                'fabric-idp': {
                    'v_range': [['6.4.0', '']],
                    'type': 'list',
                    'options': {
                        'dev-id': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'idp-cert': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'idp-entity-id': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'idp-single-logout-url': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'idp-single-sign-on-url': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'idp-status': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'forticloud-sso': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-auto-create': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-request-signed': {'v_range': [['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'want-assertions-signed': {'v_range': [['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_saml'),
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
