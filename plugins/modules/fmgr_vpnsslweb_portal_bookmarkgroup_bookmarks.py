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
module: fmgr_vpnsslweb_portal_bookmarkgroup_bookmarks
short_description: Bookmark table.
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
    portal:
        description: The parameter (portal) in requested url.
        type: str
        required: true
    bookmark-group:
        description: Deprecated, please use "bookmark_group"
        type: str
    bookmark_group:
        description: The parameter (bookmark-group) in requested url.
        type: str
    vpnsslweb_portal_bookmarkgroup_bookmarks:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            additional-params:
                type: str
                description: Deprecated, please rename it to additional_params. Additional parameters.
            apptype:
                type: str
                description: Application type.
                choices:
                    - 'web'
                    - 'telnet'
                    - 'ssh'
                    - 'ftp'
                    - 'smb'
                    - 'vnc'
                    - 'rdp'
                    - 'citrix'
                    - 'rdpnative'
                    - 'portforward'
                    - 'sftp'
            description:
                type: str
                description: Description.
            folder:
                type: str
                description: Network shared file folder parameter.
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
            host:
                type: str
                description: Host name/IP parameter.
            listening-port:
                type: int
                description: Deprecated, please rename it to listening_port. Listening port
            load-balancing-info:
                type: str
                description: Deprecated, please rename it to load_balancing_info. The load balancing information or cookie which should be provided to ...
            logon-password:
                type: raw
                description: (list) Deprecated, please rename it to logon_password.
            logon-user:
                type: str
                description: Deprecated, please rename it to logon_user. Logon user.
            name:
                type: str
                description: Bookmark name.
                required: true
            port:
                type: int
                description: Remote port.
            preconnection-blob:
                type: str
                description: Deprecated, please rename it to preconnection_blob. An arbitrary string which identifies the RDP source.
            preconnection-id:
                type: int
                description: Deprecated, please rename it to preconnection_id. The numeric ID of the RDP source
            remote-port:
                type: int
                description: Deprecated, please rename it to remote_port. Remote port
            security:
                type: str
                description: Security mode for RDP connection.
                choices:
                    - 'rdp'
                    - 'nla'
                    - 'tls'
                    - 'any'
            server-layout:
                type: str
                description: Deprecated, please rename it to server_layout. Server side keyboard layout.
                choices:
                    - 'en-us-qwerty'
                    - 'de-de-qwertz'
                    - 'fr-fr-azerty'
                    - 'it-it-qwerty'
                    - 'sv-se-qwerty'
                    - 'failsafe'
                    - 'en-gb-qwerty'
                    - 'es-es-qwerty'
                    - 'fr-ch-qwertz'
                    - 'ja-jp-qwerty'
                    - 'pt-br-qwerty'
                    - 'tr-tr-qwerty'
                    - 'fr-ca-qwerty'
            show-status-window:
                type: str
                description: Deprecated, please rename it to show_status_window. Enable/disable showing of status window.
                choices:
                    - 'disable'
                    - 'enable'
            sso:
                type: str
                description: Single Sign-On.
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
            sso-credential-sent-once:
                type: str
                description: Deprecated, please rename it to sso_credential_sent_once. Single sign-on credentials are only sent once to remote server.
                choices:
                    - 'disable'
                    - 'enable'
            sso-password:
                type: raw
                description: (list) Deprecated, please rename it to sso_password.
            sso-username:
                type: str
                description: Deprecated, please rename it to sso_username. SSO user name.
            url:
                type: str
                description: URL parameter.
            domain:
                type: str
                description: Login domain.
            color-depth:
                type: str
                description: Deprecated, please rename it to color_depth. Color depth per pixel.
                choices:
                    - '8'
                    - '16'
                    - '32'
            height:
                type: int
                description: Screen height
            keyboard-layout:
                type: str
                description: Deprecated, please rename it to keyboard_layout. Keyboard layout.
                choices:
                    - 'ar'
                    - 'da'
                    - 'de'
                    - 'de-ch'
                    - 'en-gb'
                    - 'en-uk'
                    - 'en-us'
                    - 'es'
                    - 'fi'
                    - 'fr'
                    - 'fr-be'
                    - 'fr-ca'
                    - 'fr-ch'
                    - 'hr'
                    - 'hu'
                    - 'it'
                    - 'ja'
                    - 'lt'
                    - 'lv'
                    - 'mk'
                    - 'no'
                    - 'pl'
                    - 'pt'
                    - 'pt-br'
                    - 'ru'
                    - 'sl'
                    - 'sv'
                    - 'tk'
                    - 'tr'
                    - 'fr-ca-m'
                    - 'wg'
                    - 'ar-101'
                    - 'ar-102'
                    - 'ar-102-azerty'
                    - 'can-mul'
                    - 'cz'
                    - 'cz-qwerty'
                    - 'cz-pr'
                    - 'nl'
                    - 'de-ibm'
                    - 'en-uk-ext'
                    - 'en-us-dvorak'
                    - 'es-var'
                    - 'fi-sami'
                    - 'hu-101'
                    - 'it-142'
                    - 'ko'
                    - 'lt-ibm'
                    - 'lt-std'
                    - 'lav-std'
                    - 'lav-leg'
                    - 'mk-std'
                    - 'no-sami'
                    - 'pol-214'
                    - 'pol-pr'
                    - 'pt-br-abnt2'
                    - 'ru-mne'
                    - 'ru-t'
                    - 'sv-sami'
                    - 'tuk'
                    - 'tur-f'
                    - 'tur-q'
                    - 'zh-sym-sg-us'
                    - 'zh-sym-us'
                    - 'zh-tr-hk'
                    - 'zh-tr-mo'
                    - 'zh-tr-us'
                    - 'fr-apple'
                    - 'la-am'
                    - 'ja-106'
            restricted-admin:
                type: str
                description: Deprecated, please rename it to restricted_admin. Enable/disable restricted admin mode for RDP.
                choices:
                    - 'disable'
                    - 'enable'
            send-preconnection-id:
                type: str
                description: Deprecated, please rename it to send_preconnection_id. Enable/disable sending of preconnection ID.
                choices:
                    - 'disable'
                    - 'enable'
            width:
                type: int
                description: Screen width
            vnc-keyboard-layout:
                type: str
                description: Deprecated, please rename it to vnc_keyboard_layout. Keyboard layout.
                choices:
                    - 'da'
                    - 'de'
                    - 'de-ch'
                    - 'en-uk'
                    - 'es'
                    - 'fi'
                    - 'fr'
                    - 'fr-be'
                    - 'it'
                    - 'no'
                    - 'pt'
                    - 'sv'
                    - 'nl'
                    - 'en-uk-ext'
                    - 'it-142'
                    - 'pt-br-abnt2'
                    - 'default'
                    - 'fr-ca-mul'
                    - 'gd'
                    - 'us-intl'
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
    - name: Bookmark table.
      fortinet.fortimanager.fmgr_vpnsslweb_portal_bookmarkgroup_bookmarks:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        portal: <your own value>
        bookmark_group: <your own value>
        state: present # <value in [present, absent]>
        vpnsslweb_portal_bookmarkgroup_bookmarks:
          additional_params: <string>
          apptype: <value in [web, telnet, ssh, ...]>
          description: <string>
          folder: <string>
          form_data:
            -
              name: <string>
              value: <string>
          host: <string>
          listening_port: <integer>
          load_balancing_info: <string>
          logon_password: <list or string>
          logon_user: <string>
          name: <string>
          port: <integer>
          preconnection_blob: <string>
          preconnection_id: <integer>
          remote_port: <integer>
          security: <value in [rdp, nla, tls, ...]>
          server_layout: <value in [en-us-qwerty, de-de-qwertz, fr-fr-azerty, ...]>
          show_status_window: <value in [disable, enable]>
          sso: <value in [disable, static, auto]>
          sso_credential: <value in [sslvpn-login, alternative]>
          sso_credential_sent_once: <value in [disable, enable]>
          sso_password: <list or string>
          sso_username: <string>
          url: <string>
          domain: <string>
          color_depth: <value in [8, 16, 32]>
          height: <integer>
          keyboard_layout: <value in [ar, da, de, ...]>
          restricted_admin: <value in [disable, enable]>
          send_preconnection_id: <value in [disable, enable]>
          width: <integer>
          vnc_keyboard_layout: <value in [da, de, de-ch, ...]>
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
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks',
        '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}',
        '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}'
    ]

    url_params = ['adom', 'portal', 'bookmark-group']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'portal': {'required': True, 'type': 'str'},
        'bookmark-group': {'type': 'str', 'api_name': 'bookmark_group'},
        'bookmark_group': {'type': 'str'},
        'vpnsslweb_portal_bookmarkgroup_bookmarks': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'additional-params': {'type': 'str'},
                'apptype': {'choices': ['web', 'telnet', 'ssh', 'ftp', 'smb', 'vnc', 'rdp', 'citrix', 'rdpnative', 'portforward', 'sftp'], 'type': 'str'},
                'description': {'type': 'str'},
                'folder': {'type': 'str'},
                'form-data': {'type': 'list', 'options': {'name': {'type': 'str'}, 'value': {'type': 'str'}}, 'elements': 'dict'},
                'host': {'type': 'str'},
                'listening-port': {'type': 'int'},
                'load-balancing-info': {'type': 'str'},
                'logon-password': {'no_log': True, 'type': 'raw'},
                'logon-user': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'port': {'type': 'int'},
                'preconnection-blob': {'type': 'str'},
                'preconnection-id': {'type': 'int'},
                'remote-port': {'type': 'int'},
                'security': {'choices': ['rdp', 'nla', 'tls', 'any'], 'type': 'str'},
                'server-layout': {
                    'choices': [
                        'en-us-qwerty', 'de-de-qwertz', 'fr-fr-azerty', 'it-it-qwerty', 'sv-se-qwerty', 'failsafe', 'en-gb-qwerty', 'es-es-qwerty',
                        'fr-ch-qwertz', 'ja-jp-qwerty', 'pt-br-qwerty', 'tr-tr-qwerty', 'fr-ca-qwerty'
                    ],
                    'type': 'str'
                },
                'show-status-window': {'choices': ['disable', 'enable'], 'type': 'str'},
                'sso': {'choices': ['disable', 'static', 'auto'], 'type': 'str'},
                'sso-credential': {'choices': ['sslvpn-login', 'alternative'], 'type': 'str'},
                'sso-credential-sent-once': {'choices': ['disable', 'enable'], 'type': 'str'},
                'sso-password': {'no_log': True, 'type': 'raw'},
                'sso-username': {'type': 'str'},
                'url': {'type': 'str'},
                'domain': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'color-depth': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'choices': ['8', '16', '32'], 'type': 'str'},
                'height': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'keyboard-layout': {
                    'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']],
                    'choices': [
                        'ar', 'da', 'de', 'de-ch', 'en-gb', 'en-uk', 'en-us', 'es', 'fi', 'fr', 'fr-be', 'fr-ca', 'fr-ch', 'hr', 'hu', 'it', 'ja', 'lt',
                        'lv', 'mk', 'no', 'pl', 'pt', 'pt-br', 'ru', 'sl', 'sv', 'tk', 'tr', 'fr-ca-m', 'wg', 'ar-101', 'ar-102', 'ar-102-azerty',
                        'can-mul', 'cz', 'cz-qwerty', 'cz-pr', 'nl', 'de-ibm', 'en-uk-ext', 'en-us-dvorak', 'es-var', 'fi-sami', 'hu-101', 'it-142',
                        'ko', 'lt-ibm', 'lt-std', 'lav-std', 'lav-leg', 'mk-std', 'no-sami', 'pol-214', 'pol-pr', 'pt-br-abnt2', 'ru-mne', 'ru-t',
                        'sv-sami', 'tuk', 'tur-f', 'tur-q', 'zh-sym-sg-us', 'zh-sym-us', 'zh-tr-hk', 'zh-tr-mo', 'zh-tr-us', 'fr-apple', 'la-am',
                        'ja-106'
                    ],
                    'type': 'str'
                },
                'restricted-admin': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'send-preconnection-id': {'v_range': [['6.4.7', '6.4.14'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'width': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'vnc-keyboard-layout': {
                    'v_range': [['7.2.2', '']],
                    'choices': [
                        'da', 'de', 'de-ch', 'en-uk', 'es', 'fi', 'fr', 'fr-be', 'it', 'no', 'pt', 'sv', 'nl', 'en-uk-ext', 'it-142', 'pt-br-abnt2',
                        'default', 'fr-ca-mul', 'gd', 'us-intl'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_portal_bookmarkgroup_bookmarks'),
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
