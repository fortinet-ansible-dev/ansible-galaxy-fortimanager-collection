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
module: fmgr_vpnsslweb_portal_bookmarkgroup
short_description: Portal bookmark group.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    portal:
        description: The parameter (portal) in requested url.
        type: str
        required: true
    vpnsslweb_portal_bookmarkgroup:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bookmarks:
                type: list
                elements: dict
                description: Bookmarks.
                suboptions:
                    additional_params:
                        aliases: ['additional-params']
                        type: str
                        description: Additional parameters.
                    apptype:
                        type: str
                        description: Application type.
                        choices: ['web', 'telnet', 'ssh', 'ftp', 'smb', 'vnc', 'rdp', 'citrix',
                                  'rdpnative', 'portforward', 'sftp']
                    description:
                        type: str
                        description: Description.
                    folder:
                        type: str
                        description: Network shared file folder parameter.
                    form_data:
                        aliases: ['form-data']
                        type: list
                        elements: dict
                        description: Form data.
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
                    listening_port:
                        aliases: ['listening-port']
                        type: int
                        description: Listening port
                    load_balancing_info:
                        aliases: ['load-balancing-info']
                        type: str
                        description: The load balancing information or cookie which should be provided to the connection broker.
                    logon_password:
                        aliases: ['logon-password']
                        type: raw
                        description: (list) Logon password.
                    logon_user:
                        aliases: ['logon-user']
                        type: str
                        description: Logon user.
                    name:
                        type: str
                        description: Bookmark name.
                    port:
                        type: int
                        description: Remote port.
                    preconnection_blob:
                        aliases: ['preconnection-blob']
                        type: str
                        description: An arbitrary string which identifies the RDP source.
                    preconnection_id:
                        aliases: ['preconnection-id']
                        type: int
                        description: The numeric ID of the RDP source
                    remote_port:
                        aliases: ['remote-port']
                        type: int
                        description: Remote port
                    security:
                        type: str
                        description: Security mode for RDP connection.
                        choices: ['rdp', 'nla', 'tls', 'any']
                    server_layout:
                        aliases: ['server-layout']
                        type: str
                        description: Server side keyboard layout.
                        choices: ['en-us-qwerty', 'de-de-qwertz', 'fr-fr-azerty', 'it-it-qwerty',
                                  'sv-se-qwerty', 'failsafe', 'en-gb-qwerty', 'es-es-qwerty',
                                  'fr-ch-qwertz', 'ja-jp-qwerty', 'pt-br-qwerty', 'tr-tr-qwerty',
                                  'fr-ca-qwerty']
                    show_status_window:
                        aliases: ['show-status-window']
                        type: str
                        description: Enable/disable showing of status window.
                        choices: ['disable', 'enable']
                    sso:
                        type: str
                        description: Single Sign-On.
                        choices: ['disable', 'static', 'auto']
                    sso_credential:
                        aliases: ['sso-credential']
                        type: str
                        description: Single sign-on credentials.
                        choices: ['sslvpn-login', 'alternative']
                    sso_credential_sent_once:
                        aliases: ['sso-credential-sent-once']
                        type: str
                        description: Single sign-on credentials are only sent once to remote server.
                        choices: ['disable', 'enable']
                    sso_password:
                        aliases: ['sso-password']
                        type: raw
                        description: (list) SSO password.
                    sso_username:
                        aliases: ['sso-username']
                        type: str
                        description: SSO user name.
                    url:
                        type: str
                        description: URL parameter.
                    domain:
                        type: str
                        description: Login domain.
                    color_depth:
                        aliases: ['color-depth']
                        type: str
                        description: Color depth per pixel.
                        choices: ['8', '16', '32']
                    height:
                        type: int
                        description: Screen height
                    keyboard_layout:
                        aliases: ['keyboard-layout']
                        type: str
                        description: Keyboard layout.
                        choices: ['ar', 'da', 'de', 'de-ch', 'en-gb', 'en-uk', 'en-us', 'es',
                                  'fi', 'fr', 'fr-be', 'fr-ca', 'fr-ch', 'hr', 'hu', 'it', 'ja',
                                  'lt', 'lv', 'mk', 'no', 'pl', 'pt', 'pt-br', 'ru', 'sl', 'sv',
                                  'tk', 'tr', 'fr-ca-m', 'wg', 'ar-101', 'ar-102',
                                  'ar-102-azerty', 'can-mul', 'cz', 'cz-qwerty', 'cz-pr', 'nl',
                                  'de-ibm', 'en-uk-ext', 'en-us-dvorak', 'es-var', 'fi-sami',
                                  'hu-101', 'it-142', 'ko', 'lt-ibm', 'lt-std', 'lav-std',
                                  'lav-leg', 'mk-std', 'no-sami', 'pol-214', 'pol-pr',
                                  'pt-br-abnt2', 'ru-mne', 'ru-t', 'sv-sami', 'tuk', 'tur-f',
                                  'tur-q', 'zh-sym-sg-us', 'zh-sym-us', 'zh-tr-hk', 'zh-tr-mo',
                                  'zh-tr-us', 'fr-apple', 'la-am', 'ja-106']
                    restricted_admin:
                        aliases: ['restricted-admin']
                        type: str
                        description: Enable/disable restricted admin mode for RDP.
                        choices: ['disable', 'enable']
                    send_preconnection_id:
                        aliases: ['send-preconnection-id']
                        type: str
                        description: Enable/disable sending of preconnection ID.
                        choices: ['disable', 'enable']
                    width:
                        type: int
                        description: Screen width
                    vnc_keyboard_layout:
                        aliases: ['vnc-keyboard-layout']
                        type: str
                        description: Keyboard layout.
                        choices: ['da', 'de', 'de-ch', 'en-uk', 'es', 'fi', 'fr', 'fr-be', 'it',
                                  'no', 'pt', 'sv', 'nl', 'en-uk-ext', 'it-142', 'pt-br-abnt2',
                                  'default', 'fr-ca-mul', 'gd', 'us-intl']
            name:
                type: str
                description: Bookmark group name.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Portal bookmark group.
      fortinet.fortimanager.fmgr_vpnsslweb_portal_bookmarkgroup:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        portal: <your own value>
        state: present # <value in [present, absent]>
        vpnsslweb_portal_bookmarkgroup:
          name: "your value" # Required variable, string
          # bookmarks:
          #   - additional_params: <string>
          #     apptype: <value in [web, telnet, ssh, ...]>
          #     description: <string>
          #     folder: <string>
          #     form_data:
          #       - name: <string>
          #         value: <string>
          #     host: <string>
          #     listening_port: <integer>
          #     load_balancing_info: <string>
          #     logon_password: <list or string>
          #     logon_user: <string>
          #     name: <string>
          #     port: <integer>
          #     preconnection_blob: <string>
          #     preconnection_id: <integer>
          #     remote_port: <integer>
          #     security: <value in [rdp, nla, tls, ...]>
          #     server_layout: <value in [en-us-qwerty, de-de-qwertz, fr-fr-azerty, ...]>
          #     show_status_window: <value in [disable, enable]>
          #     sso: <value in [disable, static, auto]>
          #     sso_credential: <value in [sslvpn-login, alternative]>
          #     sso_credential_sent_once: <value in [disable, enable]>
          #     sso_password: <list or string>
          #     sso_username: <string>
          #     url: <string>
          #     domain: <string>
          #     color_depth: <value in [8, 16, 32]>
          #     height: <integer>
          #     keyboard_layout: <value in [ar, da, de, ...]>
          #     restricted_admin: <value in [disable, enable]>
          #     send_preconnection_id: <value in [disable, enable]>
          #     width: <integer>
          #     vnc_keyboard_layout: <value in [da, de, de-ch, ...]>
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
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group',
        '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'portal': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vpnsslweb_portal_bookmarkgroup': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'bookmarks': {
                    'type': 'list',
                    'options': {
                        'additional-params': {'type': 'str'},
                        'apptype': {
                            'choices': ['web', 'telnet', 'ssh', 'ftp', 'smb', 'vnc', 'rdp', 'citrix', 'rdpnative', 'portforward', 'sftp'],
                            'type': 'str'
                        },
                        'description': {'type': 'str'},
                        'folder': {'type': 'str'},
                        'form-data': {'type': 'list', 'options': {'name': {'type': 'str'}, 'value': {'type': 'str'}}, 'elements': 'dict'},
                        'host': {'type': 'str'},
                        'listening-port': {'type': 'int'},
                        'load-balancing-info': {'type': 'str'},
                        'logon-password': {'no_log': True, 'type': 'raw'},
                        'logon-user': {'type': 'str'},
                        'name': {'type': 'str'},
                        'port': {'type': 'int'},
                        'preconnection-blob': {'type': 'str'},
                        'preconnection-id': {'type': 'int'},
                        'remote-port': {'type': 'int'},
                        'security': {'choices': ['rdp', 'nla', 'tls', 'any'], 'type': 'str'},
                        'server-layout': {
                            'choices': [
                                'en-us-qwerty', 'de-de-qwertz', 'fr-fr-azerty', 'it-it-qwerty', 'sv-se-qwerty', 'failsafe', 'en-gb-qwerty',
                                'es-es-qwerty', 'fr-ch-qwertz', 'ja-jp-qwerty', 'pt-br-qwerty', 'tr-tr-qwerty', 'fr-ca-qwerty'
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
                        'color-depth': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['8', '16', '32'], 'type': 'str'},
                        'height': {'v_range': [['7.0.3', '']], 'type': 'int'},
                        'keyboard-layout': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'choices': [
                                'ar', 'da', 'de', 'de-ch', 'en-gb', 'en-uk', 'en-us', 'es', 'fi', 'fr', 'fr-be', 'fr-ca', 'fr-ch', 'hr', 'hu', 'it',
                                'ja', 'lt', 'lv', 'mk', 'no', 'pl', 'pt', 'pt-br', 'ru', 'sl', 'sv', 'tk', 'tr', 'fr-ca-m', 'wg', 'ar-101', 'ar-102',
                                'ar-102-azerty', 'can-mul', 'cz', 'cz-qwerty', 'cz-pr', 'nl', 'de-ibm', 'en-uk-ext', 'en-us-dvorak', 'es-var', 'fi-sami',
                                'hu-101', 'it-142', 'ko', 'lt-ibm', 'lt-std', 'lav-std', 'lav-leg', 'mk-std', 'no-sami', 'pol-214', 'pol-pr',
                                'pt-br-abnt2', 'ru-mne', 'ru-t', 'sv-sami', 'tuk', 'tur-f', 'tur-q', 'zh-sym-sg-us', 'zh-sym-us', 'zh-tr-hk', 'zh-tr-mo',
                                'zh-tr-us', 'fr-apple', 'la-am', 'ja-106'
                            ],
                            'type': 'str'
                        },
                        'restricted-admin': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'send-preconnection-id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'width': {'v_range': [['7.0.3', '']], 'type': 'int'},
                        'vnc-keyboard-layout': {
                            'v_range': [['7.2.2', '']],
                            'choices': [
                                'da', 'de', 'de-ch', 'en-uk', 'es', 'fi', 'fr', 'fr-be', 'it', 'no', 'pt', 'sv', 'nl', 'en-uk-ext', 'it-142',
                                'pt-br-abnt2', 'default', 'fr-ca-mul', 'gd', 'us-intl'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'name': {'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_portal_bookmarkgroup'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
