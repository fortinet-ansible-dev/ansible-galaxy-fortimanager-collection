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
module: fmgr_user_group_dynamicmapping
short_description: Configure user groups.
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
    group:
        description: The parameter (group) in requested url.
        type: str
        required: true
    user_group_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _scope:
                type: list
                elements: dict
                description: Scope.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    vdom:
                        type: str
                        description: Vdom.
            auth_concurrent_override:
                type: str
                description: Enable/disable overriding the global number of concurrent authentication sessions for this user group.
                choices:
                    - 'disable'
                    - 'enable'
            auth_concurrent_value:
                type: int
                description: Maximum number of concurrent authenticated connections per user
            authtimeout:
                type: int
                description: Authentication timeout in minutes for this user group.
            company:
                type: str
                description: Set the action for the company guest user field.
                choices:
                    - 'optional'
                    - 'mandatory'
                    - 'disabled'
            email:
                type: str
                description: Enable/disable the guest user email address field.
                choices:
                    - 'disable'
                    - 'enable'
            expire:
                type: int
                description: Time in seconds before guest user accounts expire
            expire_type:
                type: str
                description: Determine when the expiration countdown begins.
                choices:
                    - 'immediately'
                    - 'first-successful-login'
            group_type:
                type: str
                description: Set the group to be for firewall authentication, FSSO, RSSO, or guest users.
                choices:
                    - 'firewall'
                    - 'directory-service'
                    - 'fsso-service'
                    - 'guest'
                    - 'rsso'
            guest:
                type: list
                elements: dict
                description: Guest.
                suboptions:
                    comment:
                        type: str
                        description: Comment.
                    company:
                        type: str
                        description: Set the action for the company guest user field.
                    email:
                        type: str
                        description: Email.
                    expiration:
                        type: str
                        description: Expire time.
                    group:
                        type: str
                        description: Group.
                    id:
                        type: int
                        description: Guest ID.
                    mobile_phone:
                        type: str
                        description: Mobile phone.
                    name:
                        type: str
                        description: Guest name.
                    password:
                        type: raw
                        description: (list) Guest password.
                    sponsor:
                        type: str
                        description: Set the action for the sponsor guest user field.
                    user_id:
                        type: str
                        description: Guest ID.
            http_digest_realm:
                type: str
                description: Realm attribute for MD5-digest authentication.
            id:
                type: int
                description: Group ID.
                required: true
            ldap_memberof:
                type: str
                description: Ldap memberof.
            logic_type:
                type: str
                description: Logic type.
                choices:
                    - 'or'
                    - 'and'
            match:
                type: list
                elements: dict
                description: Match.
                suboptions:
                    _gui_meta:
                        type: str
                        description: Gui meta.
                    group_name:
                        type: str
                        description: Name of matching user or group on remote authentication server.
                    id:
                        type: int
                        description: ID.
                    server_name:
                        type: str
                        description: Name of remote auth server.
            max_accounts:
                type: int
                description: Maximum number of guest accounts that can be created for this group
            member:
                type: raw
                description: (list or str) Names of users, peers, LDAP severs, or RADIUS servers to add to the user group.
            mobile_phone:
                type: str
                description: Enable/disable the guest user mobile phone number field.
                choices:
                    - 'disable'
                    - 'enable'
            multiple_guest_add:
                type: str
                description: Enable/disable addition of multiple guests.
                choices:
                    - 'disable'
                    - 'enable'
            password:
                type: str
                description: Guest user password type.
                choices:
                    - 'auto-generate'
                    - 'specify'
                    - 'disable'
            redir_url:
                type: str
                description: Redir url.
            sms_custom_server:
                type: str
                description: SMS server.
            sms_server:
                type: str
                description: Send SMS through FortiGuard or other external server.
                choices:
                    - 'fortiguard'
                    - 'custom'
            sponsor:
                type: str
                description: Set the action for the sponsor guest user field.
                choices:
                    - 'optional'
                    - 'mandatory'
                    - 'disabled'
            sslvpn_bookmarks_group:
                type: raw
                description: (list or str) Sslvpn bookmarks group.
            sslvpn_cache_cleaner:
                type: str
                description: Sslvpn cache cleaner.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_client_check:
                type: list
                elements: str
                description: Sslvpn client check.
                choices:
                    - 'forticlient'
                    - 'forticlient-av'
                    - 'forticlient-fw'
                    - '3rdAV'
                    - '3rdFW'
            sslvpn_ftp:
                type: str
                description: Sslvpn ftp.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_http:
                type: str
                description: Sslvpn http.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_os_check:
                type: str
                description: Sslvpn os check.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_os_check_list:
                type: dict
                description: Sslvpn os check list.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'check-up-to-date'
                            - 'deny'
                    latest_patch_level:
                        type: str
                        description: Latest patch level.
                    name:
                        type: str
                        description: Name.
                    tolerance:
                        type: int
                        description: Tolerance.
            sslvpn_portal:
                type: raw
                description: (list or str) Sslvpn portal.
            sslvpn_portal_heading:
                type: str
                description: Sslvpn portal heading.
            sslvpn_rdp:
                type: str
                description: Sslvpn rdp.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_samba:
                type: str
                description: Sslvpn samba.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_split_tunneling:
                type: str
                description: Sslvpn split tunneling.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_ssh:
                type: str
                description: Sslvpn ssh.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_telnet:
                type: str
                description: Sslvpn telnet.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_tunnel:
                type: str
                description: Sslvpn tunnel.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_tunnel_endip:
                type: str
                description: Sslvpn tunnel endip.
            sslvpn_tunnel_ip_mode:
                type: str
                description: Sslvpn tunnel ip mode.
                choices:
                    - 'range'
                    - 'usrgrp'
            sslvpn_tunnel_startip:
                type: str
                description: Sslvpn tunnel startip.
            sslvpn_virtual_desktop:
                type: str
                description: Sslvpn virtual desktop.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_vnc:
                type: str
                description: Sslvpn vnc.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_webapp:
                type: str
                description: Sslvpn webapp.
                choices:
                    - 'disable'
                    - 'enable'
            sso_attribute_value:
                type: str
                description: Name of the RADIUS user group that this local user group represents.
            user_id:
                type: str
                description: Guest user ID type.
                choices:
                    - 'email'
                    - 'auto-generate'
                    - 'specify'
            user_name:
                type: str
                description: Enable/disable the guest user name entry.
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
    - name: Configure user groups.
      fortinet.fortimanager.fmgr_user_group_dynamicmapping:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        group: <your own value>
        state: present # <value in [present, absent]>
        user_group_dynamicmapping:
          _scope:
            -
              name: <string>
              vdom: <string>
          auth_concurrent_override: <value in [disable, enable]>
          auth_concurrent_value: <integer>
          authtimeout: <integer>
          company: <value in [optional, mandatory, disabled]>
          email: <value in [disable, enable]>
          expire: <integer>
          expire_type: <value in [immediately, first-successful-login]>
          group_type: <value in [firewall, directory-service, fsso-service, ...]>
          guest:
            -
              comment: <string>
              company: <string>
              email: <string>
              expiration: <string>
              group: <string>
              id: <integer>
              mobile_phone: <string>
              name: <string>
              password: <list or string>
              sponsor: <string>
              user_id: <string>
          http_digest_realm: <string>
          id: <integer>
          ldap_memberof: <string>
          logic_type: <value in [or, and]>
          match:
            -
              _gui_meta: <string>
              group_name: <string>
              id: <integer>
              server_name: <string>
          max_accounts: <integer>
          member: <list or string>
          mobile_phone: <value in [disable, enable]>
          multiple_guest_add: <value in [disable, enable]>
          password: <value in [auto-generate, specify, disable]>
          redir_url: <string>
          sms_custom_server: <string>
          sms_server: <value in [fortiguard, custom]>
          sponsor: <value in [optional, mandatory, disabled]>
          sslvpn_bookmarks_group: <list or string>
          sslvpn_cache_cleaner: <value in [disable, enable]>
          sslvpn_client_check:
            - "forticlient"
            - "forticlient-av"
            - "forticlient-fw"
            - "3rdAV"
            - "3rdFW"
          sslvpn_ftp: <value in [disable, enable]>
          sslvpn_http: <value in [disable, enable]>
          sslvpn_os_check: <value in [disable, enable]>
          sslvpn_os_check_list:
            action: <value in [allow, check-up-to-date, deny]>
            latest_patch_level: <string>
            name: <string>
            tolerance: <integer>
          sslvpn_portal: <list or string>
          sslvpn_portal_heading: <string>
          sslvpn_rdp: <value in [disable, enable]>
          sslvpn_samba: <value in [disable, enable]>
          sslvpn_split_tunneling: <value in [disable, enable]>
          sslvpn_ssh: <value in [disable, enable]>
          sslvpn_telnet: <value in [disable, enable]>
          sslvpn_tunnel: <value in [disable, enable]>
          sslvpn_tunnel_endip: <string>
          sslvpn_tunnel_ip_mode: <value in [range, usrgrp]>
          sslvpn_tunnel_startip: <string>
          sslvpn_virtual_desktop: <value in [disable, enable]>
          sslvpn_vnc: <value in [disable, enable]>
          sslvpn_webapp: <value in [disable, enable]>
          sso_attribute_value: <string>
          user_id: <value in [email, auto-generate, specify]>
          user_name: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping',
        '/pm/config/global/obj/user/group/{group}/dynamic_mapping'
    ]
    url_params = ['adom', 'group']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'group': {'required': True, 'type': 'str'},
        'user_group_dynamicmapping': {
            'type': 'dict',
            'v_range': [['7.0.2', '']],
            'options': {
                '_scope': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['7.0.2', '']], 'type': 'str'}, 'vdom': {'v_range': [['7.0.2', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'auth-concurrent-override': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-concurrent-value': {'v_range': [['7.0.2', '']], 'type': 'int'},
                'authtimeout': {'v_range': [['7.0.2', '']], 'type': 'int'},
                'company': {'v_range': [['7.0.2', '']], 'choices': ['optional', 'mandatory', 'disabled'], 'type': 'str'},
                'email': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'expire': {'v_range': [['7.0.2', '']], 'type': 'int'},
                'expire-type': {'v_range': [['7.0.2', '']], 'choices': ['immediately', 'first-successful-login'], 'type': 'str'},
                'group-type': {'v_range': [['7.0.2', '']], 'choices': ['firewall', 'directory-service', 'fsso-service', 'guest', 'rsso'], 'type': 'str'},
                'guest': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'options': {
                        'comment': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'company': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'email': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'expiration': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'group': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'id': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'mobile-phone': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'name': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'password': {'v_range': [['7.0.2', '']], 'no_log': True, 'type': 'raw'},
                        'sponsor': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'user-id': {'v_range': [['7.0.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'http-digest-realm': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'id': {'v_range': [['7.0.2', '']], 'required': True, 'type': 'int'},
                'ldap-memberof': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'logic-type': {'v_range': [['7.0.3', '']], 'choices': ['or', 'and'], 'type': 'str'},
                'match': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'options': {
                        '_gui_meta': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'group-name': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'id': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'server-name': {'v_range': [['7.0.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'max-accounts': {'v_range': [['7.0.2', '']], 'type': 'int'},
                'member': {'v_range': [['7.0.2', '']], 'type': 'raw'},
                'mobile-phone': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'multiple-guest-add': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'password': {'v_range': [['7.0.2', '']], 'choices': ['auto-generate', 'specify', 'disable'], 'no_log': True, 'type': 'str'},
                'redir-url': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'sms-custom-server': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'sms-server': {'v_range': [['7.0.2', '']], 'choices': ['fortiguard', 'custom'], 'type': 'str'},
                'sponsor': {'v_range': [['7.0.2', '']], 'choices': ['optional', 'mandatory', 'disabled'], 'type': 'str'},
                'sslvpn-bookmarks-group': {'v_range': [['7.0.2', '']], 'type': 'raw'},
                'sslvpn-cache-cleaner': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-client-check': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'choices': ['forticlient', 'forticlient-av', 'forticlient-fw', '3rdAV', '3rdFW'],
                    'elements': 'str'
                },
                'sslvpn-ftp': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-http': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-os-check': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-os-check-list': {
                    'v_range': [['7.0.2', '']],
                    'type': 'dict',
                    'options': {
                        'action': {'v_range': [['7.0.2', '']], 'choices': ['allow', 'check-up-to-date', 'deny'], 'type': 'str'},
                        'latest-patch-level': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'name': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'tolerance': {'v_range': [['7.0.2', '']], 'type': 'int'}
                    }
                },
                'sslvpn-portal': {'v_range': [['7.0.2', '']], 'type': 'raw'},
                'sslvpn-portal-heading': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'sslvpn-rdp': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-samba': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-split-tunneling': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-ssh': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-telnet': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-tunnel': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-tunnel-endip': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'sslvpn-tunnel-ip-mode': {'v_range': [['7.0.2', '']], 'choices': ['range', 'usrgrp'], 'type': 'str'},
                'sslvpn-tunnel-startip': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'sslvpn-virtual-desktop': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-vnc': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-webapp': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sso-attribute-value': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'user-id': {'v_range': [['7.0.2', '']], 'choices': ['email', 'auto-generate', 'specify'], 'type': 'str'},
                'user-name': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_group_dynamicmapping'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
