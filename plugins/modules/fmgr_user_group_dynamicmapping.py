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
                description: No description.
                suboptions:
                    name:
                        type: str
                        description: No description.
                    vdom:
                        type: str
                        description: No description.
            auth-concurrent-override:
                type: str
                description: Deprecated, please rename it to auth_concurrent_override. Enable/disable overriding the global number of concurrent authen...
                choices:
                    - 'disable'
                    - 'enable'
            auth-concurrent-value:
                type: int
                description: Deprecated, please rename it to auth_concurrent_value. Maximum number of concurrent authenticated connections per user
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
            expire-type:
                type: str
                description: Deprecated, please rename it to expire_type. Determine when the expiration countdown begins.
                choices:
                    - 'immediately'
                    - 'first-successful-login'
            group-type:
                type: str
                description: Deprecated, please rename it to group_type. Set the group to be for firewall authentication, FSSO, RSSO, or guest users.
                choices:
                    - 'firewall'
                    - 'directory-service'
                    - 'fsso-service'
                    - 'guest'
                    - 'rsso'
            guest:
                type: list
                elements: dict
                description: No description.
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
                        description: No description.
                    id:
                        type: int
                        description: Guest ID.
                    mobile-phone:
                        type: str
                        description: Deprecated, please rename it to mobile_phone. Mobile phone.
                    name:
                        type: str
                        description: Guest name.
                    password:
                        type: raw
                        description: (list) No description.
                    sponsor:
                        type: str
                        description: Set the action for the sponsor guest user field.
                    user-id:
                        type: str
                        description: Deprecated, please rename it to user_id. Guest ID.
            http-digest-realm:
                type: str
                description: Deprecated, please rename it to http_digest_realm. Realm attribute for MD5-digest authentication.
            id:
                type: int
                description: Group ID.
                required: true
            ldap-memberof:
                type: str
                description: Deprecated, please rename it to ldap_memberof.
            logic-type:
                type: str
                description: Deprecated, please rename it to logic_type.
                choices:
                    - 'or'
                    - 'and'
            match:
                type: list
                elements: dict
                description: No description.
                suboptions:
                    _gui_meta:
                        type: str
                        description: No description.
                    group-name:
                        type: str
                        description: Deprecated, please rename it to group_name. Name of matching user or group on remote authentication server.
                    id:
                        type: int
                        description: ID.
                    server-name:
                        type: str
                        description: Deprecated, please rename it to server_name. Name of remote auth server.
            max-accounts:
                type: int
                description: Deprecated, please rename it to max_accounts. Maximum number of guest accounts that can be created for this group
            member:
                type: raw
                description: (list or str) No description.
            mobile-phone:
                type: str
                description: Deprecated, please rename it to mobile_phone. Enable/disable the guest user mobile phone number field.
                choices:
                    - 'disable'
                    - 'enable'
            multiple-guest-add:
                type: str
                description: Deprecated, please rename it to multiple_guest_add. Enable/disable addition of multiple guests.
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
            redir-url:
                type: str
                description: Deprecated, please rename it to redir_url.
            sms-custom-server:
                type: str
                description: Deprecated, please rename it to sms_custom_server. SMS server.
            sms-server:
                type: str
                description: Deprecated, please rename it to sms_server. Send SMS through FortiGuard or other external server.
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
            sslvpn-bookmarks-group:
                type: raw
                description: (list or str) Deprecated, please rename it to sslvpn_bookmarks_group.
            sslvpn-cache-cleaner:
                type: str
                description: Deprecated, please rename it to sslvpn_cache_cleaner.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-client-check:
                type: list
                elements: str
                description: Deprecated, please rename it to sslvpn_client_check.
                choices:
                    - 'forticlient'
                    - 'forticlient-av'
                    - 'forticlient-fw'
                    - '3rdAV'
                    - '3rdFW'
            sslvpn-ftp:
                type: str
                description: Deprecated, please rename it to sslvpn_ftp.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-http:
                type: str
                description: Deprecated, please rename it to sslvpn_http.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-os-check:
                type: str
                description: Deprecated, please rename it to sslvpn_os_check.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-os-check-list:
                type: dict
                description: Deprecated, please rename it to sslvpn_os_check_list.
                suboptions:
                    action:
                        type: str
                        description: No description.
                        choices:
                            - 'allow'
                            - 'check-up-to-date'
                            - 'deny'
                    latest-patch-level:
                        type: str
                        description: Deprecated, please rename it to latest_patch_level.
                    name:
                        type: str
                        description: No description.
                    tolerance:
                        type: int
                        description: No description.
            sslvpn-portal:
                type: raw
                description: (list or str) Deprecated, please rename it to sslvpn_portal.
            sslvpn-portal-heading:
                type: str
                description: Deprecated, please rename it to sslvpn_portal_heading.
            sslvpn-rdp:
                type: str
                description: Deprecated, please rename it to sslvpn_rdp.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-samba:
                type: str
                description: Deprecated, please rename it to sslvpn_samba.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-split-tunneling:
                type: str
                description: Deprecated, please rename it to sslvpn_split_tunneling.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-ssh:
                type: str
                description: Deprecated, please rename it to sslvpn_ssh.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-telnet:
                type: str
                description: Deprecated, please rename it to sslvpn_telnet.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-tunnel:
                type: str
                description: Deprecated, please rename it to sslvpn_tunnel.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-tunnel-endip:
                type: str
                description: Deprecated, please rename it to sslvpn_tunnel_endip.
            sslvpn-tunnel-ip-mode:
                type: str
                description: Deprecated, please rename it to sslvpn_tunnel_ip_mode.
                choices:
                    - 'range'
                    - 'usrgrp'
            sslvpn-tunnel-startip:
                type: str
                description: Deprecated, please rename it to sslvpn_tunnel_startip.
            sslvpn-virtual-desktop:
                type: str
                description: Deprecated, please rename it to sslvpn_virtual_desktop.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-vnc:
                type: str
                description: Deprecated, please rename it to sslvpn_vnc.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-webapp:
                type: str
                description: Deprecated, please rename it to sslvpn_webapp.
                choices:
                    - 'disable'
                    - 'enable'
            sso-attribute-value:
                type: str
                description: Deprecated, please rename it to sso_attribute_value. Name of the RADIUS user group that this local user group represents.
            user-id:
                type: str
                description: Deprecated, please rename it to user_id. Guest user ID type.
                choices:
                    - 'email'
                    - 'auto-generate'
                    - 'specify'
            user-name:
                type: str
                description: Deprecated, please rename it to user_name. Enable/disable the guest user name entry.
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
            - forticlient
            - forticlient-av
            - forticlient-fw
            - 3rdAV
            - 3rdFW
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping',
        '/pm/config/global/obj/user/group/{group}/dynamic_mapping'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}',
        '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}'
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
