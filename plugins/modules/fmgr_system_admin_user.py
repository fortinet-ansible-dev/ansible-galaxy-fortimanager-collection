#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2021 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_system_admin_user
short_description: Admin user.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    system_admin_user:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            adom:
                description: 'Adom.'
                type: list
                suboptions:
                    adom-name:
                        type: str
                        description: 'Admin domain names.'
            adom-exclude:
                description: 'Adom-Exclude.'
                type: list
                suboptions:
                    adom-name:
                        type: str
                        description: 'Admin domain names.'
            app-filter:
                description: 'App-Filter.'
                type: list
                suboptions:
                    app-filter-name:
                        type: str
                        description: 'App filter name.'
            avatar:
                type: str
                description: 'Image file for avatar (maximum 4K base64 encoded).'
            ca:
                type: str
                description: 'PKI user certificate CA (CA name in local).'
            change-password:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable restricted user to change self password.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            dashboard:
                description: 'Dashboard.'
                type: list
                suboptions:
                    column:
                        type: int
                        default: 0
                        description: 'Widgets column ID.'
                    diskio-content-type:
                        type: str
                        default: 'util'
                        description:
                         - 'Disk I/O Monitor widgets chart type.'
                         - 'util - bandwidth utilization.'
                         - 'iops - the number of I/O requests.'
                         - 'blks - the amount of data of I/O requests.'
                        choices:
                            - 'util'
                            - 'iops'
                            - 'blks'
                    diskio-period:
                        type: str
                        default: '1hour'
                        description:
                         - 'Disk I/O Monitor widgets data period.'
                         - '1hour - 1 hour.'
                         - '8hour - 8 hour.'
                         - '24hour - 24 hour.'
                        choices:
                            - '1hour'
                            - '8hour'
                            - '24hour'
                    log-rate-period:
                        type: str
                        description:
                         - 'Log receive monitor widgets data period.'
                         - '2min  - 2 minutes.'
                         - '1hour - 1 hour.'
                         - '6hours - 6 hours.'
                        choices:
                            - '2min '
                            - '1hour'
                            - '6hours'
                    log-rate-topn:
                        type: str
                        default: '5'
                        description:
                         - 'Log receive monitor widgets number of top items to display.'
                         - '1 - Top 1.'
                         - '2 - Top 2.'
                         - '3 - Top 3.'
                         - '4 - Top 4.'
                         - '5 - Top 5.'
                        choices:
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                    log-rate-type:
                        type: str
                        default: 'device'
                        description:
                         - 'Log receive monitor widgets statistics breakdown options.'
                         - 'log - Show log rates for each log type.'
                         - 'device - Show log rates for each device.'
                        choices:
                            - 'log'
                            - 'device'
                    moduleid:
                        type: int
                        default: 0
                        description: 'Widget ID.'
                    name:
                        type: str
                        description: 'Widget name.'
                    num-entries:
                        type: int
                        default: 10
                        description: 'Number of entries.'
                    refresh-interval:
                        type: int
                        default: 300
                        description: 'Widgets refresh interval.'
                    res-cpu-display:
                        type: str
                        default: 'average '
                        description:
                         - 'Widgets CPU display type.'
                         - 'average  - Average usage of CPU.'
                         - 'each - Each usage of CPU.'
                        choices:
                            - 'average '
                            - 'each'
                    res-period:
                        type: str
                        default: '10min '
                        description:
                         - 'Widgets data period.'
                         - '10min  - Last 10 minutes.'
                         - 'hour - Last hour.'
                         - 'day - Last day.'
                        choices:
                            - '10min '
                            - 'hour'
                            - 'day'
                    res-view-type:
                        type: str
                        default: 'history'
                        description:
                         - 'Widgets data view type.'
                         - 'real-time  - Real-time view.'
                         - 'history - History view.'
                        choices:
                            - 'real-time '
                            - 'history'
                    status:
                        type: str
                        default: 'open'
                        description:
                         - 'Widgets opened/closed state.'
                         - 'close - Widget closed.'
                         - 'open - Widget opened.'
                        choices:
                            - 'close'
                            - 'open'
                    tabid:
                        type: int
                        default: 0
                        description: 'ID of tab where widget is displayed.'
                    time-period:
                        type: str
                        default: '1hour'
                        description:
                         - 'Log Database Monitor widgets data period.'
                         - '1hour - 1 hour.'
                         - '8hour - 8 hour.'
                         - '24hour - 24 hour.'
                        choices:
                            - '1hour'
                            - '8hour'
                            - '24hour'
                    widget-type:
                        type: str
                        description:
                         - 'Widget type.'
                         - 'top-lograte - Log Receive Monitor.'
                         - 'sysres - System resources.'
                         - 'sysinfo - System Information.'
                         - 'licinfo - License Information.'
                         - 'jsconsole - CLI Console.'
                         - 'sysop - Unit Operation.'
                         - 'alert - Alert Message Console.'
                         - 'statistics - Statistics.'
                         - 'rpteng - Report Engine.'
                         - 'raid - Disk Monitor.'
                         - 'logrecv - Logs/Data Received.'
                         - 'devsummary - Device Summary.'
                         - 'logdb-perf - Log Database Performance Monitor.'
                         - 'logdb-lag - Log Database Lag Time.'
                         - 'disk-io - Disk I/O.'
                         - 'log-rcvd-fwd - Log receive and forwarding Monitor.'
                        choices:
                            - 'top-lograte'
                            - 'sysres'
                            - 'sysinfo'
                            - 'licinfo'
                            - 'jsconsole'
                            - 'sysop'
                            - 'alert'
                            - 'statistics'
                            - 'rpteng'
                            - 'raid'
                            - 'logrecv'
                            - 'devsummary'
                            - 'logdb-perf'
                            - 'logdb-lag'
                            - 'disk-io'
                            - 'log-rcvd-fwd'
            dashboard-tabs:
                description: 'Dashboard-Tabs.'
                type: list
                suboptions:
                    name:
                        type: str
                        description: 'Tab name.'
                    tabid:
                        type: int
                        default: 0
                        description: 'Tab ID.'
            description:
                type: str
                description: 'Description.'
            dev-group:
                type: str
                description: 'device group.'
            email-address:
                type: str
                description: 'Email address.'
            ext-auth-accprofile-override:
                type: str
                default: 'disable'
                description:
                 - 'Allow to use the access profile provided by the remote authentication server.'
                 - 'disable - Disable access profile override.'
                 - 'enable - Enable access profile override.'
                choices:
                    - 'disable'
                    - 'enable'
            ext-auth-adom-override:
                type: str
                default: 'disable'
                description:
                 - 'Allow to use the ADOM provided by the remote authentication server.'
                 - 'disable - Disable ADOM override.'
                 - 'enable - Enable ADOM override.'
                choices:
                    - 'disable'
                    - 'enable'
            ext-auth-group-match:
                type: str
                description: 'Only administrators belonging to this group can login.'
            first-name:
                type: str
                description: 'First name.'
            force-password-change:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable force password change on next login.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            group:
                type: str
                description: 'Group name.'
            hidden:
                type: int
                default: 0
                description: 'Hidden administrator.'
            ips-filter:
                description: 'Ips-Filter.'
                type: list
                suboptions:
                    ips-filter-name:
                        type: str
                        description: 'IPS filter name.'
            ipv6_trusthost1:
                type: str
                default: '::/0'
                description: 'Admin user trusted host IPv6, default ::/0 for all.'
            ipv6_trusthost10:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost2:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost3:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost4:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost5:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost6:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost7:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost8:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            ipv6_trusthost9:
                type: str
                default: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'
                description: 'Admin user trusted host IPv6, default ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 for none.'
            last-name:
                type: str
                description: 'Last name.'
            ldap-server:
                type: str
                description: 'LDAP server name.'
            meta-data:
                description: 'Meta-Data.'
                type: list
                suboptions:
                    fieldlength:
                        type: int
                        default: 0
                        description: 'Field length.'
                    fieldname:
                        type: str
                        description: 'Field name.'
                    fieldvalue:
                        type: str
                        description: 'Field value.'
                    importance:
                        type: str
                        default: 'optional'
                        description:
                         - 'Importance.'
                         - 'optional - This field is optional.'
                         - 'required - This field is required.'
                        choices:
                            - 'optional'
                            - 'required'
                    status:
                        type: str
                        default: 'enabled'
                        description:
                         - 'Status.'
                         - 'disabled - This field is disabled.'
                         - 'enabled - This field is enabled.'
                        choices:
                            - 'disabled'
                            - 'enabled'
            mobile-number:
                type: str
                description: 'Mobile number.'
            pager-number:
                type: str
                description: 'Pager number.'
            password:
                description: 'Password.'
                type: str
            password-expire:
                description: 'Password expire time in GMT.'
                type: str
            phone-number:
                type: str
                description: 'Phone number.'
            policy-package:
                description: 'Policy-Package.'
                type: list
                suboptions:
                    policy-package-name:
                        type: str
                        description: 'Policy package names.'
            profileid:
                type: str
                default: 'Restricted_User'
                description: 'Profile ID.'
            radius_server:
                type: str
                description: 'RADIUS server name.'
            restrict-access:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable restricted access to development VDOM.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            restrict-dev-vdom:
                description: no description
                type: list
                suboptions:
                    dev-vdom:
                        type: str
                        description: 'Device or device VDOM.'
            rpc-permit:
                type: str
                default: 'none'
                description:
                 - 'set none/read/read-write rpc-permission.'
                 - 'read-write - Read-write permission.'
                 - 'none - No permission.'
                 - 'read - Read-only permission.'
                choices:
                    - 'read-write'
                    - 'none'
                    - 'read'
            ssh-public-key1:
                description: 'SSH public key 1.'
                type: str
            ssh-public-key2:
                description: 'SSH public key 2.'
                type: str
            ssh-public-key3:
                description: 'SSH public key 3.'
                type: str
            subject:
                type: str
                description: 'PKI user certificate name constraints.'
            tacacs-plus-server:
                type: str
                description: 'TACACS+ server name.'
            trusthost1:
                type: str
                default: '0.0.0.0 0.0.0.0'
                description: 'Admin user trusted host IP, default 0.0.0.0 0.0.0.0 for all.'
            trusthost10:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost2:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost3:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost4:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost5:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost6:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost7:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost8:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            trusthost9:
                type: str
                default: '255.255.255.255 255.255.255.255'
                description: 'Admin user trusted host IP, default 255.255.255.255 255.255.255.255 for none.'
            two-factor-auth:
                type: str
                default: 'disable'
                description:
                 - 'Enable 2-factor authentication (certificate + password).'
                 - 'disable - Disable 2-factor authentication.'
                 - 'enable - Enable 2-factor authentication.'
                choices:
                    - 'disable'
                    - 'enable'
            user_type:
                type: str
                default: 'local'
                description:
                 - 'User type.'
                 - 'local - Local user.'
                 - 'radius - RADIUS user.'
                 - 'ldap - LDAP user.'
                 - 'tacacs-plus - TACACS+ user.'
                 - 'pki-auth - PKI user.'
                 - 'group - Group user.'
                choices:
                    - 'local'
                    - 'radius'
                    - 'ldap'
                    - 'tacacs-plus'
                    - 'pki-auth'
                    - 'group'
                    - 'sso'
            userid:
                type: str
                description: 'User name.'
            web-filter:
                description: 'Web-Filter.'
                type: list
                suboptions:
                    web-filter-name:
                        type: str
                        description: 'Web filter name.'
            wildcard:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable wildcard remote authentication.'
                 - 'disable - Disable username wildcard.'
                 - 'enable - Enable username wildcard.'
                choices:
                    - 'disable'
                    - 'enable'
            login-max:
                type: int
                default: 32
                description: 'Max login session for this user.'
            use-global-theme:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disble global theme for administration GUI.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            user-theme:
                type: str
                default: 'blue'
                description:
                 - 'Color scheme to use for the admin user GUI.'
                 - 'blue - Blueberry'
                 - 'green - Kiwi'
                 - 'red - Cherry'
                 - 'melongene - Plum'
                 - 'spring - Spring'
                 - 'summer - Summer'
                 - 'autumn - Autumn'
                 - 'winter - Winter'
                 - 'circuit-board - Circuit Board'
                 - 'calla-lily - Calla Lily'
                 - 'binary-tunnel - Binary Tunnel'
                 - 'mars - Mars'
                 - 'blue-sea - Blue Sea'
                 - 'technology - Technology'
                 - 'landscape - Landscape'
                 - 'twilight - Twilight'
                 - 'canyon - Canyon'
                 - 'northern-light - Northern Light'
                 - 'astronomy - Astronomy'
                 - 'fish - Fish'
                 - 'penguin - Penguin'
                 - 'mountain - Mountain'
                 - 'panda - Panda'
                 - 'parrot - Parrot'
                 - 'cave - Cave'
                 - 'zebra - Zebra'
                 - 'contrast-dark - High Contrast Dark'
                choices:
                    - 'blue'
                    - 'green'
                    - 'red'
                    - 'melongene'
                    - 'spring'
                    - 'summer'
                    - 'autumn'
                    - 'winter'
                    - 'circuit-board'
                    - 'calla-lily'
                    - 'binary-tunnel'
                    - 'mars'
                    - 'blue-sea'
                    - 'technology'
                    - 'landscape'
                    - 'twilight'
                    - 'canyon'
                    - 'northern-light'
                    - 'astronomy'
                    - 'fish'
                    - 'penguin'
                    - 'mountain'
                    - 'panda'
                    - 'parrot'
                    - 'cave'
                    - 'zebra'
                    - 'contrast-dark'

'''

EXAMPLES = '''
 - hosts: fortimanager00
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Admin User
      fmgr_system_admin_user:
         state: present
         system_admin_user:
             adom: 
              - adom-name: ansible
             userid: 'ansible-test'
    - name: Admin domain.
      fmgr_system_admin_user_adom:
         bypass_validation: False
         user: ansible-test # userid
         state: present
         system_admin_user_adom:
            adom-name: 'ALL ADOMS'

'''

RETURN = '''
request_url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
response_code:
    description: The status of api request
    returned: always
    type: int
    sample: 0
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/cli/global/system/admin/user'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/admin/user/{user}'
    ]

    url_params = []
    module_primary_key = 'userid'
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'system_admin_user': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True
            },
            'options': {
                'adom': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'adom-name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'adom-exclude': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'adom-name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'app-filter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'app-filter-name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'avatar': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ca': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'change-password': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dashboard': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'column': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'diskio-content-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'util',
                                'iops',
                                'blks'
                            ],
                            'type': 'str'
                        },
                        'diskio-period': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                '1hour',
                                '8hour',
                                '24hour'
                            ],
                            'type': 'str'
                        },
                        'log-rate-period': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                '2min ',
                                '1hour',
                                '6hours'
                            ],
                            'type': 'str'
                        },
                        'log-rate-topn': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                '1',
                                '2',
                                '3',
                                '4',
                                '5'
                            ],
                            'type': 'str'
                        },
                        'log-rate-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'log',
                                'device'
                            ],
                            'type': 'str'
                        },
                        'moduleid': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'num-entries': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'refresh-interval': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'res-cpu-display': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'average ',
                                'each'
                            ],
                            'type': 'str'
                        },
                        'res-period': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                '10min ',
                                'hour',
                                'day'
                            ],
                            'type': 'str'
                        },
                        'res-view-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'real-time ',
                                'history'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'close',
                                'open'
                            ],
                            'type': 'str'
                        },
                        'tabid': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'time-period': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                '1hour',
                                '8hour',
                                '24hour'
                            ],
                            'type': 'str'
                        },
                        'widget-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'top-lograte',
                                'sysres',
                                'sysinfo',
                                'licinfo',
                                'jsconsole',
                                'sysop',
                                'alert',
                                'statistics',
                                'rpteng',
                                'raid',
                                'logrecv',
                                'devsummary',
                                'logdb-perf',
                                'logdb-lag',
                                'disk-io',
                                'log-rcvd-fwd'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'dashboard-tabs': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'tabid': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'description': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'dev-group': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'email-address': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ext-auth-accprofile-override': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ext-auth-adom-override': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ext-auth-group-match': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'first-name': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'force-password-change': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'group': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'hidden': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'ips-filter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'ips-filter-name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'ipv6_trusthost1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost10': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost3': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost4': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost5': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost6': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost7': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost8': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ipv6_trusthost9': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'last-name': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ldap-server': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'meta-data': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'fieldlength': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'fieldname': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'fieldvalue': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'importance': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'optional',
                                'required'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disabled',
                                'enabled'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'mobile-number': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'pager-number': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'password': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'password-expire': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'phone-number': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'policy-package': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'policy-package-name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'profileid': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'radius_server': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'restrict-access': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': False,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'restrict-dev-vdom': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': False,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'options': {
                        'dev-vdom': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': False,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'str'
                        }
                    }
                },
                'rpc-permit': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'read-write',
                        'none',
                        'read'
                    ],
                    'type': 'str'
                },
                'ssh-public-key1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ssh-public-key2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'ssh-public-key3': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'subject': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'tacacs-plus-server': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'trusthost1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'trusthost10': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'trusthost2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'trusthost3': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'trusthost4': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'trusthost5': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'trusthost6': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'trusthost7': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'trusthost8': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'trusthost9': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'two-factor-auth': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'user_type': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'local',
                        'radius',
                        'ldap',
                        'tacacs-plus',
                        'pki-auth',
                        'group',
                        'sso'
                    ],
                    'type': 'str'
                },
                'userid': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'web-filter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'web-filter-name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'wildcard': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'login-max': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'use-global-theme': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'user-theme': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'blue',
                        'green',
                        'red',
                        'melongene',
                        'spring',
                        'summer',
                        'autumn',
                        'winter',
                        'circuit-board',
                        'calla-lily',
                        'binary-tunnel',
                        'mars',
                        'blue-sea',
                        'technology',
                        'landscape',
                        'twilight',
                        'canyon',
                        'northern-light',
                        'astronomy',
                        'fish',
                        'penguin',
                        'mountain',
                        'panda',
                        'parrot',
                        'cave',
                        'zebra',
                        'contrast-dark'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_user'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
