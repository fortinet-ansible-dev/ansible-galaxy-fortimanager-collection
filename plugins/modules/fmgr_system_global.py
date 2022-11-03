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
module: fmgr_system_global
short_description: no description
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
        description: |
          only set to True when module schema diffs with FortiManager API structure,
           module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: |
          the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
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
    system_global:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            admin-lockout-duration:
                type: int
                default: 60
                description: no description
            admin-lockout-threshold:
                type: int
                default: 3
                description: no description
            adom-mode:
                type: str
                default: 'normal'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'normal'
                    - 'advanced'
            adom-rev-auto-delete:
                type: str
                default: 'by-revisions'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'by-revisions'
                    - 'by-days'
            adom-rev-max-backup-revisions:
                type: int
                default: 5
                description: no description
            adom-rev-max-days:
                type: int
                default: 30
                description: no description
            adom-rev-max-revisions:
                type: int
                default: 120
                description: no description
            adom-select:
                type: str
                default: 'enable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            adom-status:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            clt-cert-req:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
                    - 'optional'
            console-output:
                type: str
                default: 'standard'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'standard'
                    - 'more'
            country-flag:
                type: str
                default: 'enable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            create-revision:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            daylightsavetime:
                type: str
                default: 'enable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            default-disk-quota:
                type: int
                default: 1000
                description: no description
            detect-unregistered-log-device:
                type: str
                default: 'enable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            device-view-mode:
                type: str
                default: 'regular'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'regular'
                    - 'tree'
            dh-params:
                type: str
                default: '2048'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
                    - '6144'
                    - '8192'
            disable-module:
                description: no description
                type: list
                choices:
                 - fortiview-noc
                 - none
                 - fortirecorder
                 - siem
                 - soc
                 - ai
            enc-algorithm:
                type: str
                default: 'high'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'custom'
            faz-status:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            fgfm-local-cert:
                type: str
                description: no description
            fgfm-ssl-protocol:
                type: str
                default: 'tlsv1.'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - 'sslv3'
                    - 'tlsv1.0'
                    - 'tlsv1.1'
                    - 'tlsv1.2'
                    - 'tlsv1.3'
            ha-member-auto-grouping:
                type: str
                default: 'enable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            hitcount_concurrent:
                type: int
                default: 100
                description: no description
            hitcount_interval:
                type: int
                default: 300
                description: no description
            hostname:
                type: str
                default: 'FMG-VM64'
                description: no description
            import-ignore-addr-cmt:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            language:
                type: str
                default: 'english'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - 'english'
                    - 'simch'
                    - 'japanese'
                    - 'korean'
                    - 'spanish'
                    - 'trach'
            latitude:
                type: str
                description: no description
            ldap-cache-timeout:
                type: int
                default: 86400
                description: no description
            ldapconntimeout:
                type: int
                default: 60000
                description: no description
            lock-preempt:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            log-checksum:
                type: str
                default: 'none'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - 'none'
                    - 'md5'
                    - 'md5-auth'
            log-forward-cache-size:
                type: int
                default: 0
                description: no description
            longitude:
                type: str
                description: no description
            max-log-forward:
                type: int
                default: 5
                description: no description
            max-running-reports:
                type: int
                default: 1
                description: no description
            oftp-ssl-protocol:
                type: str
                default: 'tlsv1.'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - 'sslv3'
                    - 'tlsv1.0'
                    - 'tlsv1.1'
                    - 'tlsv1.2'
                    - 'tlsv1.3'
            partial-install:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            partial-install-force:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            partial-install-rev:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            perform-improve-by-ha:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            policy-hit-count:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            policy-object-in-dual-pane:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            pre-login-banner:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            pre-login-banner-message:
                type: str
                description: no description
            remoteauthtimeout:
                type: int
                default: 10
                description: no description
            search-all-adoms:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-low-encryption:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-protocol:
                description: no description
                type: list
                choices:
                 - tlsv1.2
                 - tlsv1.1
                 - tlsv1.0
                 - sslv3
                 - tlsv1.3
            ssl-static-key-ciphers:
                type: str
                default: 'enable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            task-list-size:
                type: int
                default: 2000
                description: no description
            tftp:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            timezone:
                type: str
                default: '04'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - '00'
                    - '01'
                    - '02'
                    - '03'
                    - '04'
                    - '05'
                    - '06'
                    - '07'
                    - '08'
                    - '09'
                    - '10'
                    - '11'
                    - '12'
                    - '13'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '22'
                    - '23'
                    - '24'
                    - '25'
                    - '26'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
                    - '33'
                    - '34'
                    - '35'
                    - '36'
                    - '37'
                    - '38'
                    - '39'
                    - '40'
                    - '41'
                    - '42'
                    - '43'
                    - '44'
                    - '45'
                    - '46'
                    - '47'
                    - '48'
                    - '49'
                    - '50'
                    - '51'
                    - '52'
                    - '53'
                    - '54'
                    - '55'
                    - '56'
                    - '57'
                    - '58'
                    - '59'
                    - '60'
                    - '61'
                    - '62'
                    - '63'
                    - '64'
                    - '65'
                    - '66'
                    - '67'
                    - '68'
                    - '69'
                    - '70'
                    - '71'
                    - '72'
                    - '73'
                    - '74'
                    - '75'
                    - '76'
                    - '77'
                    - '78'
                    - '79'
                    - '80'
                    - '81'
                    - '82'
                    - '83'
                    - '84'
                    - '85'
                    - '86'
                    - '87'
                    - '88'
                    - '89'
                    - '90'
                    - '91'
            tunnel-mtu:
                type: int
                default: 1500
                description: no description
            usg:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            vdom-mirror:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            webservice-proto:
                description: no description
                type: list
                choices:
                 - tlsv1.2
                 - tlsv1.1
                 - tlsv1.0
                 - sslv3
                 - sslv2
                 - tlsv1.3
            workflow-max-sessions:
                type: int
                default: 500
                description: no description
            workspace-mode:
                type: str
                default: 'disabled'
                description:
                 - no description
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disabled'
                    - 'normal'
                    - 'workflow'
                    - 'per-adom'
            clone-name-option:
                type: str
                default: 'default'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'default'
                    - 'keep'
            fgfm-ca-cert:
                type: str
                description: no description
            mc-policy-disabled-adoms:
                description: no description
                type: list
                suboptions:
                    adom-name:
                        type: str
                        description: no description
            policy-object-icon:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            private-data-encryption:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            per-policy-lock:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            multiple-steps-upgrade-in-autolink:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            object-revision-db-max:
                type: int
                default: 100000
                description: no description
            object-revision-mandatory-note:
                type: str
                default: 'enable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            object-revision-object-max:
                type: int
                default: 100
                description: no description
            object-revision-status:
                type: str
                default: 'enable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            normalized-intf-zone-only:
                type: str
                default: 'disable'
                description:
                 - no description
                 - no description
                 - no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-cipher-suites:
                description: description
                type: list
                suboptions:
                    cipher:
                        type: str
                        description: no description
                    priority:
                        type: int
                        default: 0
                        description: no description
                    version:
                        type: str
                        default: 'tls1.'
                        description:
                         - no description
                         - no description
                         - no description
                        choices:
                            - 'tls1.2-or-below'
                            - 'tls1.3'

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
    - name: enable workspace mode
      fmgr_system_global:
         system_global:
              adom-status: enable
              workspace-mode: normal

    - name: Script table.
      fmgr_dvmdb_script:
         bypass_validation: False
         adom: root
         state: present
         workspace_locking_adom: 'root'
         dvmdb_script:
            content: 'ansiblt-test'
            name: 'fooscript000'
            target: device_database
            type: cli

    - name: verify script table
      fmgr_fact:
         facts:
            selector: 'dvmdb_script'
            params:
                adom: 'root'
                script: 'fooscript000'
      register: info
      failed_when: info.meta.response_code != 0

    - name: restore workspace mode
      fmgr_system_global:
         system_global:
             adom-status: enable
             workspace-mode: disabled

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
        '/cli/global/system/global'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/global/{global}'
    ]

    url_params = []
    module_primary_key = None
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
        'system_global': {
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
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'admin-lockout-duration': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'admin-lockout-threshold': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'adom-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'normal',
                        'advanced'
                    ],
                    'type': 'str'
                },
                'adom-rev-auto-delete': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'by-revisions',
                        'by-days'
                    ],
                    'type': 'str'
                },
                'adom-rev-max-backup-revisions': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'adom-rev-max-days': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'adom-rev-max-revisions': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'adom-select': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'adom-status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'clt-cert-req': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable',
                        'optional'
                    ],
                    'type': 'str'
                },
                'console-output': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'standard',
                        'more'
                    ],
                    'type': 'str'
                },
                'country-flag': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'create-revision': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'daylightsavetime': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'default-disk-quota': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'detect-unregistered-log-device': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'device-view-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'regular',
                        'tree'
                    ],
                    'type': 'str'
                },
                'dh-params': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        '1024',
                        '1536',
                        '2048',
                        '3072',
                        '4096',
                        '6144',
                        '8192'
                    ],
                    'type': 'str'
                },
                'disable-module': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'fortiview-noc',
                        'none',
                        'fortirecorder',
                        'siem',
                        'soc',
                        'ai'
                    ]
                },
                'enc-algorithm': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'low',
                        'medium',
                        'high',
                        'custom'
                    ],
                    'type': 'str'
                },
                'faz-status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fgfm-local-cert': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'fgfm-ssl-protocol': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'sslv3',
                        'tlsv1.0',
                        'tlsv1.1',
                        'tlsv1.2',
                        'tlsv1.3'
                    ],
                    'type': 'str'
                },
                'ha-member-auto-grouping': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'hitcount_concurrent': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'hitcount_interval': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'int'
                },
                'hostname': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'import-ignore-addr-cmt': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'language': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'english',
                        'simch',
                        'japanese',
                        'korean',
                        'spanish',
                        'trach'
                    ],
                    'type': 'str'
                },
                'latitude': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ldap-cache-timeout': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'ldapconntimeout': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'lock-preempt': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'log-checksum': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'md5',
                        'md5-auth'
                    ],
                    'type': 'str'
                },
                'log-forward-cache-size': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'longitude': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'max-log-forward': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'max-running-reports': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'oftp-ssl-protocol': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'sslv3',
                        'tlsv1.0',
                        'tlsv1.1',
                        'tlsv1.2',
                        'tlsv1.3'
                    ],
                    'type': 'str'
                },
                'partial-install': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'partial-install-force': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'partial-install-rev': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'perform-improve-by-ha': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'policy-hit-count': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'policy-object-in-dual-pane': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'pre-login-banner': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'pre-login-banner-message': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'remoteauthtimeout': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'search-all-adoms': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-low-encryption': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-protocol': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'tlsv1.2',
                        'tlsv1.1',
                        'tlsv1.0',
                        'sslv3',
                        'tlsv1.3'
                    ]
                },
                'ssl-static-key-ciphers': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'task-list-size': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'tftp': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'timezone': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        '00',
                        '01',
                        '02',
                        '03',
                        '04',
                        '05',
                        '06',
                        '07',
                        '08',
                        '09',
                        '10',
                        '11',
                        '12',
                        '13',
                        '14',
                        '15',
                        '16',
                        '17',
                        '18',
                        '19',
                        '20',
                        '21',
                        '22',
                        '23',
                        '24',
                        '25',
                        '26',
                        '27',
                        '28',
                        '29',
                        '30',
                        '31',
                        '32',
                        '33',
                        '34',
                        '35',
                        '36',
                        '37',
                        '38',
                        '39',
                        '40',
                        '41',
                        '42',
                        '43',
                        '44',
                        '45',
                        '46',
                        '47',
                        '48',
                        '49',
                        '50',
                        '51',
                        '52',
                        '53',
                        '54',
                        '55',
                        '56',
                        '57',
                        '58',
                        '59',
                        '60',
                        '61',
                        '62',
                        '63',
                        '64',
                        '65',
                        '66',
                        '67',
                        '68',
                        '69',
                        '70',
                        '71',
                        '72',
                        '73',
                        '74',
                        '75',
                        '76',
                        '77',
                        '78',
                        '79',
                        '80',
                        '81',
                        '82',
                        '83',
                        '84',
                        '85',
                        '86',
                        '87',
                        '88',
                        '89',
                        '90',
                        '91'
                    ],
                    'type': 'str'
                },
                'tunnel-mtu': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'usg': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'vdom-mirror': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'webservice-proto': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'tlsv1.2',
                        'tlsv1.1',
                        'tlsv1.0',
                        'sslv3',
                        'sslv2',
                        'tlsv1.3'
                    ]
                },
                'workflow-max-sessions': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'workspace-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disabled',
                        'normal',
                        'workflow',
                        'per-adom'
                    ],
                    'type': 'str'
                },
                'clone-name-option': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'default',
                        'keep'
                    ],
                    'type': 'str'
                },
                'fgfm-ca-cert': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'mc-policy-disabled-adoms': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'adom-name': {
                            'required': False,
                            'revision': {
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'policy-object-icon': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'private-data-encryption': {
                    'required': False,
                    'revision': {
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'per-policy-lock': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'multiple-steps-upgrade-in-autolink': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'object-revision-db-max': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'object-revision-mandatory-note': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'object-revision-object-max': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'object-revision-status': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'normalized-intf-zone-only': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-cipher-suites': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'priority': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'version': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'tls1.2-or-below',
                                'tls1.3'
                            ],
                            'type': 'str'
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_global'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
