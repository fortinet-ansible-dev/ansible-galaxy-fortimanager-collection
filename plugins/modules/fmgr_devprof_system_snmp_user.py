#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2020 Fortinet, Inc.
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
module: fmgr_devprof_system_snmp_user
short_description: SNMP user configuration.
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
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    devprof:
        description: the parameter (devprof) in requested url
        type: str
        required: true
    devprof_system_snmp_user:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            auth-proto:
                type: str
                description: 'Authentication protocol.'
                choices:
                    - 'md5'
                    - 'sha'
            auth-pwd:
                description: no description
                type: str
            events:
                description: no description
                type: list
                choices:
                 - cpu-high
                 - mem-low
                 - log-full
                 - intf-ip
                 - vpn-tun-up
                 - vpn-tun-down
                 - ha-switch
                 - fm-conf-change
                 - ips-signature
                 - ips-anomaly
                 - temperature-high
                 - voltage-alert
                 - av-virus
                 - av-oversize
                 - av-pattern
                 - av-fragmented
                 - ha-hb-failure
                 - fan-failure
                 - ha-member-up
                 - ha-member-down
                 - ent-conf-change
                 - av-conserve
                 - av-bypass
                 - av-oversize-passed
                 - av-oversize-blocked
                 - ips-pkg-update
                 - fm-if-change
                 - power-supply-failure
                 - amc-bypass
                 - faz-disconnect
                 - bgp-established
                 - bgp-backward-transition
                 - wc-ap-up
                 - wc-ap-down
                 - fswctl-session-up
                 - fswctl-session-down
                 - ips-fail-open
                 - load-balance-real-server-down
                 - device-new
                 - enter-intf-bypass
                 - exit-intf-bypass
                 - per-cpu-high
                 - power-blade-down
                 - confsync_failure
            ha-direct:
                type: str
                description: 'Enable/disable direct management of HA cluster members.'
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: 'SNMP user name.'
            notify-hosts:
                description: no description
                type: str
            notify-hosts6:
                type: str
                description: 'IPv6 SNMP managers to send notifications (traps) to.'
            priv-proto:
                type: str
                description: 'Privacy (encryption) protocol.'
                choices:
                    - 'aes'
                    - 'des'
                    - 'aes256'
                    - 'aes256cisco'
            priv-pwd:
                description: no description
                type: str
            queries:
                type: str
                description: 'Enable/disable SNMP queries for this user.'
                choices:
                    - 'disable'
                    - 'enable'
            query-port:
                type: int
                description: 'SNMPv3 query port (default = 161).'
            security-level:
                type: str
                description: 'Security level for message authentication and encryption.'
                choices:
                    - 'no-auth-no-priv'
                    - 'auth-no-priv'
                    - 'auth-priv'
            source-ip:
                type: str
                description: 'Source IP for SNMP trap.'
            source-ipv6:
                type: str
                description: 'Source IPv6 for SNMP trap.'
            status:
                type: str
                description: 'Enable/disable this SNMP user.'
                choices:
                    - 'disable'
                    - 'enable'
            trap-lport:
                type: int
                description: 'SNMPv3 local trap port (default = 162).'
            trap-rport:
                type: int
                description: 'SNMPv3 trap remote port (default = 162).'
            trap-status:
                type: str
                description: 'Enable/disable traps for this SNMP user.'
                choices:
                    - 'disable'
                    - 'enable'

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: SNMP user configuration.
      fmgr_devprof_system_snmp_user:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         devprof: <your own value>
         state: <value in [present, absent]>
         devprof_system_snmp_user:
            auth-proto: <value in [md5, sha]>
            auth-pwd: <value of string>
            events:
              - cpu-high
              - mem-low
              - log-full
              - intf-ip
              - vpn-tun-up
              - vpn-tun-down
              - ha-switch
              - fm-conf-change
              - ips-signature
              - ips-anomaly
              - temperature-high
              - voltage-alert
              - av-virus
              - av-oversize
              - av-pattern
              - av-fragmented
              - ha-hb-failure
              - fan-failure
              - ha-member-up
              - ha-member-down
              - ent-conf-change
              - av-conserve
              - av-bypass
              - av-oversize-passed
              - av-oversize-blocked
              - ips-pkg-update
              - fm-if-change
              - power-supply-failure
              - amc-bypass
              - faz-disconnect
              - bgp-established
              - bgp-backward-transition
              - wc-ap-up
              - wc-ap-down
              - fswctl-session-up
              - fswctl-session-down
              - ips-fail-open
              - load-balance-real-server-down
              - device-new
              - enter-intf-bypass
              - exit-intf-bypass
              - per-cpu-high
              - power-blade-down
              - confsync_failure
            ha-direct: <value in [disable, enable]>
            name: <value of string>
            notify-hosts: <value of string>
            notify-hosts6: <value of string>
            priv-proto: <value in [aes, des, aes256, ...]>
            priv-pwd: <value of string>
            queries: <value in [disable, enable]>
            query-port: <value of integer>
            security-level: <value in [no-auth-no-priv, auth-no-priv, auth-priv]>
            source-ip: <value of string>
            source-ipv6: <value of string>
            status: <value in [disable, enable]>
            trap-lport: <value of integer>
            trap-rport: <value of integer>
            trap-status: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user/{user}'
    ]

    url_params = ['adom', 'devprof']
    module_primary_key = 'name'
    module_arg_spec = {
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'devprof': {
            'required': True,
            'type': 'str'
        },
        'devprof_system_snmp_user': {
            'required': False,
            'type': 'dict',
            'options': {
                'auth-proto': {
                    'required': False,
                    'choices': [
                        'md5',
                        'sha'
                    ],
                    'type': 'str'
                },
                'auth-pwd': {
                    'required': False,
                    'type': 'str'
                },
                'events': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'cpu-high',
                        'mem-low',
                        'log-full',
                        'intf-ip',
                        'vpn-tun-up',
                        'vpn-tun-down',
                        'ha-switch',
                        'fm-conf-change',
                        'ips-signature',
                        'ips-anomaly',
                        'temperature-high',
                        'voltage-alert',
                        'av-virus',
                        'av-oversize',
                        'av-pattern',
                        'av-fragmented',
                        'ha-hb-failure',
                        'fan-failure',
                        'ha-member-up',
                        'ha-member-down',
                        'ent-conf-change',
                        'av-conserve',
                        'av-bypass',
                        'av-oversize-passed',
                        'av-oversize-blocked',
                        'ips-pkg-update',
                        'fm-if-change',
                        'power-supply-failure',
                        'amc-bypass',
                        'faz-disconnect',
                        'bgp-established',
                        'bgp-backward-transition',
                        'wc-ap-up',
                        'wc-ap-down',
                        'fswctl-session-up',
                        'fswctl-session-down',
                        'ips-fail-open',
                        'load-balance-real-server-down',
                        'device-new',
                        'enter-intf-bypass',
                        'exit-intf-bypass',
                        'per-cpu-high',
                        'power-blade-down',
                        'confsync_failure'
                    ]
                },
                'ha-direct': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'notify-hosts': {
                    'required': False,
                    'type': 'str'
                },
                'notify-hosts6': {
                    'required': False,
                    'type': 'str'
                },
                'priv-proto': {
                    'required': False,
                    'choices': [
                        'aes',
                        'des',
                        'aes256',
                        'aes256cisco'
                    ],
                    'type': 'str'
                },
                'priv-pwd': {
                    'required': False,
                    'type': 'str'
                },
                'queries': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'query-port': {
                    'required': False,
                    'type': 'int'
                },
                'security-level': {
                    'required': False,
                    'choices': [
                        'no-auth-no-priv',
                        'auth-no-priv',
                        'auth-priv'
                    ],
                    'type': 'str'
                },
                'source-ip': {
                    'required': False,
                    'type': 'str'
                },
                'source-ipv6': {
                    'required': False,
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'trap-lport': {
                    'required': False,
                    'type': 'int'
                },
                'trap-rport': {
                    'required': False,
                    'type': 'int'
                },
                'trap-status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_snmp_user'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
