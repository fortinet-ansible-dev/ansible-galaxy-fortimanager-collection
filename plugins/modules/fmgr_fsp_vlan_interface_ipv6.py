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
module: fmgr_fsp_vlan_interface_ipv6
short_description: no description
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
    vlan:
        description: the parameter (vlan) in requested url
        type: str
        required: true
    fsp_vlan_interface_ipv6:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            autoconf:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dhcp6-client-options:
                description: no description
                type: list
                choices:
                 - rapid
                 - iapd
                 - iana
                 - dns
                 - dnsname
            dhcp6-information-request:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dhcp6-prefix-delegation:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dhcp6-prefix-hint:
                type: str
                description: no description
            dhcp6-prefix-hint-plt:
                type: int
                description: no description
            dhcp6-prefix-hint-vlt:
                type: int
                description: no description
            dhcp6-relay-ip:
                type: str
                description: no description
            dhcp6-relay-service:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dhcp6-relay-type:
                type: str
                description: no description
                choices:
                    - 'regular'
            ip6-address:
                type: str
                description: no description
            ip6-allowaccess:
                description: no description
                type: list
                choices:
                 - https
                 - ping
                 - ssh
                 - snmp
                 - http
                 - telnet
                 - fgfm
                 - capwap
            ip6-default-life:
                type: int
                description: no description
            ip6-dns-server-override:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ip6-hop-limit:
                type: int
                description: no description
            ip6-link-mtu:
                type: int
                description: no description
            ip6-manage-flag:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ip6-max-interval:
                type: int
                description: no description
            ip6-min-interval:
                type: int
                description: no description
            ip6-mode:
                type: str
                description: no description
                choices:
                    - 'static'
                    - 'dhcp'
                    - 'pppoe'
                    - 'delegated'
            ip6-other-flag:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ip6-reachable-time:
                type: int
                description: no description
            ip6-retrans-time:
                type: int
                description: no description
            ip6-send-adv:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ip6-subnet:
                type: str
                description: no description
            ip6-upstream-interface:
                type: str
                description: no description
            nd-cert:
                type: str
                description: no description
            nd-cga-modifier:
                type: str
                description: no description
            nd-mode:
                type: str
                description: no description
                choices:
                    - 'basic'
                    - 'SEND-compatible'
            nd-security-level:
                type: int
                description: no description
            nd-timestamp-delta:
                type: int
                description: no description
            nd-timestamp-fuzz:
                type: int
                description: no description
            vrip6_link_local:
                type: str
                description: no description
            vrrp-virtual-mac6:
                type: str
                description: no description
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
    - name: no description
      fmgr_fsp_vlan_interface_ipv6:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         vlan: <your own value>
         fsp_vlan_interface_ipv6:
            autoconf: <value in [disable, enable]>
            dhcp6-client-options:
              - rapid
              - iapd
              - iana
              - dns
              - dnsname
            dhcp6-information-request: <value in [disable, enable]>
            dhcp6-prefix-delegation: <value in [disable, enable]>
            dhcp6-prefix-hint: <value of string>
            dhcp6-prefix-hint-plt: <value of integer>
            dhcp6-prefix-hint-vlt: <value of integer>
            dhcp6-relay-ip: <value of string>
            dhcp6-relay-service: <value in [disable, enable]>
            dhcp6-relay-type: <value in [regular]>
            ip6-address: <value of string>
            ip6-allowaccess:
              - https
              - ping
              - ssh
              - snmp
              - http
              - telnet
              - fgfm
              - capwap
            ip6-default-life: <value of integer>
            ip6-dns-server-override: <value in [disable, enable]>
            ip6-hop-limit: <value of integer>
            ip6-link-mtu: <value of integer>
            ip6-manage-flag: <value in [disable, enable]>
            ip6-max-interval: <value of integer>
            ip6-min-interval: <value of integer>
            ip6-mode: <value in [static, dhcp, pppoe, ...]>
            ip6-other-flag: <value in [disable, enable]>
            ip6-reachable-time: <value of integer>
            ip6-retrans-time: <value of integer>
            ip6-send-adv: <value in [disable, enable]>
            ip6-subnet: <value of string>
            ip6-upstream-interface: <value of string>
            nd-cert: <value of string>
            nd-cga-modifier: <value of string>
            nd-mode: <value in [basic, SEND-compatible]>
            nd-security-level: <value of integer>
            nd-timestamp-delta: <value of integer>
            nd-timestamp-fuzz: <value of integer>
            vrip6_link_local: <value of string>
            vrrp-virtual-mac6: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6',
        '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/{ipv6}',
        '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/{ipv6}'
    ]

    url_params = ['adom', 'vlan']
    module_primary_key = None
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'vlan': {
            'required': True,
            'type': 'str'
        },
        'fsp_vlan_interface_ipv6': {
            'required': False,
            'type': 'dict',
            'options': {
                'autoconf': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dhcp6-client-options': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'rapid',
                        'iapd',
                        'iana',
                        'dns',
                        'dnsname'
                    ]
                },
                'dhcp6-information-request': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dhcp6-prefix-delegation': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dhcp6-prefix-hint': {
                    'required': False,
                    'type': 'str'
                },
                'dhcp6-prefix-hint-plt': {
                    'required': False,
                    'type': 'int'
                },
                'dhcp6-prefix-hint-vlt': {
                    'required': False,
                    'type': 'int'
                },
                'dhcp6-relay-ip': {
                    'required': False,
                    'type': 'str'
                },
                'dhcp6-relay-service': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dhcp6-relay-type': {
                    'required': False,
                    'choices': [
                        'regular'
                    ],
                    'type': 'str'
                },
                'ip6-address': {
                    'required': False,
                    'type': 'str'
                },
                'ip6-allowaccess': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'https',
                        'ping',
                        'ssh',
                        'snmp',
                        'http',
                        'telnet',
                        'fgfm',
                        'capwap'
                    ]
                },
                'ip6-default-life': {
                    'required': False,
                    'type': 'int'
                },
                'ip6-dns-server-override': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ip6-hop-limit': {
                    'required': False,
                    'type': 'int'
                },
                'ip6-link-mtu': {
                    'required': False,
                    'type': 'int'
                },
                'ip6-manage-flag': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ip6-max-interval': {
                    'required': False,
                    'type': 'int'
                },
                'ip6-min-interval': {
                    'required': False,
                    'type': 'int'
                },
                'ip6-mode': {
                    'required': False,
                    'choices': [
                        'static',
                        'dhcp',
                        'pppoe',
                        'delegated'
                    ],
                    'type': 'str'
                },
                'ip6-other-flag': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ip6-reachable-time': {
                    'required': False,
                    'type': 'int'
                },
                'ip6-retrans-time': {
                    'required': False,
                    'type': 'int'
                },
                'ip6-send-adv': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ip6-subnet': {
                    'required': False,
                    'type': 'str'
                },
                'ip6-upstream-interface': {
                    'required': False,
                    'type': 'str'
                },
                'nd-cert': {
                    'required': False,
                    'type': 'str'
                },
                'nd-cga-modifier': {
                    'required': False,
                    'type': 'str'
                },
                'nd-mode': {
                    'required': False,
                    'choices': [
                        'basic',
                        'SEND-compatible'
                    ],
                    'type': 'str'
                },
                'nd-security-level': {
                    'required': False,
                    'type': 'int'
                },
                'nd-timestamp-delta': {
                    'required': False,
                    'type': 'int'
                },
                'nd-timestamp-fuzz': {
                    'required': False,
                    'type': 'int'
                },
                'vrip6_link_local': {
                    'required': False,
                    'type': 'str'
                },
                'vrrp-virtual-mac6': {
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_interface_ipv6'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
