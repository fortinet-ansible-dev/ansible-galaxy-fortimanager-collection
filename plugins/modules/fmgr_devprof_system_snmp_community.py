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
module: fmgr_devprof_system_snmp_community
short_description: SNMP community configuration.
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
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    devprof:
        description: the parameter (devprof) in requested url
        type: str
        required: true
    devprof_system_snmp_community:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
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
                 - ha-hb-failure
                 - ips-signature
                 - ips-anomaly
                 - av-virus
                 - av-oversize
                 - av-pattern
                 - av-fragmented
                 - fm-if-change
                 - fm-conf-change
                 - temperature-high
                 - voltage-alert
                 - ha-member-up
                 - ha-member-down
                 - ent-conf-change
                 - av-conserve
                 - av-bypass
                 - av-oversize-passed
                 - av-oversize-blocked
                 - ips-pkg-update
                 - power-supply-failure
                 - amc-bypass
                 - faz-disconnect
                 - fan-failure
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
                 - dhcp
                 - pool-usage
                 - power-redundancy-degrade
                 - power-redundancy-failure
                 - ospf-nbr-state-change
                 - ospf-virtnbr-state-change
            hosts:
                description: no description
                type: list
                suboptions:
                    ha-direct:
                        type: str
                        description: 'Enable/disable direct management of HA cluster members.'
                        choices:
                            - 'disable'
                            - 'enable'
                    host-type:
                        type: str
                        description: 'Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.'
                        choices:
                            - 'any'
                            - 'query'
                            - 'trap'
                    id:
                        type: int
                        description: 'Host entry ID.'
                    ip:
                        type: str
                        description: 'IPv4 address of the SNMP manager (host).'
                    source-ip:
                        type: str
                        description: 'Source IPv4 address for SNMP traps.'
            hosts6:
                description: no description
                type: list
                suboptions:
                    ha-direct:
                        type: str
                        description: 'Enable/disable direct management of HA cluster members.'
                        choices:
                            - 'disable'
                            - 'enable'
                    host-type:
                        type: str
                        description: 'Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.'
                        choices:
                            - 'any'
                            - 'query'
                            - 'trap'
                    id:
                        type: int
                        description: 'Host6 entry ID.'
                    ipv6:
                        type: str
                        description: 'SNMP manager IPv6 address prefix.'
                    source-ipv6:
                        type: str
                        description: 'Source IPv6 address for SNMP traps.'
            id:
                type: int
                description: 'Community ID.'
            name:
                type: str
                description: 'Community name.'
            query-v1-port:
                type: int
                description: 'SNMP v1 query port (default = 161).'
            query-v1-status:
                type: str
                description: 'Enable/disable SNMP v1 queries.'
                choices:
                    - 'disable'
                    - 'enable'
            query-v2c-port:
                type: int
                description: 'SNMP v2c query port (default = 161).'
            query-v2c-status:
                type: str
                description: 'Enable/disable SNMP v2c queries.'
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description: 'Enable/disable this SNMP community.'
                choices:
                    - 'disable'
                    - 'enable'
            trap-v1-lport:
                type: int
                description: 'SNMP v1 trap local port (default = 162).'
            trap-v1-rport:
                type: int
                description: 'SNMP v1 trap remote port (default = 162).'
            trap-v1-status:
                type: str
                description: 'Enable/disable SNMP v1 traps.'
                choices:
                    - 'disable'
                    - 'enable'
            trap-v2c-lport:
                type: int
                description: 'SNMP v2c trap local port (default = 162).'
            trap-v2c-rport:
                type: int
                description: 'SNMP v2c trap remote port (default = 162).'
            trap-v2c-status:
                type: str
                description: 'Enable/disable SNMP v2c traps.'
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
    - name: SNMP community configuration.
      fmgr_devprof_system_snmp_community:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         devprof: <your own value>
         state: <value in [present, absent]>
         devprof_system_snmp_community:
            events:
              - cpu-high
              - mem-low
              - log-full
              - intf-ip
              - vpn-tun-up
              - vpn-tun-down
              - ha-switch
              - ha-hb-failure
              - ips-signature
              - ips-anomaly
              - av-virus
              - av-oversize
              - av-pattern
              - av-fragmented
              - fm-if-change
              - fm-conf-change
              - temperature-high
              - voltage-alert
              - ha-member-up
              - ha-member-down
              - ent-conf-change
              - av-conserve
              - av-bypass
              - av-oversize-passed
              - av-oversize-blocked
              - ips-pkg-update
              - power-supply-failure
              - amc-bypass
              - faz-disconnect
              - fan-failure
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
              - dhcp
              - pool-usage
              - power-redundancy-degrade
              - power-redundancy-failure
              - ospf-nbr-state-change
              - ospf-virtnbr-state-change
            hosts:
              -
                  ha-direct: <value in [disable, enable]>
                  host-type: <value in [any, query, trap]>
                  id: <value of integer>
                  ip: <value of string>
                  source-ip: <value of string>
            hosts6:
              -
                  ha-direct: <value in [disable, enable]>
                  host-type: <value in [any, query, trap]>
                  id: <value of integer>
                  ipv6: <value of string>
                  source-ipv6: <value of string>
            id: <value of integer>
            name: <value of string>
            query-v1-port: <value of integer>
            query-v1-status: <value in [disable, enable]>
            query-v2c-port: <value of integer>
            query-v2c-status: <value in [disable, enable]>
            status: <value in [disable, enable]>
            trap-v1-lport: <value of integer>
            trap-v1-rport: <value of integer>
            trap-v1-status: <value in [disable, enable]>
            trap-v2c-lport: <value of integer>
            trap-v2c-rport: <value of integer>
            trap-v2c-status: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}'
    ]

    url_params = ['adom', 'devprof']
    module_primary_key = 'id'
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'devprof': {
            'required': True,
            'type': 'str'
        },
        'devprof_system_snmp_community': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True
            },
            'options': {
                'events': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'cpu-high',
                        'mem-low',
                        'log-full',
                        'intf-ip',
                        'vpn-tun-up',
                        'vpn-tun-down',
                        'ha-switch',
                        'ha-hb-failure',
                        'ips-signature',
                        'ips-anomaly',
                        'av-virus',
                        'av-oversize',
                        'av-pattern',
                        'av-fragmented',
                        'fm-if-change',
                        'fm-conf-change',
                        'temperature-high',
                        'voltage-alert',
                        'ha-member-up',
                        'ha-member-down',
                        'ent-conf-change',
                        'av-conserve',
                        'av-bypass',
                        'av-oversize-passed',
                        'av-oversize-blocked',
                        'ips-pkg-update',
                        'power-supply-failure',
                        'amc-bypass',
                        'faz-disconnect',
                        'fan-failure',
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
                        'confsync_failure',
                        'dhcp',
                        'pool-usage',
                        'power-redundancy-degrade',
                        'power-redundancy-failure',
                        'ospf-nbr-state-change',
                        'ospf-virtnbr-state-change'
                    ]
                },
                'hosts': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'ha-direct': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'host-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'any',
                                'query',
                                'trap'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'ip': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'source-ip': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'hosts6': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'ha-direct': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'host-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'any',
                                'query',
                                'trap'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'ipv6': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'source-ipv6': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'id': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
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
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'query-v1-port': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'query-v1-status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'query-v2c-port': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'query-v2c-status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
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
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'trap-v1-lport': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'trap-v1-rport': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'trap-v1-status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'trap-v2c-lport': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'trap-v2c-rport': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'trap-v2c-status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': True,
                        '7.0.0': True
                    },
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_snmp_community'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
