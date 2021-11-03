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
module: fmgr_wanprof_system_virtualwanlink_healthcheck
short_description: SD-WAN status checking or health checking.
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
    wanprof:
        description: the parameter (wanprof) in requested url
        type: str
        required: true
    wanprof_system_virtualwanlink_healthcheck:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            _dynamic-server:
                type: str
                description: no description
            addr-mode:
                type: str
                description: 'Address mode (IPv4 or IPv6).'
                choices:
                    - 'ipv4'
                    - 'ipv6'
            failtime:
                type: int
                description: 'Number of failures before server is considered lost (1 - 3600, default = 5).'
            http-agent:
                type: str
                description: 'String in the http-agent field in the HTTP header.'
            http-get:
                type: str
                description: 'URL used to communicate with the server if the protocol if the protocol is HTTP.'
            http-match:
                type: str
                description: 'Response string expected from the server if the protocol is HTTP.'
            interval:
                type: int
                description: 'Status check interval, or the time between attempting to connect to the server (1 - 3600 sec, default = 5).'
            members:
                type: str
                description: 'Member sequence number list.'
            name:
                type: str
                description: 'Status check or health check name.'
            packet-size:
                type: int
                description: 'Packet size of a twamp test session,'
            password:
                description: no description
                type: str
            port:
                type: int
                description: 'Port number used to communicate with the server over the selected protocol.'
            protocol:
                type: str
                description: 'Protocol used to determine if the FortiGate can communicate with the server.'
                choices:
                    - 'ping'
                    - 'tcp-echo'
                    - 'udp-echo'
                    - 'http'
                    - 'twamp'
                    - 'ping6'
                    - 'dns'
            recoverytime:
                type: int
                description: 'Number of successful responses received before server is considered recovered (1 - 3600, default = 5).'
            security-mode:
                type: str
                description: 'Twamp controller security mode.'
                choices:
                    - 'none'
                    - 'authentication'
            server:
                description: no description
                type: str
            sla:
                description: no description
                type: list
                suboptions:
                    id:
                        type: int
                        description: 'SLA ID.'
                    jitter-threshold:
                        type: int
                        description: 'Jitter for SLA to make decision in milliseconds. (0 - 10000000, default = 5).'
                    latency-threshold:
                        type: int
                        description: 'Latency for SLA to make decision in milliseconds. (0 - 10000000, default = 5).'
                    link-cost-factor:
                        description: no description
                        type: list
                        choices:
                         - latency
                         - jitter
                         - packet-loss
                    packetloss-threshold:
                        type: int
                        description: 'Packet loss for SLA to make decision in percentage. (0 - 100, default = 0).'
            threshold-alert-jitter:
                type: int
                description: 'Alert threshold for jitter (ms, default = 0).'
            threshold-alert-latency:
                type: int
                description: 'Alert threshold for latency (ms, default = 0).'
            threshold-alert-packetloss:
                type: int
                description: 'Alert threshold for packet loss (percentage, default = 0).'
            threshold-warning-jitter:
                type: int
                description: 'Warning threshold for jitter (ms, default = 0).'
            threshold-warning-latency:
                type: int
                description: 'Warning threshold for latency (ms, default = 0).'
            threshold-warning-packetloss:
                type: int
                description: 'Warning threshold for packet loss (percentage, default = 0).'
            update-cascade-interface:
                type: str
                description: 'Enable/disable update cascade interface.'
                choices:
                    - 'disable'
                    - 'enable'
            update-static-route:
                type: str
                description: 'Enable/disable updating the static route.'
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-id:
                type: str
                description: 'Internet service ID.'
            probe-packets:
                type: str
                description: 'Enable/disable transmission of probe packets.'
                choices:
                    - 'disable'
                    - 'enable'
            sla-fail-log-period:
                type: int
                description: 'Time interval in seconds that SLA fail log messages will be generated (0 - 3600, default = 0).'
            sla-pass-log-period:
                type: int
                description: 'Time interval in seconds that SLA pass log messages will be generated (0 - 3600, default = 0).'
            ha-priority:
                type: int
                description: 'HA election priority (1 - 50).'
            diffservcode:
                type: str
                description: 'Differentiated services code point (DSCP) in the IP header of the probe packet.'
            probe-timeout:
                type: int
                description: 'Time to wait before a probe packet is considered lost (500 - 5000 msec, default = 500).'
            dns-request-domain:
                type: str
                description: 'Fully qualified domain name to resolve for the DNS probe.'
            probe-count:
                type: int
                description: 'Number of most recent probes that should be used to calculate latency and jitter (5 - 30, default = 30).'
            system-dns:
                type: str
                description: 'Enable/disable system DNS as the probe server.'
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
    - name: SD-WAN status checking or health checking.
      fmgr_wanprof_system_virtualwanlink_healthcheck:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         wanprof: <your own value>
         state: <value in [present, absent]>
         wanprof_system_virtualwanlink_healthcheck:
            _dynamic-server: <value of string>
            addr-mode: <value in [ipv4, ipv6]>
            failtime: <value of integer>
            http-agent: <value of string>
            http-get: <value of string>
            http-match: <value of string>
            interval: <value of integer>
            members: <value of string>
            name: <value of string>
            packet-size: <value of integer>
            password: <value of string>
            port: <value of integer>
            protocol: <value in [ping, tcp-echo, udp-echo, ...]>
            recoverytime: <value of integer>
            security-mode: <value in [none, authentication]>
            server: <value of string>
            sla:
              -
                  id: <value of integer>
                  jitter-threshold: <value of integer>
                  latency-threshold: <value of integer>
                  link-cost-factor:
                    - latency
                    - jitter
                    - packet-loss
                  packetloss-threshold: <value of integer>
            threshold-alert-jitter: <value of integer>
            threshold-alert-latency: <value of integer>
            threshold-alert-packetloss: <value of integer>
            threshold-warning-jitter: <value of integer>
            threshold-warning-latency: <value of integer>
            threshold-warning-packetloss: <value of integer>
            update-cascade-interface: <value in [disable, enable]>
            update-static-route: <value in [disable, enable]>
            internet-service-id: <value of string>
            probe-packets: <value in [disable, enable]>
            sla-fail-log-period: <value of integer>
            sla-pass-log-period: <value of integer>
            ha-priority: <value of integer>
            diffservcode: <value of string>
            probe-timeout: <value of integer>
            dns-request-domain: <value of string>
            probe-count: <value of integer>
            system-dns: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}'
    ]

    url_params = ['adom', 'wanprof']
    module_primary_key = 'name'
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'wanprof': {
            'required': True,
            'type': 'str'
        },
        'wanprof_system_virtualwanlink_healthcheck': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            },
            'options': {
                '_dynamic-server': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'addr-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'ipv4',
                        'ipv6'
                    ],
                    'type': 'str'
                },
                'failtime': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'http-agent': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'http-get': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'http-match': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'interval': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'members': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'packet-size': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'password': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'port': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'protocol': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'ping',
                        'tcp-echo',
                        'udp-echo',
                        'http',
                        'twamp',
                        'ping6',
                        'dns'
                    ],
                    'type': 'str'
                },
                'recoverytime': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'security-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'none',
                        'authentication'
                    ],
                    'type': 'str'
                },
                'server': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'sla': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'list',
                    'options': {
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'int'
                        },
                        'jitter-threshold': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'int'
                        },
                        'latency-threshold': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'int'
                        },
                        'link-cost-factor': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'list',
                            'choices': [
                                'latency',
                                'jitter',
                                'packet-loss'
                            ]
                        },
                        'packetloss-threshold': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'type': 'int'
                        }
                    }
                },
                'threshold-alert-jitter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'threshold-alert-latency': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'threshold-alert-packetloss': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'threshold-warning-jitter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'threshold-warning-latency': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'threshold-warning-packetloss': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'update-cascade-interface': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
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
                'update-static-route': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
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
                'internet-service-id': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'probe-packets': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
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
                'sla-fail-log-period': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'sla-pass-log-period': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'ha-priority': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'diffservcode': {
                    'required': False,
                    'revision': {
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'probe-timeout': {
                    'required': False,
                    'revision': {
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'dns-request-domain': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'probe-count': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'system-dns': {
                    'required': False,
                    'revision': {
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
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanprof_system_virtualwanlink_healthcheck'),
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
