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
module: fmgr_wanprof_system_sdwan_healthcheck
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
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    wanprof:
        description: the parameter (wanprof) in requested url
        type: str
        required: true
    wanprof_system_sdwan_healthcheck:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            _dynamic-server:
                type: str
                description: no description
            addr-mode:
                type: str
                description: no description
                choices:
                    - 'ipv4'
                    - 'ipv6'
            diffservcode:
                type: str
                description: no description
            dns-match-ip:
                type: str
                description: no description
            dns-request-domain:
                type: str
                description: no description
            failtime:
                type: int
                description: no description
            ftp-file:
                type: str
                description: no description
            ftp-mode:
                type: str
                description: no description
                choices:
                    - 'passive'
                    - 'port'
            ha-priority:
                type: int
                description: no description
            http-agent:
                type: str
                description: no description
            http-get:
                type: str
                description: no description
            http-match:
                type: str
                description: no description
            interval:
                type: int
                description: no description
            members:
                type: str
                description: no description
            name:
                type: str
                description: no description
            packet-size:
                type: int
                description: no description
            password:
                description: description
                type: str
            port:
                type: int
                description: no description
            probe-count:
                type: int
                description: no description
            probe-packets:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            probe-timeout:
                type: int
                description: no description
            protocol:
                type: str
                description: no description
                choices:
                    - 'ping'
                    - 'tcp-echo'
                    - 'udp-echo'
                    - 'http'
                    - 'twamp'
                    - 'ping6'
                    - 'dns'
                    - 'tcp-connect'
                    - 'ftp'
            quality-measured-method:
                type: str
                description: no description
                choices:
                    - 'half-close'
                    - 'half-open'
            recoverytime:
                type: int
                description: no description
            security-mode:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'authentication'
            server:
                description: description
                type: str
            sla:
                description: description
                type: list
                suboptions:
                    id:
                        type: int
                        description: no description
                    jitter-threshold:
                        type: int
                        description: no description
                    latency-threshold:
                        type: int
                        description: no description
                    link-cost-factor:
                        description: description
                        type: list
                        choices:
                         - latency
                         - jitter
                         - packet-loss
                         - mos
                    packetloss-threshold:
                        type: int
                        description: no description
                    mos-threshold:
                        type: str
                        description: no description
            sla-fail-log-period:
                type: int
                description: no description
            sla-pass-log-period:
                type: int
                description: no description
            system-dns:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            threshold-alert-jitter:
                type: int
                description: no description
            threshold-alert-latency:
                type: int
                description: no description
            threshold-alert-packetloss:
                type: int
                description: no description
            threshold-warning-jitter:
                type: int
                description: no description
            threshold-warning-latency:
                type: int
                description: no description
            threshold-warning-packetloss:
                type: int
                description: no description
            update-cascade-interface:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            update-static-route:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            user:
                type: str
                description: no description
            detect-mode:
                type: str
                description: no description
                choices:
                    - 'active'
                    - 'passive'
                    - 'prefer-passive'
            mos-codec:
                type: str
                description: no description
                choices:
                    - 'g711'
                    - 'g722'
                    - 'g729'
            source:
                type: str
                description: no description
            vrf:
                type: int
                description: no description

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
      fmgr_wanprof_system_sdwan_healthcheck:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         wanprof: <your own value>
         state: <value in [present, absent]>
         wanprof_system_sdwan_healthcheck:
            _dynamic-server: <value of string>
            addr-mode: <value in [ipv4, ipv6]>
            diffservcode: <value of string>
            dns-match-ip: <value of string>
            dns-request-domain: <value of string>
            failtime: <value of integer>
            ftp-file: <value of string>
            ftp-mode: <value in [passive, port]>
            ha-priority: <value of integer>
            http-agent: <value of string>
            http-get: <value of string>
            http-match: <value of string>
            interval: <value of integer>
            members: <value of string>
            name: <value of string>
            packet-size: <value of integer>
            password: <value of string>
            port: <value of integer>
            probe-count: <value of integer>
            probe-packets: <value in [disable, enable]>
            probe-timeout: <value of integer>
            protocol: <value in [ping, tcp-echo, udp-echo, ...]>
            quality-measured-method: <value in [half-close, half-open]>
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
                    - mos
                  packetloss-threshold: <value of integer>
                  mos-threshold: <value of string>
            sla-fail-log-period: <value of integer>
            sla-pass-log-period: <value of integer>
            system-dns: <value in [disable, enable]>
            threshold-alert-jitter: <value of integer>
            threshold-alert-latency: <value of integer>
            threshold-alert-packetloss: <value of integer>
            threshold-warning-jitter: <value of integer>
            threshold-warning-latency: <value of integer>
            threshold-warning-packetloss: <value of integer>
            update-cascade-interface: <value in [disable, enable]>
            update-static-route: <value in [disable, enable]>
            user: <value of string>
            detect-mode: <value in [active, passive, prefer-passive]>
            mos-codec: <value in [g711, g722, g729]>
            source: <value of string>
            vrf: <value of integer>

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
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check/{health-check}'
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
        'wanprof_system_sdwan_healthcheck': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                '_dynamic-server': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'str'
                },
                'addr-mode': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'ipv4',
                        'ipv6'
                    ],
                    'type': 'str'
                },
                'diffservcode': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dns-match-ip': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dns-request-domain': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'failtime': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'ftp-file': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ftp-mode': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'passive',
                        'port'
                    ],
                    'type': 'str'
                },
                'ha-priority': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'http-agent': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'http-get': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'http-match': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'interval': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'members': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'packet-size': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'password': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'port': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'probe-count': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'probe-packets': {
                    'required': False,
                    'revision': {
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
                'probe-timeout': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'protocol': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'ping',
                        'tcp-echo',
                        'udp-echo',
                        'http',
                        'twamp',
                        'ping6',
                        'dns',
                        'tcp-connect',
                        'ftp'
                    ],
                    'type': 'str'
                },
                'quality-measured-method': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'half-close',
                        'half-open'
                    ],
                    'type': 'str'
                },
                'recoverytime': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'security-mode': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
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
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sla': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'id': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'jitter-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'latency-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'link-cost-factor': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'latency',
                                'jitter',
                                'packet-loss',
                                'mos'
                            ]
                        },
                        'packetloss-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'mos-threshold': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'sla-fail-log-period': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'sla-pass-log-period': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'system-dns': {
                    'required': False,
                    'revision': {
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
                'threshold-alert-jitter': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'threshold-alert-latency': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'threshold-alert-packetloss': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'threshold-warning-jitter': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'threshold-warning-latency': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'threshold-warning-packetloss': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'update-cascade-interface': {
                    'required': False,
                    'revision': {
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
                'update-static-route': {
                    'required': False,
                    'revision': {
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
                'user': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'detect-mode': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'active',
                        'passive',
                        'prefer-passive'
                    ],
                    'type': 'str'
                },
                'mos-codec': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'g711',
                        'g722',
                        'g729'
                    ],
                    'type': 'str'
                },
                'source': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'vrf': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanprof_system_sdwan_healthcheck'),
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
