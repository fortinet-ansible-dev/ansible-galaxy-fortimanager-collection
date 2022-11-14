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
module: fmgr_system_npu
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
    system_npu:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            capwap-offload:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dedicated-management-affinity:
                type: str
                description: no description
            dedicated-management-cpu:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            fastpath:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            fp-anomaly:
                description: no description
                type: dict
                required: false
                suboptions:
                    esp-minlen-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    icmp-csum-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    icmp-minlen-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4-csum-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4-ihl-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4-len-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4-opt-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4-ttlzero-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4-ver-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv6-exthdr-len-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv6-exthdr-order-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv6-ihl-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv6-plen-zero:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv6-ver-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    tcp-csum-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    tcp-hlen-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    tcp-plen-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udp-csum-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udp-hlen-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udp-len-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udp-plen-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udplite-cover-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udplite-csum-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    unknproto-minlen-err:
                        type: str
                        description: no description
                        choices:
                            - 'drop'
                            - 'trap-to-host'
            gtp-enhanced-cpu-range:
                type: str
                description: no description
                choices:
                    - '0'
                    - '1'
                    - '2'
            gtp-enhanced-mode:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            host-shortcut-mode:
                type: str
                description: no description
                choices:
                    - 'bi-directional'
                    - 'host-shortcut'
            htx-gtse-quota:
                type: str
                description: no description
                choices:
                    - '100Mbps'
                    - '200Mbps'
                    - '300Mbps'
                    - '400Mbps'
                    - '500Mbps'
                    - '600Mbps'
                    - '700Mbps'
                    - '800Mbps'
                    - '900Mbps'
                    - '1Gbps'
                    - '2Gbps'
                    - '4Gbps'
                    - '8Gbps'
                    - '10Gbps'
            intf-shaping-offload:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            iph-rsvd-re-cksum:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ipsec-dec-subengine-mask:
                type: str
                description: no description
            ipsec-enc-subengine-mask:
                type: str
                description: no description
            ipsec-inbound-cache:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ipsec-mtu-override:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ipsec-over-vlink:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            isf-np-queues:
                description: no description
                type: dict
                required: false
                suboptions:
                    cos0:
                        type: str
                        description: no description
                    cos1:
                        type: str
                        description: no description
                    cos2:
                        type: str
                        description: no description
                    cos3:
                        type: str
                        description: no description
                    cos4:
                        type: str
                        description: no description
                    cos5:
                        type: str
                        description: no description
                    cos6:
                        type: str
                        description: no description
                    cos7:
                        type: str
                        description: no description
            lag-out-port-select:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            mcast-session-accounting:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'session-based'
                    - 'tpe-based'
            np6-cps-optimization-mode:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            per-session-accounting:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'
                    - 'enable-by-log'
                    - 'all-enable'
                    - 'traffic-log-only'
            port-cpu-map:
                description: description
                type: list
                suboptions:
                    cpu-core:
                        type: str
                        description: no description
                    interface:
                        type: str
                        description: no description
            port-npu-map:
                description: description
                type: list
                suboptions:
                    interface:
                        type: str
                        description: no description
                    npu-group-index:
                        type: int
                        description: no description
            priority-protocol:
                description: no description
                type: dict
                required: false
                suboptions:
                    bfd:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    bgp:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    slbc:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            qos-mode:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'priority'
                    - 'round-robin'
            rdp-offload:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            recover-np6-link:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            session-denied-offload:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sse-backpressure:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            strip-clear-text-padding:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            strip-esp-padding:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sw-eh-hash:
                description: no description
                type: dict
                required: false
                suboptions:
                    computation:
                        type: str
                        description: no description
                        choices:
                            - 'xor16'
                            - 'xor8'
                            - 'xor4'
                            - 'crc16'
                    destination-ip-lower-16:
                        type: str
                        description: no description
                        choices:
                            - 'include'
                            - 'exclude'
                    destination-ip-upper-16:
                        type: str
                        description: no description
                        choices:
                            - 'include'
                            - 'exclude'
                    destination-port:
                        type: str
                        description: no description
                        choices:
                            - 'include'
                            - 'exclude'
                    ip-protocol:
                        type: str
                        description: no description
                        choices:
                            - 'include'
                            - 'exclude'
                    netmask-length:
                        type: int
                        description: no description
                    source-ip-lower-16:
                        type: str
                        description: no description
                        choices:
                            - 'include'
                            - 'exclude'
                    source-ip-upper-16:
                        type: str
                        description: no description
                        choices:
                            - 'include'
                            - 'exclude'
                    source-port:
                        type: str
                        description: no description
                        choices:
                            - 'include'
                            - 'exclude'
            sw-np-bandwidth:
                type: str
                description: no description
                choices:
                    - '0G'
                    - '2G'
                    - '4G'
                    - '5G'
                    - '6G'
                    - '7G'
                    - '8G'
                    - '9G'
            switch-np-hash:
                type: str
                description: no description
                choices:
                    - 'src-ip'
                    - 'dst-ip'
                    - 'src-dst-ip'
            uesp-offload:
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
      fmgr_system_npu:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         system_npu:
            capwap-offload: <value in [disable, enable]>
            dedicated-management-affinity: <value of string>
            dedicated-management-cpu: <value in [disable, enable]>
            fastpath: <value in [disable, enable]>
            fp-anomaly:
               esp-minlen-err: <value in [drop, trap-to-host]>
               icmp-csum-err: <value in [drop, trap-to-host]>
               icmp-minlen-err: <value in [drop, trap-to-host]>
               ipv4-csum-err: <value in [drop, trap-to-host]>
               ipv4-ihl-err: <value in [drop, trap-to-host]>
               ipv4-len-err: <value in [drop, trap-to-host]>
               ipv4-opt-err: <value in [drop, trap-to-host]>
               ipv4-ttlzero-err: <value in [drop, trap-to-host]>
               ipv4-ver-err: <value in [drop, trap-to-host]>
               ipv6-exthdr-len-err: <value in [drop, trap-to-host]>
               ipv6-exthdr-order-err: <value in [drop, trap-to-host]>
               ipv6-ihl-err: <value in [drop, trap-to-host]>
               ipv6-plen-zero: <value in [drop, trap-to-host]>
               ipv6-ver-err: <value in [drop, trap-to-host]>
               tcp-csum-err: <value in [drop, trap-to-host]>
               tcp-hlen-err: <value in [drop, trap-to-host]>
               tcp-plen-err: <value in [drop, trap-to-host]>
               udp-csum-err: <value in [drop, trap-to-host]>
               udp-hlen-err: <value in [drop, trap-to-host]>
               udp-len-err: <value in [drop, trap-to-host]>
               udp-plen-err: <value in [drop, trap-to-host]>
               udplite-cover-err: <value in [drop, trap-to-host]>
               udplite-csum-err: <value in [drop, trap-to-host]>
               unknproto-minlen-err: <value in [drop, trap-to-host]>
            gtp-enhanced-cpu-range: <value in [0, 1, 2]>
            gtp-enhanced-mode: <value in [disable, enable]>
            host-shortcut-mode: <value in [bi-directional, host-shortcut]>
            htx-gtse-quota: <value in [100Mbps, 200Mbps, 300Mbps, ...]>
            intf-shaping-offload: <value in [disable, enable]>
            iph-rsvd-re-cksum: <value in [disable, enable]>
            ipsec-dec-subengine-mask: <value of string>
            ipsec-enc-subengine-mask: <value of string>
            ipsec-inbound-cache: <value in [disable, enable]>
            ipsec-mtu-override: <value in [disable, enable]>
            ipsec-over-vlink: <value in [disable, enable]>
            isf-np-queues:
               cos0: <value of string>
               cos1: <value of string>
               cos2: <value of string>
               cos3: <value of string>
               cos4: <value of string>
               cos5: <value of string>
               cos6: <value of string>
               cos7: <value of string>
            lag-out-port-select: <value in [disable, enable]>
            mcast-session-accounting: <value in [disable, session-based, tpe-based]>
            np6-cps-optimization-mode: <value in [disable, enable]>
            per-session-accounting: <value in [enable, disable, enable-by-log, ...]>
            port-cpu-map:
              -
                  cpu-core: <value of string>
                  interface: <value of string>
            port-npu-map:
              -
                  interface: <value of string>
                  npu-group-index: <value of integer>
            priority-protocol:
               bfd: <value in [disable, enable]>
               bgp: <value in [disable, enable]>
               slbc: <value in [disable, enable]>
            qos-mode: <value in [disable, priority, round-robin]>
            rdp-offload: <value in [disable, enable]>
            recover-np6-link: <value in [disable, enable]>
            session-denied-offload: <value in [disable, enable]>
            sse-backpressure: <value in [disable, enable]>
            strip-clear-text-padding: <value in [disable, enable]>
            strip-esp-padding: <value in [disable, enable]>
            sw-eh-hash:
               computation: <value in [xor16, xor8, xor4, ...]>
               destination-ip-lower-16: <value in [include, exclude]>
               destination-ip-upper-16: <value in [include, exclude]>
               destination-port: <value in [include, exclude]>
               ip-protocol: <value in [include, exclude]>
               netmask-length: <value of integer>
               source-ip-lower-16: <value in [include, exclude]>
               source-ip-upper-16: <value in [include, exclude]>
               source-port: <value in [include, exclude]>
            sw-np-bandwidth: <value in [0G, 2G, 4G, ...]>
            switch-np-hash: <value in [src-ip, dst-ip, src-dst-ip]>
            uesp-offload: <value in [disable, enable]>

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
        '/pm/config/global/obj/system/npu',
        '/pm/config/adom/{adom}/obj/system/npu'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/system/npu/{npu}',
        '/pm/config/adom/{adom}/obj/system/npu/{npu}'
    ]

    url_params = ['adom']
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'system_npu': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.2.0': True
            },
            'options': {
                'capwap-offload': {
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
                'dedicated-management-affinity': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dedicated-management-cpu': {
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
                'fastpath': {
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
                'fp-anomaly': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'esp-minlen-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'icmp-csum-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'icmp-minlen-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'ipv4-csum-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'ipv4-ihl-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'ipv4-len-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'ipv4-opt-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'ipv4-ttlzero-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'ipv4-ver-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'ipv6-exthdr-len-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'ipv6-exthdr-order-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'ipv6-ihl-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'ipv6-plen-zero': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'ipv6-ver-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'tcp-csum-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'tcp-hlen-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'tcp-plen-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'udp-csum-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'udp-hlen-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'udp-len-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'udp-plen-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'udplite-cover-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'udplite-csum-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        },
                        'unknproto-minlen-err': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'drop',
                                'trap-to-host'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'gtp-enhanced-cpu-range': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        '0',
                        '1',
                        '2'
                    ],
                    'type': 'str'
                },
                'gtp-enhanced-mode': {
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
                'host-shortcut-mode': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'bi-directional',
                        'host-shortcut'
                    ],
                    'type': 'str'
                },
                'htx-gtse-quota': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        '100Mbps',
                        '200Mbps',
                        '300Mbps',
                        '400Mbps',
                        '500Mbps',
                        '600Mbps',
                        '700Mbps',
                        '800Mbps',
                        '900Mbps',
                        '1Gbps',
                        '2Gbps',
                        '4Gbps',
                        '8Gbps',
                        '10Gbps'
                    ],
                    'type': 'str'
                },
                'intf-shaping-offload': {
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
                'iph-rsvd-re-cksum': {
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
                'ipsec-dec-subengine-mask': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipsec-enc-subengine-mask': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipsec-inbound-cache': {
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
                'ipsec-mtu-override': {
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
                'ipsec-over-vlink': {
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
                'isf-np-queues': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'cos0': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'cos1': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'cos2': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'cos3': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'cos4': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'cos5': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'cos6': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'cos7': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'lag-out-port-select': {
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
                'mcast-session-accounting': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'session-based',
                        'tpe-based'
                    ],
                    'type': 'str'
                },
                'np6-cps-optimization-mode': {
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
                'per-session-accounting': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'enable',
                        'disable',
                        'enable-by-log',
                        'all-enable',
                        'traffic-log-only'
                    ],
                    'type': 'str'
                },
                'port-cpu-map': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'cpu-core': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'interface': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'port-npu-map': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'interface': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'npu-group-index': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'priority-protocol': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'bfd': {
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
                        'bgp': {
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
                        'slbc': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'qos-mode': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'priority',
                        'round-robin'
                    ],
                    'type': 'str'
                },
                'rdp-offload': {
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
                'recover-np6-link': {
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
                'session-denied-offload': {
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
                'sse-backpressure': {
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
                'strip-clear-text-padding': {
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
                'strip-esp-padding': {
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
                'sw-eh-hash': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'computation': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'xor16',
                                'xor8',
                                'xor4',
                                'crc16'
                            ],
                            'type': 'str'
                        },
                        'destination-ip-lower-16': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'include',
                                'exclude'
                            ],
                            'type': 'str'
                        },
                        'destination-ip-upper-16': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'include',
                                'exclude'
                            ],
                            'type': 'str'
                        },
                        'destination-port': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'include',
                                'exclude'
                            ],
                            'type': 'str'
                        },
                        'ip-protocol': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'include',
                                'exclude'
                            ],
                            'type': 'str'
                        },
                        'netmask-length': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'source-ip-lower-16': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'include',
                                'exclude'
                            ],
                            'type': 'str'
                        },
                        'source-ip-upper-16': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'include',
                                'exclude'
                            ],
                            'type': 'str'
                        },
                        'source-port': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'include',
                                'exclude'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'sw-np-bandwidth': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        '0G',
                        '2G',
                        '4G',
                        '5G',
                        '6G',
                        '7G',
                        '8G',
                        '9G'
                    ],
                    'type': 'str'
                },
                'switch-np-hash': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'src-ip',
                        'dst-ip',
                        'src-dst-ip'
                    ],
                    'type': 'str'
                },
                'uesp-offload': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu'),
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
