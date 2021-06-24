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
module: fmgr_switchcontroller_managedswitch_ports
short_description: Managed-switch port list.
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
    managed-switch:
        description: the parameter (managed-switch) in requested url
        type: str
        required: true
    switchcontroller_managedswitch_ports:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            allowed-vlans:
                type: str
                description: 'Configure switch port tagged vlans'
            allowed-vlans-all:
                type: str
                description: 'Enable/disable all defined vlans on this port.'
                choices:
                    - 'disable'
                    - 'enable'
            arp-inspection-trust:
                type: str
                description: 'Trusted or untrusted dynamic ARP inspection.'
                choices:
                    - 'untrusted'
                    - 'trusted'
            bundle:
                type: str
                description: 'Enable/disable Link Aggregation Group (LAG) bundling for non-FortiLink interfaces.'
                choices:
                    - 'disable'
                    - 'enable'
            description:
                type: str
                description: 'Description for port.'
            dhcp-snoop-option82-trust:
                type: str
                description: 'Enable/disable allowance of DHCP with option-82 on untrusted interface.'
                choices:
                    - 'disable'
                    - 'enable'
            dhcp-snooping:
                type: str
                description: 'Trusted or untrusted DHCP-snooping interface.'
                choices:
                    - 'trusted'
                    - 'untrusted'
            discard-mode:
                type: str
                description: 'Configure discard mode for port.'
                choices:
                    - 'none'
                    - 'all-untagged'
                    - 'all-tagged'
            edge-port:
                type: str
                description: 'Enable/disable this interface as an edge port, bridging connections between workstations and/or computers.'
                choices:
                    - 'disable'
                    - 'enable'
            igmp-snooping:
                type: str
                description: 'Set IGMP snooping mode for the physical port interface.'
                choices:
                    - 'disable'
                    - 'enable'
            igmps-flood-reports:
                type: str
                description: 'Enable/disable flooding of IGMP reports to this interface when igmp-snooping enabled.'
                choices:
                    - 'disable'
                    - 'enable'
            igmps-flood-traffic:
                type: str
                description: 'Enable/disable flooding of IGMP snooping traffic to this interface.'
                choices:
                    - 'disable'
                    - 'enable'
            lacp-speed:
                type: str
                description: 'end Link Aggregation Control Protocol (LACP) messages every 30 seconds (slow) or every second (fast).'
                choices:
                    - 'slow'
                    - 'fast'
            learning-limit:
                type: int
                description: 'Limit the number of dynamic MAC addresses on this Port (1 - 128, 0 = no limit, default).'
            lldp-profile:
                type: str
                description: 'LLDP port TLV profile.'
            lldp-status:
                type: str
                description: 'LLDP transmit and receive status.'
                choices:
                    - 'disable'
                    - 'rx-only'
                    - 'tx-only'
                    - 'tx-rx'
            loop-guard:
                type: str
                description: 'Enable/disable loop-guard on this interface, an STP optimization used to prevent network loops.'
                choices:
                    - 'disabled'
                    - 'enabled'
            loop-guard-timeout:
                type: int
                description: 'Loop-guard timeout (0 - 120 min, default = 45).'
            max-bundle:
                type: int
                description: 'Maximum size of LAG bundle (1 - 24, default = 24)'
            mclag:
                type: str
                description: 'Enable/disable multi-chassis link aggregation (MCLAG).'
                choices:
                    - 'disable'
                    - 'enable'
            member-withdrawal-behavior:
                type: str
                description: 'Port behavior after it withdraws because of loss of control packets.'
                choices:
                    - 'forward'
                    - 'block'
            members:
                description: no description
                type: str
            min-bundle:
                type: int
                description: 'Minimum size of LAG bundle (1 - 24, default = 1)'
            mode:
                type: str
                description: 'LACP mode: ignore and do not send control messages, or negotiate 802.3ad aggregation passively or actively.'
                choices:
                    - 'static'
                    - 'lacp-passive'
                    - 'lacp-active'
            poe-pre-standard-detection:
                type: str
                description: 'Enable/disable PoE pre-standard detection.'
                choices:
                    - 'disable'
                    - 'enable'
            poe-status:
                type: str
                description: 'Enable/disable PoE status.'
                choices:
                    - 'disable'
                    - 'enable'
            port-name:
                type: str
                description: 'Switch port name.'
            port-owner:
                type: str
                description: 'Switch port name.'
            port-security-policy:
                type: str
                description: 'Switch controller authentication policy to apply to this managed switch from available options.'
            port-selection-criteria:
                type: str
                description: 'Algorithm for aggregate port selection.'
                choices:
                    - 'src-mac'
                    - 'dst-mac'
                    - 'src-dst-mac'
                    - 'src-ip'
                    - 'dst-ip'
                    - 'src-dst-ip'
            qos-policy:
                type: str
                description: 'Switch controller QoS policy from available options.'
            sample-direction:
                type: str
                description: 'sFlow sample direction.'
                choices:
                    - 'rx'
                    - 'tx'
                    - 'both'
            sflow-counter-interval:
                type: int
                description: 'sFlow sampler counter polling interval (1 - 255 sec).'
            sflow-sample-rate:
                type: int
                description: 'sFlow sampler sample rate (0 - 99999 p/sec).'
            sflow-sampler:
                type: str
                description: 'Enable/disable sFlow protocol on this interface.'
                choices:
                    - 'disabled'
                    - 'enabled'
            stp-bpdu-guard:
                type: str
                description: 'Enable/disable STP BPDU guard on this interface.'
                choices:
                    - 'disabled'
                    - 'enabled'
            stp-bpdu-guard-timeout:
                type: int
                description: 'BPDU Guard disabling protection (0 - 120 min).'
            stp-root-guard:
                type: str
                description: 'Enable/disable STP root guard on this interface.'
                choices:
                    - 'disabled'
                    - 'enabled'
            stp-state:
                type: str
                description: 'Enable/disable Spanning Tree Protocol (STP) on this interface.'
                choices:
                    - 'disabled'
                    - 'enabled'
            type:
                type: str
                description: 'Interface type: physical or trunk port.'
                choices:
                    - 'physical'
                    - 'trunk'
            untagged-vlans:
                type: str
                description: 'Configure switch port untagged vlans'
            vlan:
                type: str
                description: 'Assign switch ports to a VLAN.'
            export-to-pool-flag:
                type: int
                description: 'Switch controller export port to pool-list.'
            mac-addr:
                type: str
                description: 'Port/Trunk MAC.'
            packet-sample-rate:
                type: int
                description: 'Packet sampling rate (0 - 99999 p/sec).'
            packet-sampler:
                type: str
                description: 'Enable/disable packet sampling on this interface.'
                choices:
                    - 'disabled'
                    - 'enabled'
            sticky-mac:
                type: str
                description: 'Enable or disable sticky-mac on the interface.'
                choices:
                    - 'disable'
                    - 'enable'
            storm-control-policy:
                type: str
                description: 'Switch controller storm control policy from available options.'
            access-mode:
                type: str
                description: 'Access mode of the port.'
                choices:
                    - 'normal'
                    - 'nac'
                    - 'dynamic'
                    - 'static'
            ip-source-guard:
                type: str
                description: 'Enable/disable IP source guard.'
                choices:
                    - 'disable'
                    - 'enable'
            mclag-icl-port:
                type: int
                description: no description
            p2p-port:
                type: int
                description: no description
            aggregator-mode:
                type: str
                description: 'LACP member select mode.'
                choices:
                    - 'bandwidth'
                    - 'count'
            rpvst-port:
                type: str
                description: 'Enable/disable inter-operability with rapid PVST on this interface.'
                choices:
                    - 'disabled'
                    - 'enabled'
            flow-control:
                type: str
                description: 'Flow control direction.'
                choices:
                    - 'disable'
                    - 'tx'
                    - 'rx'
                    - 'both'
            media-type:
                type: str
                description: no description
            pause-meter:
                type: int
                description: 'Configure ingress pause metering rate, in kbps (default = 0, disabled).'
            pause-meter-resume:
                type: str
                description: 'Resume threshold for resuming traffic on ingress port.'
                choices:
                    - '25%'
                    - '50%'
                    - '75%'
            trunk-member:
                type: int
                description: 'Trunk member.'
            fec-capable:
                type: int
                description: 'FEC capable.'
            fec-state:
                type: str
                description: 'State of forward error correction.'
                choices:
                    - 'disabled'
                    - 'cl74'
                    - 'cl91'
            matched-dpp-intf-tags:
                type: str
                description: 'Matched interface tags in the dynamic port policy.'
            matched-dpp-policy:
                type: str
                description: 'Matched child policy in the dynamic port policy.'
            port-policy:
                type: str
                description: 'Switch controller dynamic port policy from available options.'
            status:
                type: str
                description: 'Switch port admin status: up or down.'
                choices:
                    - 'down'
                    - 'up'

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
    - name: Managed-switch port list.
      fmgr_switchcontroller_managedswitch_ports:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         managed-switch: <your own value>
         state: <value in [present, absent]>
         switchcontroller_managedswitch_ports:
            allowed-vlans: <value of string>
            allowed-vlans-all: <value in [disable, enable]>
            arp-inspection-trust: <value in [untrusted, trusted]>
            bundle: <value in [disable, enable]>
            description: <value of string>
            dhcp-snoop-option82-trust: <value in [disable, enable]>
            dhcp-snooping: <value in [trusted, untrusted]>
            discard-mode: <value in [none, all-untagged, all-tagged]>
            edge-port: <value in [disable, enable]>
            igmp-snooping: <value in [disable, enable]>
            igmps-flood-reports: <value in [disable, enable]>
            igmps-flood-traffic: <value in [disable, enable]>
            lacp-speed: <value in [slow, fast]>
            learning-limit: <value of integer>
            lldp-profile: <value of string>
            lldp-status: <value in [disable, rx-only, tx-only, ...]>
            loop-guard: <value in [disabled, enabled]>
            loop-guard-timeout: <value of integer>
            max-bundle: <value of integer>
            mclag: <value in [disable, enable]>
            member-withdrawal-behavior: <value in [forward, block]>
            members: <value of string>
            min-bundle: <value of integer>
            mode: <value in [static, lacp-passive, lacp-active]>
            poe-pre-standard-detection: <value in [disable, enable]>
            poe-status: <value in [disable, enable]>
            port-name: <value of string>
            port-owner: <value of string>
            port-security-policy: <value of string>
            port-selection-criteria: <value in [src-mac, dst-mac, src-dst-mac, ...]>
            qos-policy: <value of string>
            sample-direction: <value in [rx, tx, both]>
            sflow-counter-interval: <value of integer>
            sflow-sample-rate: <value of integer>
            sflow-sampler: <value in [disabled, enabled]>
            stp-bpdu-guard: <value in [disabled, enabled]>
            stp-bpdu-guard-timeout: <value of integer>
            stp-root-guard: <value in [disabled, enabled]>
            stp-state: <value in [disabled, enabled]>
            type: <value in [physical, trunk]>
            untagged-vlans: <value of string>
            vlan: <value of string>
            export-to-pool-flag: <value of integer>
            mac-addr: <value of string>
            packet-sample-rate: <value of integer>
            packet-sampler: <value in [disabled, enabled]>
            sticky-mac: <value in [disable, enable]>
            storm-control-policy: <value of string>
            access-mode: <value in [normal, nac, dynamic, ...]>
            ip-source-guard: <value in [disable, enable]>
            mclag-icl-port: <value of integer>
            p2p-port: <value of integer>
            aggregator-mode: <value in [bandwidth, count]>
            rpvst-port: <value in [disabled, enabled]>
            flow-control: <value in [disable, tx, rx, ...]>
            media-type: <value of string>
            pause-meter: <value of integer>
            pause-meter-resume: <value in [25%, 50%, 75%]>
            trunk-member: <value of integer>
            fec-capable: <value of integer>
            fec-state: <value in [disabled, cl74, cl91]>
            matched-dpp-intf-tags: <value of string>
            matched-dpp-policy: <value of string>
            port-policy: <value of string>
            status: <value in [down, up]>

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
        '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports',
        '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}',
        '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}'
    ]

    url_params = ['adom', 'managed-switch']
    module_primary_key = 'port-name'
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
        'managed-switch': {
            'required': True,
            'type': 'str'
        },
        'switchcontroller_managedswitch_ports': {
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
                'allowed-vlans': {
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
                'allowed-vlans-all': {
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
                'arp-inspection-trust': {
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
                        'untrusted',
                        'trusted'
                    ],
                    'type': 'str'
                },
                'bundle': {
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
                'dhcp-snoop-option82-trust': {
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
                'dhcp-snooping': {
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
                        'trusted',
                        'untrusted'
                    ],
                    'type': 'str'
                },
                'discard-mode': {
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
                        'none',
                        'all-untagged',
                        'all-tagged'
                    ],
                    'type': 'str'
                },
                'edge-port': {
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
                'igmp-snooping': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
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
                'igmps-flood-reports': {
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
                'igmps-flood-traffic': {
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
                'lacp-speed': {
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
                        'slow',
                        'fast'
                    ],
                    'type': 'str'
                },
                'learning-limit': {
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
                'lldp-profile': {
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
                'lldp-status': {
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
                        'rx-only',
                        'tx-only',
                        'tx-rx'
                    ],
                    'type': 'str'
                },
                'loop-guard': {
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
                },
                'loop-guard-timeout': {
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
                'max-bundle': {
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
                'mclag': {
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
                'member-withdrawal-behavior': {
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
                        'forward',
                        'block'
                    ],
                    'type': 'str'
                },
                'members': {
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
                'min-bundle': {
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
                'mode': {
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
                        'static',
                        'lacp-passive',
                        'lacp-active'
                    ],
                    'type': 'str'
                },
                'poe-pre-standard-detection': {
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
                'poe-status': {
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
                'port-name': {
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
                'port-owner': {
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
                'port-security-policy': {
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
                'port-selection-criteria': {
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
                        'src-mac',
                        'dst-mac',
                        'src-dst-mac',
                        'src-ip',
                        'dst-ip',
                        'src-dst-ip'
                    ],
                    'type': 'str'
                },
                'qos-policy': {
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
                'sample-direction': {
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
                        'rx',
                        'tx',
                        'both'
                    ],
                    'type': 'str'
                },
                'sflow-counter-interval': {
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
                'sflow-sample-rate': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'sflow-sampler': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disabled',
                        'enabled'
                    ],
                    'type': 'str'
                },
                'stp-bpdu-guard': {
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
                },
                'stp-bpdu-guard-timeout': {
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
                'stp-root-guard': {
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
                },
                'stp-state': {
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
                },
                'type': {
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
                        'physical',
                        'trunk'
                    ],
                    'type': 'str'
                },
                'untagged-vlans': {
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
                'vlan': {
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
                'export-to-pool-flag': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'mac-addr': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'packet-sample-rate': {
                    'required': False,
                    'revision': {
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
                'packet-sampler': {
                    'required': False,
                    'revision': {
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
                },
                'sticky-mac': {
                    'required': False,
                    'revision': {
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
                'storm-control-policy': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'str'
                },
                'access-mode': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'normal',
                        'nac',
                        'dynamic',
                        'static'
                    ],
                    'type': 'str'
                },
                'ip-source-guard': {
                    'required': False,
                    'revision': {
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
                'mclag-icl-port': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'p2p-port': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'aggregator-mode': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'bandwidth',
                        'count'
                    ],
                    'type': 'str'
                },
                'rpvst-port': {
                    'required': False,
                    'revision': {
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disabled',
                        'enabled'
                    ],
                    'type': 'str'
                },
                'flow-control': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'tx',
                        'rx',
                        'both'
                    ],
                    'type': 'str'
                },
                'media-type': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'pause-meter': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'pause-meter-resume': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        '25%',
                        '50%',
                        '75%'
                    ],
                    'type': 'str'
                },
                'trunk-member': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'fec-capable': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'fec-state': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'disabled',
                        'cl74',
                        'cl91'
                    ],
                    'type': 'str'
                },
                'matched-dpp-intf-tags': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'matched-dpp-policy': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'port-policy': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'down',
                        'up'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_managedswitch_ports'),
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
