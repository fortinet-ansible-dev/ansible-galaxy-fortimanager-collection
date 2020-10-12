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
module: fmgr_pkg_firewall_policy6
short_description: Configure IPv6 policies.
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
    pkg:
        description: the parameter (pkg) in requested url
        type: str
        required: true
    pkg_firewall_policy6:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: 'Policy action (allow/deny/ipsec).'
                choices:
                    - 'deny'
                    - 'accept'
                    - 'ipsec'
                    - 'ssl-vpn'
            app-category:
                type: str
                description: 'Application category ID list.'
            application:
                description: no description
                type: int
            application-list:
                type: str
                description: 'Name of an existing Application list.'
            auto-asic-offload:
                type: str
                description: 'Enable/disable policy traffic ASIC offloading.'
                choices:
                    - 'disable'
                    - 'enable'
            av-profile:
                type: str
                description: 'Name of an existing Antivirus profile.'
            comments:
                type: str
                description: 'Comment.'
            custom-log-fields:
                type: str
                description: 'Log field index numbers to append custom log fields to log messages for this policy.'
            devices:
                type: str
                description: 'Names of devices or device groups that can be matched by the policy.'
            diffserv-forward:
                type: str
                description: 'Enable to change packets DiffServ values to the specified diffservcode-forward value.'
                choices:
                    - 'disable'
                    - 'enable'
            diffserv-reverse:
                type: str
                description: 'Enable to change packets reverse (reply) DiffServ values to the specified diffservcode-rev value.'
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode-forward:
                type: str
                description: 'Change packets DiffServ to this value.'
            diffservcode-rev:
                type: str
                description: 'Change packets reverse (reply) DiffServ to this value.'
            dlp-sensor:
                type: str
                description: 'Name of an existing DLP sensor.'
            dscp-match:
                type: str
                description: 'Enable DSCP check.'
                choices:
                    - 'disable'
                    - 'enable'
            dscp-negate:
                type: str
                description: 'Enable negated DSCP match.'
                choices:
                    - 'disable'
                    - 'enable'
            dscp-value:
                type: str
                description: 'DSCP value.'
            dsri:
                type: str
                description: 'Enable DSRI to ignore HTTP server responses.'
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: str
                description: 'Destination address and address group names.'
            dstaddr-negate:
                type: str
                description: 'When enabled dstaddr specifies what the destination address must NOT be.'
                choices:
                    - 'disable'
                    - 'enable'
            dstintf:
                type: str
                description: 'Outgoing (egress) interface.'
            firewall-session-dirty:
                type: str
                description: 'How to handle sessions if the configuration of this firewall policy changes.'
                choices:
                    - 'check-all'
                    - 'check-new'
            fixedport:
                type: str
                description: 'Enable to prevent source NAT from changing a sessions source port.'
                choices:
                    - 'disable'
                    - 'enable'
            global-label:
                type: str
                description: 'Label for the policy that appears when the GUI is in Global View mode.'
            groups:
                type: str
                description: 'Names of user groups that can authenticate with this policy.'
            icap-profile:
                type: str
                description: 'Name of an existing ICAP profile.'
            inbound:
                type: str
                description: 'Policy-based IPsec VPN: only traffic from the remote network can initiate a VPN.'
                choices:
                    - 'disable'
                    - 'enable'
            ippool:
                type: str
                description: 'Enable to use IP Pools for source NAT.'
                choices:
                    - 'disable'
                    - 'enable'
            ips-sensor:
                type: str
                description: 'Name of an existing IPS sensor.'
            label:
                type: str
                description: 'Label for the policy that appears when the GUI is in Section View mode.'
            logtraffic:
                type: str
                description: 'Enable or disable logging. Log all sessions or security profile sessions.'
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            logtraffic-start:
                type: str
                description: 'Record logs when a session starts and ends.'
                choices:
                    - 'disable'
                    - 'enable'
            mms-profile:
                type: str
                description: 'Name of an existing MMS profile.'
            name:
                type: str
                description: 'Policy name.'
            nat:
                type: str
                description: 'Enable/disable source NAT.'
                choices:
                    - 'disable'
                    - 'enable'
            natinbound:
                type: str
                description: 'Policy-based IPsec VPN: apply destination NAT to inbound traffic.'
                choices:
                    - 'disable'
                    - 'enable'
            natoutbound:
                type: str
                description: 'Policy-based IPsec VPN: apply source NAT to outbound traffic.'
                choices:
                    - 'disable'
                    - 'enable'
            np-accelation:
                type: str
                description: 'Enable/disable UTM Network Processor acceleration.'
                choices:
                    - 'disable'
                    - 'enable'
            outbound:
                type: str
                description: 'Policy-based IPsec VPN: only traffic from the internal network can initiate a VPN.'
                choices:
                    - 'disable'
                    - 'enable'
            per-ip-shaper:
                type: str
                description: 'Per-IP traffic shaper.'
            policyid:
                type: int
                description: 'Policy ID.'
            poolname:
                type: str
                description: 'IP Pool names.'
            profile-group:
                type: str
                description: 'Name of profile group.'
            profile-protocol-options:
                type: str
                description: 'Name of an existing Protocol options profile.'
            profile-type:
                type: str
                description: 'Determine whether the firewall policy allows security profile groups or single profiles only.'
                choices:
                    - 'single'
                    - 'group'
            replacemsg-override-group:
                type: str
                description: 'Override the default replacement message group for this policy.'
            rsso:
                type: str
                description: 'Enable/disable RADIUS single sign-on (RSSO).'
                choices:
                    - 'disable'
                    - 'enable'
            schedule:
                type: str
                description: 'Schedule name.'
            send-deny-packet:
                type: str
                description: 'Enable/disable return of deny-packet.'
                choices:
                    - 'disable'
                    - 'enable'
            service:
                type: str
                description: 'Service and service group names.'
            service-negate:
                type: str
                description: 'When enabled service specifies what the service must NOT be.'
                choices:
                    - 'disable'
                    - 'enable'
            session-ttl:
                type: int
                description: 'Session TTL in seconds for sessions accepted by this policy. 0 means use the system default session TTL.'
            spamfilter-profile:
                type: str
                description: 'Name of an existing Spam filter profile.'
            srcaddr:
                type: str
                description: 'Source address and address group names.'
            srcaddr-negate:
                type: str
                description: 'When enabled srcaddr specifies what the source address must NOT be.'
                choices:
                    - 'disable'
                    - 'enable'
            srcintf:
                type: str
                description: 'Incoming (ingress) interface.'
            ssl-mirror:
                type: str
                description: 'Enable to copy decrypted SSL traffic to a FortiGate interface (called SSL mirroring).'
                choices:
                    - 'disable'
                    - 'enable'
            ssl-mirror-intf:
                type: str
                description: 'SSL mirror interface name.'
            ssl-ssh-profile:
                type: str
                description: 'Name of an existing SSL SSH profile.'
            status:
                type: str
                description: 'Enable or disable this policy.'
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: str
                description: 'Names of object-tags applied to this policy.'
            tcp-mss-receiver:
                type: int
                description: 'Receiver TCP maximum segment size (MSS).'
            tcp-mss-sender:
                type: int
                description: 'Sender TCP maximum segment size (MSS).'
            tcp-session-without-syn:
                type: str
                description: 'Enable/disable creation of TCP session without SYN flag.'
                choices:
                    - 'all'
                    - 'data-only'
                    - 'disable'
            timeout-send-rst:
                type: str
                description: 'Enable/disable sending RST packets when TCP sessions expire.'
                choices:
                    - 'disable'
                    - 'enable'
            traffic-shaper:
                type: str
                description: 'Reverse traffic shaper.'
            traffic-shaper-reverse:
                type: str
                description: 'Reverse traffic shaper.'
            url-category:
                type: str
                description: 'URL category ID list.'
            users:
                type: str
                description: 'Names of individual users that can authenticate with this policy.'
            utm-status:
                type: str
                description: 'Enable AV/web/ips protection profile.'
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: 'Universally Unique Identifier (UUID; automatically assigned but can be manually reset).'
            vlan-cos-fwd:
                type: int
                description: 'VLAN forward direction user priority: 255 passthrough, 0 lowest, 7 highest'
            vlan-cos-rev:
                type: int
                description: 'VLAN reverse direction user priority: 255 passthrough, 0 lowest, 7 highest'
            voip-profile:
                type: str
                description: 'Name of an existing VoIP profile.'
            vpntunnel:
                type: str
                description: 'Policy-based IPsec VPN: name of the IPsec VPN Phase 1.'
            webfilter-profile:
                type: str
                description: 'Name of an existing Web filter profile.'

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
    - name: Configure IPv6 policies.
      fmgr_pkg_firewall_policy6:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         pkg: <your own value>
         state: <value in [present, absent]>
         pkg_firewall_policy6:
            action: <value in [deny, accept, ipsec, ...]>
            app-category: <value of string>
            application: <value of integer>
            application-list: <value of string>
            auto-asic-offload: <value in [disable, enable]>
            av-profile: <value of string>
            comments: <value of string>
            custom-log-fields: <value of string>
            devices: <value of string>
            diffserv-forward: <value in [disable, enable]>
            diffserv-reverse: <value in [disable, enable]>
            diffservcode-forward: <value of string>
            diffservcode-rev: <value of string>
            dlp-sensor: <value of string>
            dscp-match: <value in [disable, enable]>
            dscp-negate: <value in [disable, enable]>
            dscp-value: <value of string>
            dsri: <value in [disable, enable]>
            dstaddr: <value of string>
            dstaddr-negate: <value in [disable, enable]>
            dstintf: <value of string>
            firewall-session-dirty: <value in [check-all, check-new]>
            fixedport: <value in [disable, enable]>
            global-label: <value of string>
            groups: <value of string>
            icap-profile: <value of string>
            inbound: <value in [disable, enable]>
            ippool: <value in [disable, enable]>
            ips-sensor: <value of string>
            label: <value of string>
            logtraffic: <value in [disable, enable, all, ...]>
            logtraffic-start: <value in [disable, enable]>
            mms-profile: <value of string>
            name: <value of string>
            nat: <value in [disable, enable]>
            natinbound: <value in [disable, enable]>
            natoutbound: <value in [disable, enable]>
            np-accelation: <value in [disable, enable]>
            outbound: <value in [disable, enable]>
            per-ip-shaper: <value of string>
            policyid: <value of integer>
            poolname: <value of string>
            profile-group: <value of string>
            profile-protocol-options: <value of string>
            profile-type: <value in [single, group]>
            replacemsg-override-group: <value of string>
            rsso: <value in [disable, enable]>
            schedule: <value of string>
            send-deny-packet: <value in [disable, enable]>
            service: <value of string>
            service-negate: <value in [disable, enable]>
            session-ttl: <value of integer>
            spamfilter-profile: <value of string>
            srcaddr: <value of string>
            srcaddr-negate: <value in [disable, enable]>
            srcintf: <value of string>
            ssl-mirror: <value in [disable, enable]>
            ssl-mirror-intf: <value of string>
            ssl-ssh-profile: <value of string>
            status: <value in [disable, enable]>
            tags: <value of string>
            tcp-mss-receiver: <value of integer>
            tcp-mss-sender: <value of integer>
            tcp-session-without-syn: <value in [all, data-only, disable]>
            timeout-send-rst: <value in [disable, enable]>
            traffic-shaper: <value of string>
            traffic-shaper-reverse: <value of string>
            url-category: <value of string>
            users: <value of string>
            utm-status: <value in [disable, enable]>
            uuid: <value of string>
            vlan-cos-fwd: <value of integer>
            vlan-cos-rev: <value of integer>
            voip-profile: <value of string>
            vpntunnel: <value of string>
            webfilter-profile: <value of string>

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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy6'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy6/{policy6}'
    ]

    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
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
        'pkg': {
            'required': True,
            'type': 'str'
        },
        'pkg_firewall_policy6': {
            'required': False,
            'type': 'dict',
            'options': {
                'action': {
                    'required': False,
                    'choices': [
                        'deny',
                        'accept',
                        'ipsec',
                        'ssl-vpn'
                    ],
                    'type': 'str'
                },
                'app-category': {
                    'required': False,
                    'type': 'str'
                },
                'application': {
                    'required': False,
                    'type': 'int'
                },
                'application-list': {
                    'required': False,
                    'type': 'str'
                },
                'auto-asic-offload': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'av-profile': {
                    'required': False,
                    'type': 'str'
                },
                'comments': {
                    'required': False,
                    'type': 'str'
                },
                'custom-log-fields': {
                    'required': False,
                    'type': 'str'
                },
                'devices': {
                    'required': False,
                    'type': 'str'
                },
                'diffserv-forward': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'diffserv-reverse': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'diffservcode-forward': {
                    'required': False,
                    'type': 'str'
                },
                'diffservcode-rev': {
                    'required': False,
                    'type': 'str'
                },
                'dlp-sensor': {
                    'required': False,
                    'type': 'str'
                },
                'dscp-match': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dscp-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dscp-value': {
                    'required': False,
                    'type': 'str'
                },
                'dsri': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dstaddr': {
                    'required': False,
                    'type': 'str'
                },
                'dstaddr-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dstintf': {
                    'required': False,
                    'type': 'str'
                },
                'firewall-session-dirty': {
                    'required': False,
                    'choices': [
                        'check-all',
                        'check-new'
                    ],
                    'type': 'str'
                },
                'fixedport': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'global-label': {
                    'required': False,
                    'type': 'str'
                },
                'groups': {
                    'required': False,
                    'type': 'str'
                },
                'icap-profile': {
                    'required': False,
                    'type': 'str'
                },
                'inbound': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ippool': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ips-sensor': {
                    'required': False,
                    'type': 'str'
                },
                'label': {
                    'required': False,
                    'type': 'str'
                },
                'logtraffic': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable',
                        'all',
                        'utm'
                    ],
                    'type': 'str'
                },
                'logtraffic-start': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mms-profile': {
                    'required': False,
                    'type': 'str'
                },
                'name': {
                    'required': False,
                    'type': 'str'
                },
                'nat': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'natinbound': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'natoutbound': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'np-accelation': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'outbound': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'per-ip-shaper': {
                    'required': False,
                    'type': 'str'
                },
                'policyid': {
                    'required': True,
                    'type': 'int'
                },
                'poolname': {
                    'required': False,
                    'type': 'str'
                },
                'profile-group': {
                    'required': False,
                    'type': 'str'
                },
                'profile-protocol-options': {
                    'required': False,
                    'type': 'str'
                },
                'profile-type': {
                    'required': False,
                    'choices': [
                        'single',
                        'group'
                    ],
                    'type': 'str'
                },
                'replacemsg-override-group': {
                    'required': False,
                    'type': 'str'
                },
                'rsso': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'schedule': {
                    'required': False,
                    'type': 'str'
                },
                'send-deny-packet': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'service': {
                    'required': False,
                    'type': 'str'
                },
                'service-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'session-ttl': {
                    'required': False,
                    'type': 'int'
                },
                'spamfilter-profile': {
                    'required': False,
                    'type': 'str'
                },
                'srcaddr': {
                    'required': False,
                    'type': 'str'
                },
                'srcaddr-negate': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'srcintf': {
                    'required': False,
                    'type': 'str'
                },
                'ssl-mirror': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-mirror-intf': {
                    'required': False,
                    'type': 'str'
                },
                'ssl-ssh-profile': {
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
                'tags': {
                    'required': False,
                    'type': 'str'
                },
                'tcp-mss-receiver': {
                    'required': False,
                    'type': 'int'
                },
                'tcp-mss-sender': {
                    'required': False,
                    'type': 'int'
                },
                'tcp-session-without-syn': {
                    'required': False,
                    'choices': [
                        'all',
                        'data-only',
                        'disable'
                    ],
                    'type': 'str'
                },
                'timeout-send-rst': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'traffic-shaper': {
                    'required': False,
                    'type': 'str'
                },
                'traffic-shaper-reverse': {
                    'required': False,
                    'type': 'str'
                },
                'url-category': {
                    'required': False,
                    'type': 'str'
                },
                'users': {
                    'required': False,
                    'type': 'str'
                },
                'utm-status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'uuid': {
                    'required': False,
                    'type': 'str'
                },
                'vlan-cos-fwd': {
                    'required': False,
                    'type': 'int'
                },
                'vlan-cos-rev': {
                    'required': False,
                    'type': 'int'
                },
                'voip-profile': {
                    'required': False,
                    'type': 'str'
                },
                'vpntunnel': {
                    'required': False,
                    'type': 'str'
                },
                'webfilter-profile': {
                    'required': False,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_policy6'),
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
