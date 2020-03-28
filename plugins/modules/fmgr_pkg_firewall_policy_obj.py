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
module: fmgr_pkg_firewall_policy_obj
short_description: Configure IPv4 policies.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ clone delete get move set update ] the following apis.
    - /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}
    - Examples include all parameters and values need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Frank Shen (@fshen01)
    - Link Zheng (@zhengl)
notes:
    - There are only three top-level parameters where 'method' is always required
      while other two 'params' and 'url_params' can be optional
    - Due to the complexity of fortimanager api schema, the validation is done
      out of Ansible native parameter validation procedure.
    - The syntax of OPTIONS doen not comply with the standard Ansible argument
      specification, but with the structure of fortimanager API schema, we need
      a trivial transformation when we are filling the ansible playbook
options:
    url_params:
        description: the parameters in url path
        required: True
        type: dict
        suboptions:
            adom:
                type: str
                description: the domain prefix, the none and global are reserved
                choices:
                  - none
                  - global
                  - custom dom
            pkg:
                type: str
            policy:
                type: str
    schema_object0:
        methods: [clone, update]
        description: 'Configure IPv4 policies.'
        api_categories: [api_tag0]
        api_tag0:
            data:
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
                    -
                        type: int
                application-list:
                    type: str
                    description: 'Name of an existing Application list.'
                auth-cert:
                    type: str
                    description: 'HTTPS server certificate for policy authentication.'
                auth-path:
                    type: str
                    description: 'Enable/disable authentication-based routing.'
                    choices:
                        - 'disable'
                        - 'enable'
                auth-redirect-addr:
                    type: str
                    description: 'HTTP-to-HTTPS redirect address for firewall authentication.'
                auto-asic-offload:
                    type: str
                    description: 'Enable/disable offloading security profile processing to CP processors.'
                    choices:
                        - 'disable'
                        - 'enable'
                av-profile:
                    type: str
                    description: 'Name of an existing Antivirus profile.'
                block-notification:
                    type: str
                    description: 'Enable/disable block notification.'
                    choices:
                        - 'disable'
                        - 'enable'
                captive-portal-exempt:
                    type: str
                    description: 'Enable to exempt some users from the captive portal.'
                    choices:
                        - 'disable'
                        - 'enable'
                capture-packet:
                    type: str
                    description: 'Enable/disable capture packets.'
                    choices:
                        - 'disable'
                        - 'enable'
                comments:
                    type: str
                custom-log-fields:
                    type: str
                    description: 'Custom fields to append to log messages for this policy.'
                delay-tcp-npu-session:
                    type: str
                    description: 'Enable TCP NPU session delay to guarantee packet order of 3-way handshake.'
                    choices:
                        - 'disable'
                        - 'enable'
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
                disclaimer:
                    type: str
                    description: 'Enable/disable user authentication disclaimer.'
                    choices:
                        - 'disable'
                        - 'enable'
                dlp-sensor:
                    type: str
                    description: 'Name of an existing DLP sensor.'
                dnsfilter-profile:
                    type: str
                    description: 'Name of an existing DNS filter profile.'
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
                fsso:
                    type: str
                    description: 'Enable/disable Fortinet Single Sign-On.'
                    choices:
                        - 'disable'
                        - 'enable'
                fsso-agent-for-ntlm:
                    type: str
                    description: 'FSSO agent to use for NTLM authentication.'
                global-label:
                    type: str
                    description: 'Label for the policy that appears when the GUI is in Global View mode.'
                groups:
                    type: str
                    description: 'Names of user groups that can authenticate with this policy.'
                gtp-profile:
                    type: str
                    description: 'GTP profile.'
                icap-profile:
                    type: str
                    description: 'Name of an existing ICAP profile.'
                identity-based-route:
                    type: str
                    description: 'Name of identity-based routing rule.'
                inbound:
                    type: str
                    description: 'Policy-based IPsec VPN: only traffic from the remote network can initiate a VPN.'
                    choices:
                        - 'disable'
                        - 'enable'
                internet-service:
                    type: str
                    description: 'Enable/disable use of Internet Services for this policy. If enabled, destination address and service are not used.'
                    choices:
                        - 'disable'
                        - 'enable'
                internet-service-custom:
                    type: str
                    description: 'Custom Internet Service Name.'
                internet-service-id:
                    type: str
                    description: 'Internet Service ID.'
                internet-service-negate:
                    type: str
                    description: 'When enabled internet-service specifies what the service must NOT be.'
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
                learning-mode:
                    type: str
                    description: 'Enable to allow everything, but log all of the meaningful data for security information gathering. A learning report will ...'
                    choices:
                        - 'disable'
                        - 'enable'
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
                match-vip:
                    type: str
                    description: 'Enable to match packets that have had their destination addresses changed by a VIP.'
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
                natip:
                    type: str
                    description: 'Policy-based IPsec VPN: source NAT IP address for outgoing traffic.'
                natoutbound:
                    type: str
                    description: 'Policy-based IPsec VPN: apply source NAT to outbound traffic.'
                    choices:
                        - 'disable'
                        - 'enable'
                ntlm:
                    type: str
                    description: 'Enable/disable NTLM authentication.'
                    choices:
                        - 'disable'
                        - 'enable'
                ntlm-enabled-browsers:
                    -
                        type: str
                ntlm-guest:
                    type: str
                    description: 'Enable/disable NTLM guest user access.'
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
                permit-any-host:
                    type: str
                    description: 'Accept UDP packets from any host.'
                    choices:
                        - 'disable'
                        - 'enable'
                permit-stun-host:
                    type: str
                    description: 'Accept UDP packets from any Session Traversal Utilities for NAT (STUN) host.'
                    choices:
                        - 'disable'
                        - 'enable'
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
                radius-mac-auth-bypass:
                    type: str
                    description: 'Enable MAC authentication bypass. The bypassed MAC address must be received from RADIUS server.'
                    choices:
                        - 'disable'
                        - 'enable'
                redirect-url:
                    type: str
                    description: 'URL users are directed to after seeing and accepting the disclaimer or authenticating.'
                replacemsg-override-group:
                    type: str
                    description: 'Override the default replacement message group for this policy.'
                rsso:
                    type: str
                    description: 'Enable/disable RADIUS single sign-on (RSSO).'
                    choices:
                        - 'disable'
                        - 'enable'
                rtp-addr:
                    type: str
                    description: 'Address names if this is an RTP NAT policy.'
                rtp-nat:
                    type: str
                    description: 'Enable Real Time Protocol (RTP) NAT.'
                    choices:
                        - 'disable'
                        - 'enable'
                scan-botnet-connections:
                    type: str
                    description: 'Block or monitor connections to Botnet servers or disable Botnet scanning.'
                    choices:
                        - 'disable'
                        - 'block'
                        - 'monitor'
                schedule:
                    type: str
                    description: 'Schedule name.'
                schedule-timeout:
                    type: str
                    description: 'Enable to force current sessions to end when the schedule object times out. Disable allows them to end from inactivity.'
                    choices:
                        - 'disable'
                        - 'enable'
                send-deny-packet:
                    type: str
                    description: 'Enable to send a reply when a session is denied or blocked by a firewall policy.'
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
                    description: 'Traffic shaper.'
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
                    description: 'Enable to add one or more security profiles (AV, IPS, etc.) to the firewall policy.'
                    choices:
                        - 'disable'
                        - 'enable'
                uuid:
                    type: str
                    description: 'Universally Unique Identifier (UUID; automatically assigned but can be manually reset).'
                vlan-cos-fwd:
                    type: int
                    description: 'VLAN forward direction user priority: 255 passthrough, 0 lowest, 7 highest.'
                vlan-cos-rev:
                    type: int
                    description: 'VLAN reverse direction user priority: 255 passthrough, 0 lowest, 7 highest..'
                voip-profile:
                    type: str
                    description: 'Name of an existing VoIP profile.'
                vpn_dst_node:
                    -
                        host:
                            type: str
                        seq:
                            type: int
                        subnet:
                            type: str
                vpn_src_node:
                    -
                        host:
                            type: str
                        seq:
                            type: int
                        subnet:
                            type: str
                vpntunnel:
                    type: str
                    description: 'Policy-based IPsec VPN: name of the IPsec VPN Phase 1.'
                waf-profile:
                    type: str
                    description: 'Name of an existing Web application firewall profile.'
                wanopt:
                    type: str
                    description: 'Enable/disable WAN optimization.'
                    choices:
                        - 'disable'
                        - 'enable'
                wanopt-detection:
                    type: str
                    description: 'WAN optimization auto-detection mode.'
                    choices:
                        - 'active'
                        - 'passive'
                        - 'off'
                wanopt-passive-opt:
                    type: str
                    description: 'WAN optimization passive mode options. This option decides what IP address will be used to connect server.'
                    choices:
                        - 'default'
                        - 'transparent'
                        - 'non-transparent'
                wanopt-peer:
                    type: str
                    description: 'WAN optimization peer.'
                wanopt-profile:
                    type: str
                    description: 'WAN optimization profile.'
                wccp:
                    type: str
                    description: 'Enable/disable forwarding traffic matching this policy to a configured WCCP server.'
                    choices:
                        - 'disable'
                        - 'enable'
                webcache:
                    type: str
                    description: 'Enable/disable web cache.'
                    choices:
                        - 'disable'
                        - 'enable'
                webcache-https:
                    type: str
                    description: 'Enable/disable web cache for HTTPS.'
                    choices:
                        - 'disable'
                        - 'ssl-server'
                        - 'any'
                        - 'enable'
                webfilter-profile:
                    type: str
                    description: 'Name of an existing Web filter profile.'
                wsso:
                    type: str
                    description: 'Enable/disable WiFi Single Sign On (WSSO).'
                    choices:
                        - 'disable'
                        - 'enable'
    schema_object1:
        methods: [delete]
        description: 'Configure IPv4 policies.'
        api_categories: [api_tag0, api_tag1]
        api_tag0:
        api_tag1:
            data:
                attr:
                    type: str
                    choices:
                        - 'label'
                        - 'global-label'
                name:
                    type: str
    schema_object2:
        methods: [get]
        description: 'Configure IPv4 policies.'
        api_categories: [api_tag0]
        api_tag0:
            option:
                type: str
                description:
                 - 'Set fetch option for the request. If no option is specified, by default the attributes of the object will be returned.'
                 - 'object member - Return a list of object members along with other attributes.'
                 - 'chksum - Return the check-sum value instead of attributes.'
                choices:
                    - 'object member'
                    - 'chksum'
                    - 'datasrc'
    schema_object3:
        methods: [move]
        description: 'Configure IPv4 policies.'
        api_categories: [api_tag0]
        api_tag0:
            option:
                type: str
                choices:
                    - 'before'
                    - 'after'
            target:
                type: str
                description: 'Key to the target entry.'
    schema_object4:
        methods: [set]
        description: 'Configure IPv4 policies.'
        api_categories: [api_tag0, api_tag1]
        api_tag0:
            data:
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
                    -
                        type: int
                application-list:
                    type: str
                    description: 'Name of an existing Application list.'
                auth-cert:
                    type: str
                    description: 'HTTPS server certificate for policy authentication.'
                auth-path:
                    type: str
                    description: 'Enable/disable authentication-based routing.'
                    choices:
                        - 'disable'
                        - 'enable'
                auth-redirect-addr:
                    type: str
                    description: 'HTTP-to-HTTPS redirect address for firewall authentication.'
                auto-asic-offload:
                    type: str
                    description: 'Enable/disable offloading security profile processing to CP processors.'
                    choices:
                        - 'disable'
                        - 'enable'
                av-profile:
                    type: str
                    description: 'Name of an existing Antivirus profile.'
                block-notification:
                    type: str
                    description: 'Enable/disable block notification.'
                    choices:
                        - 'disable'
                        - 'enable'
                captive-portal-exempt:
                    type: str
                    description: 'Enable to exempt some users from the captive portal.'
                    choices:
                        - 'disable'
                        - 'enable'
                capture-packet:
                    type: str
                    description: 'Enable/disable capture packets.'
                    choices:
                        - 'disable'
                        - 'enable'
                comments:
                    type: str
                custom-log-fields:
                    type: str
                    description: 'Custom fields to append to log messages for this policy.'
                delay-tcp-npu-session:
                    type: str
                    description: 'Enable TCP NPU session delay to guarantee packet order of 3-way handshake.'
                    choices:
                        - 'disable'
                        - 'enable'
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
                disclaimer:
                    type: str
                    description: 'Enable/disable user authentication disclaimer.'
                    choices:
                        - 'disable'
                        - 'enable'
                dlp-sensor:
                    type: str
                    description: 'Name of an existing DLP sensor.'
                dnsfilter-profile:
                    type: str
                    description: 'Name of an existing DNS filter profile.'
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
                fsso:
                    type: str
                    description: 'Enable/disable Fortinet Single Sign-On.'
                    choices:
                        - 'disable'
                        - 'enable'
                fsso-agent-for-ntlm:
                    type: str
                    description: 'FSSO agent to use for NTLM authentication.'
                global-label:
                    type: str
                    description: 'Label for the policy that appears when the GUI is in Global View mode.'
                groups:
                    type: str
                    description: 'Names of user groups that can authenticate with this policy.'
                gtp-profile:
                    type: str
                    description: 'GTP profile.'
                icap-profile:
                    type: str
                    description: 'Name of an existing ICAP profile.'
                identity-based-route:
                    type: str
                    description: 'Name of identity-based routing rule.'
                inbound:
                    type: str
                    description: 'Policy-based IPsec VPN: only traffic from the remote network can initiate a VPN.'
                    choices:
                        - 'disable'
                        - 'enable'
                internet-service:
                    type: str
                    description: 'Enable/disable use of Internet Services for this policy. If enabled, destination address and service are not used.'
                    choices:
                        - 'disable'
                        - 'enable'
                internet-service-custom:
                    type: str
                    description: 'Custom Internet Service Name.'
                internet-service-id:
                    type: str
                    description: 'Internet Service ID.'
                internet-service-negate:
                    type: str
                    description: 'When enabled internet-service specifies what the service must NOT be.'
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
                learning-mode:
                    type: str
                    description: 'Enable to allow everything, but log all of the meaningful data for security information gathering. A learning report will ...'
                    choices:
                        - 'disable'
                        - 'enable'
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
                match-vip:
                    type: str
                    description: 'Enable to match packets that have had their destination addresses changed by a VIP.'
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
                natip:
                    type: str
                    description: 'Policy-based IPsec VPN: source NAT IP address for outgoing traffic.'
                natoutbound:
                    type: str
                    description: 'Policy-based IPsec VPN: apply source NAT to outbound traffic.'
                    choices:
                        - 'disable'
                        - 'enable'
                ntlm:
                    type: str
                    description: 'Enable/disable NTLM authentication.'
                    choices:
                        - 'disable'
                        - 'enable'
                ntlm-enabled-browsers:
                    -
                        type: str
                ntlm-guest:
                    type: str
                    description: 'Enable/disable NTLM guest user access.'
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
                permit-any-host:
                    type: str
                    description: 'Accept UDP packets from any host.'
                    choices:
                        - 'disable'
                        - 'enable'
                permit-stun-host:
                    type: str
                    description: 'Accept UDP packets from any Session Traversal Utilities for NAT (STUN) host.'
                    choices:
                        - 'disable'
                        - 'enable'
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
                radius-mac-auth-bypass:
                    type: str
                    description: 'Enable MAC authentication bypass. The bypassed MAC address must be received from RADIUS server.'
                    choices:
                        - 'disable'
                        - 'enable'
                redirect-url:
                    type: str
                    description: 'URL users are directed to after seeing and accepting the disclaimer or authenticating.'
                replacemsg-override-group:
                    type: str
                    description: 'Override the default replacement message group for this policy.'
                rsso:
                    type: str
                    description: 'Enable/disable RADIUS single sign-on (RSSO).'
                    choices:
                        - 'disable'
                        - 'enable'
                rtp-addr:
                    type: str
                    description: 'Address names if this is an RTP NAT policy.'
                rtp-nat:
                    type: str
                    description: 'Enable Real Time Protocol (RTP) NAT.'
                    choices:
                        - 'disable'
                        - 'enable'
                scan-botnet-connections:
                    type: str
                    description: 'Block or monitor connections to Botnet servers or disable Botnet scanning.'
                    choices:
                        - 'disable'
                        - 'block'
                        - 'monitor'
                schedule:
                    type: str
                    description: 'Schedule name.'
                schedule-timeout:
                    type: str
                    description: 'Enable to force current sessions to end when the schedule object times out. Disable allows them to end from inactivity.'
                    choices:
                        - 'disable'
                        - 'enable'
                send-deny-packet:
                    type: str
                    description: 'Enable to send a reply when a session is denied or blocked by a firewall policy.'
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
                    description: 'Traffic shaper.'
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
                    description: 'Enable to add one or more security profiles (AV, IPS, etc.) to the firewall policy.'
                    choices:
                        - 'disable'
                        - 'enable'
                uuid:
                    type: str
                    description: 'Universally Unique Identifier (UUID; automatically assigned but can be manually reset).'
                vlan-cos-fwd:
                    type: int
                    description: 'VLAN forward direction user priority: 255 passthrough, 0 lowest, 7 highest.'
                vlan-cos-rev:
                    type: int
                    description: 'VLAN reverse direction user priority: 255 passthrough, 0 lowest, 7 highest..'
                voip-profile:
                    type: str
                    description: 'Name of an existing VoIP profile.'
                vpn_dst_node:
                    -
                        host:
                            type: str
                        seq:
                            type: int
                        subnet:
                            type: str
                vpn_src_node:
                    -
                        host:
                            type: str
                        seq:
                            type: int
                        subnet:
                            type: str
                vpntunnel:
                    type: str
                    description: 'Policy-based IPsec VPN: name of the IPsec VPN Phase 1.'
                waf-profile:
                    type: str
                    description: 'Name of an existing Web application firewall profile.'
                wanopt:
                    type: str
                    description: 'Enable/disable WAN optimization.'
                    choices:
                        - 'disable'
                        - 'enable'
                wanopt-detection:
                    type: str
                    description: 'WAN optimization auto-detection mode.'
                    choices:
                        - 'active'
                        - 'passive'
                        - 'off'
                wanopt-passive-opt:
                    type: str
                    description: 'WAN optimization passive mode options. This option decides what IP address will be used to connect server.'
                    choices:
                        - 'default'
                        - 'transparent'
                        - 'non-transparent'
                wanopt-peer:
                    type: str
                    description: 'WAN optimization peer.'
                wanopt-profile:
                    type: str
                    description: 'WAN optimization profile.'
                wccp:
                    type: str
                    description: 'Enable/disable forwarding traffic matching this policy to a configured WCCP server.'
                    choices:
                        - 'disable'
                        - 'enable'
                webcache:
                    type: str
                    description: 'Enable/disable web cache.'
                    choices:
                        - 'disable'
                        - 'enable'
                webcache-https:
                    type: str
                    description: 'Enable/disable web cache for HTTPS.'
                    choices:
                        - 'disable'
                        - 'ssl-server'
                        - 'any'
                        - 'enable'
                webfilter-profile:
                    type: str
                    description: 'Name of an existing Web filter profile.'
                wsso:
                    type: str
                    description: 'Enable/disable WiFi Single Sign On (WSSO).'
                    choices:
                        - 'disable'
                        - 'enable'
        api_tag1:
            data:
                attr:
                    type: str
                    choices:
                        - 'label'
                        - 'global-label'
                name:
                    type: str

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

    - name: REQUESTING /PM/CONFIG/PKG/{PKG}/FIREWALL/POLICY/{POLICY}
      fmgr_pkg_firewall_policy_obj:
         method: <value in [clone, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            pkg: <value of string>
            policy: <value of string>
         params:
            -
               data:
                  action: <value in [deny, accept, ipsec, ...]>
                  app-category: <value of string>
                  application:
                    - <value of integer>
                  application-list: <value of string>
                  auth-cert: <value of string>
                  auth-path: <value in [disable, enable]>
                  auth-redirect-addr: <value of string>
                  auto-asic-offload: <value in [disable, enable]>
                  av-profile: <value of string>
                  block-notification: <value in [disable, enable]>
                  captive-portal-exempt: <value in [disable, enable]>
                  capture-packet: <value in [disable, enable]>
                  comments: <value of string>
                  custom-log-fields: <value of string>
                  delay-tcp-npu-session: <value in [disable, enable]>
                  devices: <value of string>
                  diffserv-forward: <value in [disable, enable]>
                  diffserv-reverse: <value in [disable, enable]>
                  diffservcode-forward: <value of string>
                  diffservcode-rev: <value of string>
                  disclaimer: <value in [disable, enable]>
                  dlp-sensor: <value of string>
                  dnsfilter-profile: <value of string>
                  dscp-match: <value in [disable, enable]>
                  dscp-negate: <value in [disable, enable]>
                  dscp-value: <value of string>
                  dsri: <value in [disable, enable]>
                  dstaddr: <value of string>
                  dstaddr-negate: <value in [disable, enable]>
                  dstintf: <value of string>
                  firewall-session-dirty: <value in [check-all, check-new]>
                  fixedport: <value in [disable, enable]>
                  fsso: <value in [disable, enable]>
                  fsso-agent-for-ntlm: <value of string>
                  global-label: <value of string>
                  groups: <value of string>
                  gtp-profile: <value of string>
                  icap-profile: <value of string>
                  identity-based-route: <value of string>
                  inbound: <value in [disable, enable]>
                  internet-service: <value in [disable, enable]>
                  internet-service-custom: <value of string>
                  internet-service-id: <value of string>
                  internet-service-negate: <value in [disable, enable]>
                  ippool: <value in [disable, enable]>
                  ips-sensor: <value of string>
                  label: <value of string>
                  learning-mode: <value in [disable, enable]>
                  logtraffic: <value in [disable, enable, all, ...]>
                  logtraffic-start: <value in [disable, enable]>
                  match-vip: <value in [disable, enable]>
                  mms-profile: <value of string>
                  name: <value of string>
                  nat: <value in [disable, enable]>
                  natinbound: <value in [disable, enable]>
                  natip: <value of string>
                  natoutbound: <value in [disable, enable]>
                  ntlm: <value in [disable, enable]>
                  ntlm-enabled-browsers:
                    - <value of string>
                  ntlm-guest: <value in [disable, enable]>
                  outbound: <value in [disable, enable]>
                  per-ip-shaper: <value of string>
                  permit-any-host: <value in [disable, enable]>
                  permit-stun-host: <value in [disable, enable]>
                  policyid: <value of integer>
                  poolname: <value of string>
                  profile-group: <value of string>
                  profile-protocol-options: <value of string>
                  profile-type: <value in [single, group]>
                  radius-mac-auth-bypass: <value in [disable, enable]>
                  redirect-url: <value of string>
                  replacemsg-override-group: <value of string>
                  rsso: <value in [disable, enable]>
                  rtp-addr: <value of string>
                  rtp-nat: <value in [disable, enable]>
                  scan-botnet-connections: <value in [disable, block, monitor]>
                  schedule: <value of string>
                  schedule-timeout: <value in [disable, enable]>
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
                  vpn_dst_node:
                    -
                        host: <value of string>
                        seq: <value of integer>
                        subnet: <value of string>
                  vpn_src_node:
                    -
                        host: <value of string>
                        seq: <value of integer>
                        subnet: <value of string>
                  vpntunnel: <value of string>
                  waf-profile: <value of string>
                  wanopt: <value in [disable, enable]>
                  wanopt-detection: <value in [active, passive, off]>
                  wanopt-passive-opt: <value in [default, transparent, non-transparent]>
                  wanopt-peer: <value of string>
                  wanopt-profile: <value of string>
                  wccp: <value in [disable, enable]>
                  webcache: <value in [disable, enable]>
                  webcache-https: <value in [disable, ssl-server, any, ...]>
                  webfilter-profile: <value of string>
                  wsso: <value in [disable, enable]>

    - name: REQUESTING /PM/CONFIG/PKG/{PKG}/FIREWALL/POLICY/{POLICY}
      fmgr_pkg_firewall_policy_obj:
         method: <value in [delete]>
         url_params:
            adom: <value in [none, global, custom dom]>
            pkg: <value of string>
            policy: <value of string>
         params:
            -
               data:
                  attr: <value in [label, global-label]>
                  name: <value of string>

    - name: REQUESTING /PM/CONFIG/PKG/{PKG}/FIREWALL/POLICY/{POLICY}
      fmgr_pkg_firewall_policy_obj:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            pkg: <value of string>
            policy: <value of string>
         params:
            -
               option: <value in [object member, chksum, datasrc]>

    - name: REQUESTING /PM/CONFIG/PKG/{PKG}/FIREWALL/POLICY/{POLICY}
      fmgr_pkg_firewall_policy_obj:
         method: <value in [move]>
         url_params:
            adom: <value in [none, global, custom dom]>
            pkg: <value of string>
            policy: <value of string>
         params:
            -
               option: <value in [before, after]>
               target: <value of string>

    - name: REQUESTING /PM/CONFIG/PKG/{PKG}/FIREWALL/POLICY/{POLICY}
      fmgr_pkg_firewall_policy_obj:
         method: <value in [set]>
         url_params:
            adom: <value in [none, global, custom dom]>
            pkg: <value of string>
            policy: <value of string>
         params:
            -
               data:
                  action: <value in [deny, accept, ipsec, ...]>
                  app-category: <value of string>
                  application:
                    - <value of integer>
                  application-list: <value of string>
                  auth-cert: <value of string>
                  auth-path: <value in [disable, enable]>
                  auth-redirect-addr: <value of string>
                  auto-asic-offload: <value in [disable, enable]>
                  av-profile: <value of string>
                  block-notification: <value in [disable, enable]>
                  captive-portal-exempt: <value in [disable, enable]>
                  capture-packet: <value in [disable, enable]>
                  comments: <value of string>
                  custom-log-fields: <value of string>
                  delay-tcp-npu-session: <value in [disable, enable]>
                  devices: <value of string>
                  diffserv-forward: <value in [disable, enable]>
                  diffserv-reverse: <value in [disable, enable]>
                  diffservcode-forward: <value of string>
                  diffservcode-rev: <value of string>
                  disclaimer: <value in [disable, enable]>
                  dlp-sensor: <value of string>
                  dnsfilter-profile: <value of string>
                  dscp-match: <value in [disable, enable]>
                  dscp-negate: <value in [disable, enable]>
                  dscp-value: <value of string>
                  dsri: <value in [disable, enable]>
                  dstaddr: <value of string>
                  dstaddr-negate: <value in [disable, enable]>
                  dstintf: <value of string>
                  firewall-session-dirty: <value in [check-all, check-new]>
                  fixedport: <value in [disable, enable]>
                  fsso: <value in [disable, enable]>
                  fsso-agent-for-ntlm: <value of string>
                  global-label: <value of string>
                  groups: <value of string>
                  gtp-profile: <value of string>
                  icap-profile: <value of string>
                  identity-based-route: <value of string>
                  inbound: <value in [disable, enable]>
                  internet-service: <value in [disable, enable]>
                  internet-service-custom: <value of string>
                  internet-service-id: <value of string>
                  internet-service-negate: <value in [disable, enable]>
                  ippool: <value in [disable, enable]>
                  ips-sensor: <value of string>
                  label: <value of string>
                  learning-mode: <value in [disable, enable]>
                  logtraffic: <value in [disable, enable, all, ...]>
                  logtraffic-start: <value in [disable, enable]>
                  match-vip: <value in [disable, enable]>
                  mms-profile: <value of string>
                  name: <value of string>
                  nat: <value in [disable, enable]>
                  natinbound: <value in [disable, enable]>
                  natip: <value of string>
                  natoutbound: <value in [disable, enable]>
                  ntlm: <value in [disable, enable]>
                  ntlm-enabled-browsers:
                    - <value of string>
                  ntlm-guest: <value in [disable, enable]>
                  outbound: <value in [disable, enable]>
                  per-ip-shaper: <value of string>
                  permit-any-host: <value in [disable, enable]>
                  permit-stun-host: <value in [disable, enable]>
                  policyid: <value of integer>
                  poolname: <value of string>
                  profile-group: <value of string>
                  profile-protocol-options: <value of string>
                  profile-type: <value in [single, group]>
                  radius-mac-auth-bypass: <value in [disable, enable]>
                  redirect-url: <value of string>
                  replacemsg-override-group: <value of string>
                  rsso: <value in [disable, enable]>
                  rtp-addr: <value of string>
                  rtp-nat: <value in [disable, enable]>
                  scan-botnet-connections: <value in [disable, block, monitor]>
                  schedule: <value of string>
                  schedule-timeout: <value in [disable, enable]>
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
                  vpn_dst_node:
                    -
                        host: <value of string>
                        seq: <value of integer>
                        subnet: <value of string>
                  vpn_src_node:
                    -
                        host: <value of string>
                        seq: <value of integer>
                        subnet: <value of string>
                  vpntunnel: <value of string>
                  waf-profile: <value of string>
                  wanopt: <value in [disable, enable]>
                  wanopt-detection: <value in [active, passive, off]>
                  wanopt-passive-opt: <value in [default, transparent, non-transparent]>
                  wanopt-peer: <value of string>
                  wanopt-profile: <value of string>
                  wccp: <value in [disable, enable]>
                  webcache: <value in [disable, enable]>
                  webcache-https: <value in [disable, ssl-server, any, ...]>
                  webfilter-profile: <value of string>
                  wsso: <value in [disable, enable]>

    - name: REQUESTING /PM/CONFIG/PKG/{PKG}/FIREWALL/POLICY/{POLICY}
      fmgr_pkg_firewall_policy_obj:
         method: <value in [set]>
         url_params:
            adom: <value in [none, global, custom dom]>
            pkg: <value of string>
            policy: <value of string>
         params:
            -
               data:
                  attr: <value in [label, global-label]>
                  name: <value of string>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[clone, move, update]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            policyid:
               type: int
               description: 'Policy ID.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'
return_of_api_category_0:
   description: items returned for method:[delete]
   returned: always
   suboptions:
      id:
         type: int
      result:
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'
return_of_api_category_1:
   description: items returned for method:[delete]
   returned: always
   suboptions:
      id:
         type: int
      result:
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            action:
               type: str
               description: 'Policy action (allow/deny/ipsec).'
            app-category:
               type: str
               description: 'Application category ID list.'
            application:
               type: array
               suboptions:
                  type: int
            application-list:
               type: str
               description: 'Name of an existing Application list.'
            auth-cert:
               type: str
               description: 'HTTPS server certificate for policy authentication.'
            auth-path:
               type: str
               description: 'Enable/disable authentication-based routing.'
            auth-redirect-addr:
               type: str
               description: 'HTTP-to-HTTPS redirect address for firewall authentication.'
            auto-asic-offload:
               type: str
               description: 'Enable/disable offloading security profile processing to CP processors.'
            av-profile:
               type: str
               description: 'Name of an existing Antivirus profile.'
            block-notification:
               type: str
               description: 'Enable/disable block notification.'
            captive-portal-exempt:
               type: str
               description: 'Enable to exempt some users from the captive portal.'
            capture-packet:
               type: str
               description: 'Enable/disable capture packets.'
            comments:
               type: str
            custom-log-fields:
               type: str
               description: 'Custom fields to append to log messages for this policy.'
            delay-tcp-npu-session:
               type: str
               description: 'Enable TCP NPU session delay to guarantee packet order of 3-way handshake.'
            devices:
               type: str
               description: 'Names of devices or device groups that can be matched by the policy.'
            diffserv-forward:
               type: str
               description: 'Enable to change packets DiffServ values to the specified diffservcode-forward value.'
            diffserv-reverse:
               type: str
               description: 'Enable to change packets reverse (reply) DiffServ values to the specified diffservcode-rev value.'
            diffservcode-forward:
               type: str
               description: 'Change packets DiffServ to this value.'
            diffservcode-rev:
               type: str
               description: 'Change packets reverse (reply) DiffServ to this value.'
            disclaimer:
               type: str
               description: 'Enable/disable user authentication disclaimer.'
            dlp-sensor:
               type: str
               description: 'Name of an existing DLP sensor.'
            dnsfilter-profile:
               type: str
               description: 'Name of an existing DNS filter profile.'
            dscp-match:
               type: str
               description: 'Enable DSCP check.'
            dscp-negate:
               type: str
               description: 'Enable negated DSCP match.'
            dscp-value:
               type: str
               description: 'DSCP value.'
            dsri:
               type: str
               description: 'Enable DSRI to ignore HTTP server responses.'
            dstaddr:
               type: str
               description: 'Destination address and address group names.'
            dstaddr-negate:
               type: str
               description: 'When enabled dstaddr specifies what the destination address must NOT be.'
            dstintf:
               type: str
               description: 'Outgoing (egress) interface.'
            firewall-session-dirty:
               type: str
               description: 'How to handle sessions if the configuration of this firewall policy changes.'
            fixedport:
               type: str
               description: 'Enable to prevent source NAT from changing a sessions source port.'
            fsso:
               type: str
               description: 'Enable/disable Fortinet Single Sign-On.'
            fsso-agent-for-ntlm:
               type: str
               description: 'FSSO agent to use for NTLM authentication.'
            global-label:
               type: str
               description: 'Label for the policy that appears when the GUI is in Global View mode.'
            groups:
               type: str
               description: 'Names of user groups that can authenticate with this policy.'
            gtp-profile:
               type: str
               description: 'GTP profile.'
            icap-profile:
               type: str
               description: 'Name of an existing ICAP profile.'
            identity-based-route:
               type: str
               description: 'Name of identity-based routing rule.'
            inbound:
               type: str
               description: 'Policy-based IPsec VPN: only traffic from the remote network can initiate a VPN.'
            internet-service:
               type: str
               description: 'Enable/disable use of Internet Services for this policy. If enabled, destination address and service are not used.'
            internet-service-custom:
               type: str
               description: 'Custom Internet Service Name.'
            internet-service-id:
               type: str
               description: 'Internet Service ID.'
            internet-service-negate:
               type: str
               description: 'When enabled internet-service specifies what the service must NOT be.'
            ippool:
               type: str
               description: 'Enable to use IP Pools for source NAT.'
            ips-sensor:
               type: str
               description: 'Name of an existing IPS sensor.'
            label:
               type: str
               description: 'Label for the policy that appears when the GUI is in Section View mode.'
            learning-mode:
               type: str
               description: 'Enable to allow everything, but log all of the meaningful data for security information gathering. A learning report will be ge...'
            logtraffic:
               type: str
               description: 'Enable or disable logging. Log all sessions or security profile sessions.'
            logtraffic-start:
               type: str
               description: 'Record logs when a session starts and ends.'
            match-vip:
               type: str
               description: 'Enable to match packets that have had their destination addresses changed by a VIP.'
            mms-profile:
               type: str
               description: 'Name of an existing MMS profile.'
            name:
               type: str
               description: 'Policy name.'
            nat:
               type: str
               description: 'Enable/disable source NAT.'
            natinbound:
               type: str
               description: 'Policy-based IPsec VPN: apply destination NAT to inbound traffic.'
            natip:
               type: str
               description: 'Policy-based IPsec VPN: source NAT IP address for outgoing traffic.'
            natoutbound:
               type: str
               description: 'Policy-based IPsec VPN: apply source NAT to outbound traffic.'
            ntlm:
               type: str
               description: 'Enable/disable NTLM authentication.'
            ntlm-enabled-browsers:
               type: array
               suboptions:
                  type: str
            ntlm-guest:
               type: str
               description: 'Enable/disable NTLM guest user access.'
            outbound:
               type: str
               description: 'Policy-based IPsec VPN: only traffic from the internal network can initiate a VPN.'
            per-ip-shaper:
               type: str
               description: 'Per-IP traffic shaper.'
            permit-any-host:
               type: str
               description: 'Accept UDP packets from any host.'
            permit-stun-host:
               type: str
               description: 'Accept UDP packets from any Session Traversal Utilities for NAT (STUN) host.'
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
            radius-mac-auth-bypass:
               type: str
               description: 'Enable MAC authentication bypass. The bypassed MAC address must be received from RADIUS server.'
            redirect-url:
               type: str
               description: 'URL users are directed to after seeing and accepting the disclaimer or authenticating.'
            replacemsg-override-group:
               type: str
               description: 'Override the default replacement message group for this policy.'
            rsso:
               type: str
               description: 'Enable/disable RADIUS single sign-on (RSSO).'
            rtp-addr:
               type: str
               description: 'Address names if this is an RTP NAT policy.'
            rtp-nat:
               type: str
               description: 'Enable Real Time Protocol (RTP) NAT.'
            scan-botnet-connections:
               type: str
               description: 'Block or monitor connections to Botnet servers or disable Botnet scanning.'
            schedule:
               type: str
               description: 'Schedule name.'
            schedule-timeout:
               type: str
               description: 'Enable to force current sessions to end when the schedule object times out. Disable allows them to end from inactivity.'
            send-deny-packet:
               type: str
               description: 'Enable to send a reply when a session is denied or blocked by a firewall policy.'
            service:
               type: str
               description: 'Service and service group names.'
            service-negate:
               type: str
               description: 'When enabled service specifies what the service must NOT be.'
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
            srcintf:
               type: str
               description: 'Incoming (ingress) interface.'
            ssl-mirror:
               type: str
               description: 'Enable to copy decrypted SSL traffic to a FortiGate interface (called SSL mirroring).'
            ssl-mirror-intf:
               type: str
               description: 'SSL mirror interface name.'
            ssl-ssh-profile:
               type: str
               description: 'Name of an existing SSL SSH profile.'
            status:
               type: str
               description: 'Enable or disable this policy.'
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
            timeout-send-rst:
               type: str
               description: 'Enable/disable sending RST packets when TCP sessions expire.'
            traffic-shaper:
               type: str
               description: 'Traffic shaper.'
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
               description: 'Enable to add one or more security profiles (AV, IPS, etc.) to the firewall policy.'
            uuid:
               type: str
               description: 'Universally Unique Identifier (UUID; automatically assigned but can be manually reset).'
            vlan-cos-fwd:
               type: int
               description: 'VLAN forward direction user priority: 255 passthrough, 0 lowest, 7 highest.'
            vlan-cos-rev:
               type: int
               description: 'VLAN reverse direction user priority: 255 passthrough, 0 lowest, 7 highest..'
            voip-profile:
               type: str
               description: 'Name of an existing VoIP profile.'
            vpn_dst_node:
               type: array
               suboptions:
                  host:
                     type: str
                  seq:
                     type: int
                  subnet:
                     type: str
            vpn_src_node:
               type: array
               suboptions:
                  host:
                     type: str
                  seq:
                     type: int
                  subnet:
                     type: str
            vpntunnel:
               type: str
               description: 'Policy-based IPsec VPN: name of the IPsec VPN Phase 1.'
            waf-profile:
               type: str
               description: 'Name of an existing Web application firewall profile.'
            wanopt:
               type: str
               description: 'Enable/disable WAN optimization.'
            wanopt-detection:
               type: str
               description: 'WAN optimization auto-detection mode.'
            wanopt-passive-opt:
               type: str
               description: 'WAN optimization passive mode options. This option decides what IP address will be used to connect server.'
            wanopt-peer:
               type: str
               description: 'WAN optimization peer.'
            wanopt-profile:
               type: str
               description: 'WAN optimization profile.'
            wccp:
               type: str
               description: 'Enable/disable forwarding traffic matching this policy to a configured WCCP server.'
            webcache:
               type: str
               description: 'Enable/disable web cache.'
            webcache-https:
               type: str
               description: 'Enable/disable web cache for HTTPS.'
            webfilter-profile:
               type: str
               description: 'Name of an existing Web filter profile.'
            wsso:
               type: str
               description: 'Enable/disable WiFi Single Sign On (WSSO).'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'
return_of_api_category_0:
   description: items returned for method:[set]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            policyid:
               type: int
               description: 'Policy ID.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'
return_of_api_category_1:
   description: items returned for method:[set]
   returned: always
   suboptions:
      id:
         type: int
      result:
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FAIL_SOCKET_MSG
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import DEFAULT_RESULT_OBJ
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGRCommon
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGBaseException
from ansible_collections.fortinet.fortimanager.plugins.module_utils.fortimanager import FortiManagerHandler


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        },
        {
            'name': 'pkg',
            'type': 'string'
        },
        {
            'name': 'policy',
            'type': 'string'
        }
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'action': {
                            'type': 'string',
                            'enum': [
                                'deny',
                                'accept',
                                'ipsec',
                                'ssl-vpn'
                            ]
                        },
                        'app-category': {
                            'type': 'string'
                        },
                        'application': {
                            'type': 'array',
                            'items': {
                                'type': 'integer'
                            }
                        },
                        'application-list': {
                            'type': 'string'
                        },
                        'auth-cert': {
                            'type': 'string'
                        },
                        'auth-path': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'auth-redirect-addr': {
                            'type': 'string'
                        },
                        'auto-asic-offload': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'av-profile': {
                            'type': 'string'
                        },
                        'block-notification': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'captive-portal-exempt': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'capture-packet': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'comments': {
                            'type': 'string'
                        },
                        'custom-log-fields': {
                            'type': 'string'
                        },
                        'delay-tcp-npu-session': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'devices': {
                            'type': 'string'
                        },
                        'diffserv-forward': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'diffserv-reverse': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'diffservcode-forward': {
                            'type': 'string'
                        },
                        'diffservcode-rev': {
                            'type': 'string'
                        },
                        'disclaimer': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dlp-sensor': {
                            'type': 'string'
                        },
                        'dnsfilter-profile': {
                            'type': 'string'
                        },
                        'dscp-match': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dscp-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dscp-value': {
                            'type': 'string'
                        },
                        'dsri': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dstaddr': {
                            'type': 'string'
                        },
                        'dstaddr-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dstintf': {
                            'type': 'string'
                        },
                        'firewall-session-dirty': {
                            'type': 'string',
                            'enum': [
                                'check-all',
                                'check-new'
                            ]
                        },
                        'fixedport': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'fsso': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'fsso-agent-for-ntlm': {
                            'type': 'string'
                        },
                        'global-label': {
                            'type': 'string'
                        },
                        'groups': {
                            'type': 'string'
                        },
                        'gtp-profile': {
                            'type': 'string'
                        },
                        'icap-profile': {
                            'type': 'string'
                        },
                        'identity-based-route': {
                            'type': 'string'
                        },
                        'inbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'internet-service': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'internet-service-custom': {
                            'type': 'string'
                        },
                        'internet-service-id': {
                            'type': 'string'
                        },
                        'internet-service-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ippool': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ips-sensor': {
                            'type': 'string'
                        },
                        'label': {
                            'type': 'string'
                        },
                        'learning-mode': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'logtraffic': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable',
                                'all',
                                'utm'
                            ]
                        },
                        'logtraffic-start': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'match-vip': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'mms-profile': {
                            'type': 'string'
                        },
                        'name': {
                            'type': 'string'
                        },
                        'nat': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'natinbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'natip': {
                            'type': 'string'
                        },
                        'natoutbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ntlm': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ntlm-enabled-browsers': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'ntlm-guest': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'outbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'per-ip-shaper': {
                            'type': 'string'
                        },
                        'permit-any-host': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'permit-stun-host': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'policyid': {
                            'type': 'integer'
                        },
                        'poolname': {
                            'type': 'string'
                        },
                        'profile-group': {
                            'type': 'string'
                        },
                        'profile-protocol-options': {
                            'type': 'string'
                        },
                        'profile-type': {
                            'type': 'string',
                            'enum': [
                                'single',
                                'group'
                            ]
                        },
                        'radius-mac-auth-bypass': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'redirect-url': {
                            'type': 'string'
                        },
                        'replacemsg-override-group': {
                            'type': 'string'
                        },
                        'rsso': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'rtp-addr': {
                            'type': 'string'
                        },
                        'rtp-nat': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'scan-botnet-connections': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'block',
                                'monitor'
                            ]
                        },
                        'schedule': {
                            'type': 'string'
                        },
                        'schedule-timeout': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'send-deny-packet': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'service': {
                            'type': 'string'
                        },
                        'service-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'session-ttl': {
                            'type': 'integer'
                        },
                        'spamfilter-profile': {
                            'type': 'string'
                        },
                        'srcaddr': {
                            'type': 'string'
                        },
                        'srcaddr-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'srcintf': {
                            'type': 'string'
                        },
                        'ssl-mirror': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-mirror-intf': {
                            'type': 'string'
                        },
                        'ssl-ssh-profile': {
                            'type': 'string'
                        },
                        'status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'tags': {
                            'type': 'string'
                        },
                        'tcp-mss-receiver': {
                            'type': 'integer'
                        },
                        'tcp-mss-sender': {
                            'type': 'integer'
                        },
                        'tcp-session-without-syn': {
                            'type': 'string',
                            'enum': [
                                'all',
                                'data-only',
                                'disable'
                            ]
                        },
                        'timeout-send-rst': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'traffic-shaper': {
                            'type': 'string'
                        },
                        'traffic-shaper-reverse': {
                            'type': 'string'
                        },
                        'url-category': {
                            'type': 'string'
                        },
                        'users': {
                            'type': 'string'
                        },
                        'utm-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'uuid': {
                            'type': 'string'
                        },
                        'vlan-cos-fwd': {
                            'type': 'integer'
                        },
                        'vlan-cos-rev': {
                            'type': 'integer'
                        },
                        'voip-profile': {
                            'type': 'string'
                        },
                        'vpn_dst_node': {
                            'type': 'array',
                            'items': {
                                'host': {
                                    'type': 'string'
                                },
                                'seq': {
                                    'type': 'integer'
                                },
                                'subnet': {
                                    'type': 'string'
                                }
                            }
                        },
                        'vpn_src_node': {
                            'type': 'array',
                            'items': {
                                'host': {
                                    'type': 'string'
                                },
                                'seq': {
                                    'type': 'integer'
                                },
                                'subnet': {
                                    'type': 'string'
                                }
                            }
                        },
                        'vpntunnel': {
                            'type': 'string'
                        },
                        'waf-profile': {
                            'type': 'string'
                        },
                        'wanopt': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'wanopt-detection': {
                            'type': 'string',
                            'enum': [
                                'active',
                                'passive',
                                'off'
                            ]
                        },
                        'wanopt-passive-opt': {
                            'type': 'string',
                            'enum': [
                                'default',
                                'transparent',
                                'non-transparent'
                            ]
                        },
                        'wanopt-peer': {
                            'type': 'string'
                        },
                        'wanopt-profile': {
                            'type': 'string'
                        },
                        'wccp': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'webcache': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'webcache-https': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'ssl-server',
                                'any',
                                'enable'
                            ]
                        },
                        'webfilter-profile': {
                            'type': 'string'
                        },
                        'wsso': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object1': [
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                },
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'attr': {
                            'type': 'string',
                            'enum': [
                                'label',
                                'global-label'
                            ]
                        },
                        'name': {
                            'type': 'string'
                        }
                    },
                    'api_tag': 1
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 1
                }
            ],
            'object2': [
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'object member',
                            'chksum',
                            'datasrc'
                        ]
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object3': [
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'before',
                            'after'
                        ]
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'target',
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object4': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'action': {
                            'type': 'string',
                            'enum': [
                                'deny',
                                'accept',
                                'ipsec',
                                'ssl-vpn'
                            ]
                        },
                        'app-category': {
                            'type': 'string'
                        },
                        'application': {
                            'type': 'array',
                            'items': {
                                'type': 'integer'
                            }
                        },
                        'application-list': {
                            'type': 'string'
                        },
                        'auth-cert': {
                            'type': 'string'
                        },
                        'auth-path': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'auth-redirect-addr': {
                            'type': 'string'
                        },
                        'auto-asic-offload': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'av-profile': {
                            'type': 'string'
                        },
                        'block-notification': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'captive-portal-exempt': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'capture-packet': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'comments': {
                            'type': 'string'
                        },
                        'custom-log-fields': {
                            'type': 'string'
                        },
                        'delay-tcp-npu-session': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'devices': {
                            'type': 'string'
                        },
                        'diffserv-forward': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'diffserv-reverse': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'diffservcode-forward': {
                            'type': 'string'
                        },
                        'diffservcode-rev': {
                            'type': 'string'
                        },
                        'disclaimer': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dlp-sensor': {
                            'type': 'string'
                        },
                        'dnsfilter-profile': {
                            'type': 'string'
                        },
                        'dscp-match': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dscp-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dscp-value': {
                            'type': 'string'
                        },
                        'dsri': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dstaddr': {
                            'type': 'string'
                        },
                        'dstaddr-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'dstintf': {
                            'type': 'string'
                        },
                        'firewall-session-dirty': {
                            'type': 'string',
                            'enum': [
                                'check-all',
                                'check-new'
                            ]
                        },
                        'fixedport': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'fsso': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'fsso-agent-for-ntlm': {
                            'type': 'string'
                        },
                        'global-label': {
                            'type': 'string'
                        },
                        'groups': {
                            'type': 'string'
                        },
                        'gtp-profile': {
                            'type': 'string'
                        },
                        'icap-profile': {
                            'type': 'string'
                        },
                        'identity-based-route': {
                            'type': 'string'
                        },
                        'inbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'internet-service': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'internet-service-custom': {
                            'type': 'string'
                        },
                        'internet-service-id': {
                            'type': 'string'
                        },
                        'internet-service-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ippool': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ips-sensor': {
                            'type': 'string'
                        },
                        'label': {
                            'type': 'string'
                        },
                        'learning-mode': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'logtraffic': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable',
                                'all',
                                'utm'
                            ]
                        },
                        'logtraffic-start': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'match-vip': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'mms-profile': {
                            'type': 'string'
                        },
                        'name': {
                            'type': 'string'
                        },
                        'nat': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'natinbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'natip': {
                            'type': 'string'
                        },
                        'natoutbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ntlm': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ntlm-enabled-browsers': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'ntlm-guest': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'outbound': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'per-ip-shaper': {
                            'type': 'string'
                        },
                        'permit-any-host': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'permit-stun-host': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'policyid': {
                            'type': 'integer'
                        },
                        'poolname': {
                            'type': 'string'
                        },
                        'profile-group': {
                            'type': 'string'
                        },
                        'profile-protocol-options': {
                            'type': 'string'
                        },
                        'profile-type': {
                            'type': 'string',
                            'enum': [
                                'single',
                                'group'
                            ]
                        },
                        'radius-mac-auth-bypass': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'redirect-url': {
                            'type': 'string'
                        },
                        'replacemsg-override-group': {
                            'type': 'string'
                        },
                        'rsso': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'rtp-addr': {
                            'type': 'string'
                        },
                        'rtp-nat': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'scan-botnet-connections': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'block',
                                'monitor'
                            ]
                        },
                        'schedule': {
                            'type': 'string'
                        },
                        'schedule-timeout': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'send-deny-packet': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'service': {
                            'type': 'string'
                        },
                        'service-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'session-ttl': {
                            'type': 'integer'
                        },
                        'spamfilter-profile': {
                            'type': 'string'
                        },
                        'srcaddr': {
                            'type': 'string'
                        },
                        'srcaddr-negate': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'srcintf': {
                            'type': 'string'
                        },
                        'ssl-mirror': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-mirror-intf': {
                            'type': 'string'
                        },
                        'ssl-ssh-profile': {
                            'type': 'string'
                        },
                        'status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'tags': {
                            'type': 'string'
                        },
                        'tcp-mss-receiver': {
                            'type': 'integer'
                        },
                        'tcp-mss-sender': {
                            'type': 'integer'
                        },
                        'tcp-session-without-syn': {
                            'type': 'string',
                            'enum': [
                                'all',
                                'data-only',
                                'disable'
                            ]
                        },
                        'timeout-send-rst': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'traffic-shaper': {
                            'type': 'string'
                        },
                        'traffic-shaper-reverse': {
                            'type': 'string'
                        },
                        'url-category': {
                            'type': 'string'
                        },
                        'users': {
                            'type': 'string'
                        },
                        'utm-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'uuid': {
                            'type': 'string'
                        },
                        'vlan-cos-fwd': {
                            'type': 'integer'
                        },
                        'vlan-cos-rev': {
                            'type': 'integer'
                        },
                        'voip-profile': {
                            'type': 'string'
                        },
                        'vpn_dst_node': {
                            'type': 'array',
                            'items': {
                                'host': {
                                    'type': 'string'
                                },
                                'seq': {
                                    'type': 'integer'
                                },
                                'subnet': {
                                    'type': 'string'
                                }
                            }
                        },
                        'vpn_src_node': {
                            'type': 'array',
                            'items': {
                                'host': {
                                    'type': 'string'
                                },
                                'seq': {
                                    'type': 'integer'
                                },
                                'subnet': {
                                    'type': 'string'
                                }
                            }
                        },
                        'vpntunnel': {
                            'type': 'string'
                        },
                        'waf-profile': {
                            'type': 'string'
                        },
                        'wanopt': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'wanopt-detection': {
                            'type': 'string',
                            'enum': [
                                'active',
                                'passive',
                                'off'
                            ]
                        },
                        'wanopt-passive-opt': {
                            'type': 'string',
                            'enum': [
                                'default',
                                'transparent',
                                'non-transparent'
                            ]
                        },
                        'wanopt-peer': {
                            'type': 'string'
                        },
                        'wanopt-profile': {
                            'type': 'string'
                        },
                        'wccp': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'webcache': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'webcache-https': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'ssl-server',
                                'any',
                                'enable'
                            ]
                        },
                        'webfilter-profile': {
                            'type': 'string'
                        },
                        'wsso': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                },
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'attr': {
                            'type': 'string',
                            'enum': [
                                'label',
                                'global-label'
                            ]
                        },
                        'name': {
                            'type': 'string'
                        }
                    },
                    'api_tag': 1
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 1
                }
            ]
        },
        'method_mapping': {
            'clone': 'object0',
            'delete': 'object1',
            'get': 'object2',
            'move': 'object3',
            'set': 'object4',
            'update': 'object0'
        }
    }

    module_arg_spec = {
        'loose_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'params': {
            'type': 'list',
            'required': False
        },
        'method': {
            'type': 'str',
            'required': True,
            'choices': [
                'clone',
                'delete',
                'get',
                'move',
                'set',
                'update'
            ]
        },
        'url_params': {
            'type': 'dict',
            'required': False
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    method = module.params['method']
    loose_validation = module.params['loose_validation']

    fmgr = None
    payload = None
    response = DEFAULT_RESULT_OBJ

    if module._socket_path:
        connection = Connection(module._socket_path)
        tools = FMGRCommon()
        if loose_validation == False:
            tools.validate_module_params(module, body_schema)
        tools.validate_module_url_params(module, jrpc_urls, url_schema)
        full_url = tools.get_full_url_path(module, jrpc_urls)
        payload = tools.get_full_payload(module, full_url)
        fmgr = FortiManagerHandler(connection, module)
        fmgr.tools = tools
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    try:
        response = fmgr._conn.send_request(method, payload)
        fmgr.govern_response(module=module, results=response,
                             msg='Operation Finished',
                             ansible_facts=fmgr.construct_ansible_facts(response, module.params, module.params))
    except Exception as e:
        raise FMGBaseException(e)

    module.exit_json(meta=response[1])


if __name__ == '__main__':
    main()
