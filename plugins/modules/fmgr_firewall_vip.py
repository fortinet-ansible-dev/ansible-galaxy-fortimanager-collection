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
module: fmgr_firewall_vip
short_description: Configure virtual IP for IPv4.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/firewall/vip
    - /pm/config/global/obj/firewall/vip
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
    schema_object0:
        methods: [add, set, update]
        description: 'Configure virtual IP for IPv4.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                -
                    arp-reply:
                        type: str
                        description: 'Enable to respond to ARP requests for this virtual IP address. Enabled by default.'
                        choices:
                            - 'disable'
                            - 'enable'
                    color:
                        type: int
                        description: 'Color of icon on the GUI.'
                    comment:
                        type: str
                        description: 'Comment.'
                    dns-mapping-ttl:
                        type: int
                        description: 'DNS mapping TTL (Set to zero to use TTL in DNS response, default = 0).'
                    dynamic_mapping:
                        -
                            _scope:
                                -
                                    name:
                                        type: str
                                    vdom:
                                        type: str
                            arp-reply:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            color:
                                type: int
                            comment:
                                type: str
                            dns-mapping-ttl:
                                type: int
                            extaddr:
                                type: str
                            extintf:
                                type: str
                            extip:
                                type: str
                            extport:
                                type: str
                            gratuitous-arp-interval:
                                type: int
                            http-cookie-age:
                                type: int
                            http-cookie-domain:
                                type: str
                            http-cookie-domain-from-host:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            http-cookie-generation:
                                type: int
                            http-cookie-path:
                                type: str
                            http-cookie-share:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'same-ip'
                            http-ip-header:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            http-ip-header-name:
                                type: str
                            http-multiplex:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            https-cookie-secure:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            id:
                                type: int
                            ldb-method:
                                type: str
                                choices:
                                    - 'static'
                                    - 'round-robin'
                                    - 'weighted'
                                    - 'least-session'
                                    - 'least-rtt'
                                    - 'first-alive'
                                    - 'http-host'
                            mapped-addr:
                                type: str
                            mappedip:
                                -
                                    type: str
                            mappedport:
                                type: str
                            max-embryonic-connections:
                                type: int
                            monitor:
                                -
                                    type: str
                            nat-source-vip:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            outlook-web-access:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            persistence:
                                type: str
                                choices:
                                    - 'none'
                                    - 'http-cookie'
                                    - 'ssl-session-id'
                            portforward:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            portmapping-type:
                                type: str
                                choices:
                                    - '1-to-1'
                                    - 'm-to-n'
                            protocol:
                                type: str
                                choices:
                                    - 'tcp'
                                    - 'udp'
                                    - 'sctp'
                                    - 'icmp'
                            realservers:
                                -
                                    client-ip:
                                        -
                                            type: str
                                    healthcheck:
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                            - 'vip'
                                    holddown-interval:
                                        type: int
                                    http-host:
                                        type: str
                                    ip:
                                        type: str
                                    max-connections:
                                        type: int
                                    monitor:
                                        type: str
                                    port:
                                        type: int
                                    seq:
                                        type: int
                                    status:
                                        type: str
                                        choices:
                                            - 'active'
                                            - 'standby'
                                            - 'disable'
                                    weight:
                                        type: int
                            server-type:
                                type: str
                                choices:
                                    - 'http'
                                    - 'https'
                                    - 'ssl'
                                    - 'tcp'
                                    - 'udp'
                                    - 'ip'
                                    - 'imaps'
                                    - 'pop3s'
                                    - 'smtps'
                            service:
                                type: str
                            src-filter:
                                -
                                    type: str
                            srcintf-filter:
                                -
                                    type: str
                            ssl-algorithm:
                                type: str
                                choices:
                                    - 'high'
                                    - 'medium'
                                    - 'low'
                                    - 'custom'
                            ssl-certificate:
                                type: str
                            ssl-cipher-suites:
                                -
                                    cipher:
                                        type: str
                                        choices:
                                            - 'TLS-RSA-WITH-RC4-128-MD5'
                                            - 'TLS-RSA-WITH-RC4-128-SHA'
                                            - 'TLS-RSA-WITH-DES-CBC-SHA'
                                            - 'TLS-RSA-WITH-3DES-EDE-CBC-SHA'
                                            - 'TLS-RSA-WITH-AES-128-CBC-SHA'
                                            - 'TLS-RSA-WITH-AES-256-CBC-SHA'
                                            - 'TLS-RSA-WITH-AES-128-CBC-SHA256'
                                            - 'TLS-RSA-WITH-AES-256-CBC-SHA256'
                                            - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA'
                                            - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA'
                                            - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                                            - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                                            - 'TLS-RSA-WITH-SEED-CBC-SHA'
                                            - 'TLS-RSA-WITH-ARIA-128-CBC-SHA256'
                                            - 'TLS-RSA-WITH-ARIA-256-CBC-SHA384'
                                            - 'TLS-DHE-RSA-WITH-DES-CBC-SHA'
                                            - 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA'
                                            - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA'
                                            - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA'
                                            - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256'
                                            - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256'
                                            - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA'
                                            - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA'
                                            - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                                            - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                                            - 'TLS-DHE-RSA-WITH-SEED-CBC-SHA'
                                            - 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256'
                                            - 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384'
                                            - 'TLS-ECDHE-RSA-WITH-RC4-128-SHA'
                                            - 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA'
                                            - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA'
                                            - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA'
                                            - 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                                            - 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256'
                                            - 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                                            - 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256'
                                            - 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384'
                                            - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA'
                                            - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA'
                                            - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256'
                                            - 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256'
                                            - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256'
                                            - 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384'
                                            - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256'
                                            - 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256'
                                            - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384'
                                            - 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384'
                                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA'
                                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256'
                                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256'
                                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384'
                                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384'
                                            - 'TLS-RSA-WITH-AES-128-GCM-SHA256'
                                            - 'TLS-RSA-WITH-AES-256-GCM-SHA384'
                                            - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA'
                                            - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA'
                                            - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256'
                                            - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256'
                                            - 'TLS-DHE-DSS-WITH-SEED-CBC-SHA'
                                            - 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256'
                                            - 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384'
                                            - 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256'
                                            - 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384'
                                            - 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256'
                                            - 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384'
                                            - 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA'
                                            - 'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                                    id:
                                        type: int
                                    versions:
                                        -
                                            type: str
                                            choices:
                                                - 'ssl-3.0'
                                                - 'tls-1.0'
                                                - 'tls-1.1'
                                                - 'tls-1.2'
                            ssl-client-fallback:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ssl-client-renegotiation:
                                type: str
                                choices:
                                    - 'deny'
                                    - 'allow'
                                    - 'secure'
                            ssl-client-session-state-max:
                                type: int
                            ssl-client-session-state-timeout:
                                type: int
                            ssl-client-session-state-type:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'time'
                                    - 'count'
                                    - 'both'
                            ssl-dh-bits:
                                type: str
                                choices:
                                    - '768'
                                    - '1024'
                                    - '1536'
                                    - '2048'
                                    - '3072'
                                    - '4096'
                            ssl-hpkp:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                                    - 'report-only'
                            ssl-hpkp-age:
                                type: int
                            ssl-hpkp-backup:
                                type: str
                            ssl-hpkp-include-subdomains:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ssl-hpkp-primary:
                                type: str
                            ssl-hpkp-report-uri:
                                type: str
                            ssl-hsts:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ssl-hsts-age:
                                type: int
                            ssl-hsts-include-subdomains:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ssl-http-location-conversion:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ssl-http-match-host:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ssl-max-version:
                                type: str
                                choices:
                                    - 'ssl-3.0'
                                    - 'tls-1.0'
                                    - 'tls-1.1'
                                    - 'tls-1.2'
                            ssl-min-version:
                                type: str
                                choices:
                                    - 'ssl-3.0'
                                    - 'tls-1.0'
                                    - 'tls-1.1'
                                    - 'tls-1.2'
                            ssl-mode:
                                type: str
                                choices:
                                    - 'half'
                                    - 'full'
                            ssl-pfs:
                                type: str
                                choices:
                                    - 'require'
                                    - 'deny'
                                    - 'allow'
                            ssl-send-empty-frags:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ssl-server-algorithm:
                                type: str
                                choices:
                                    - 'high'
                                    - 'low'
                                    - 'medium'
                                    - 'custom'
                                    - 'client'
                            ssl-server-max-version:
                                type: str
                                choices:
                                    - 'ssl-3.0'
                                    - 'tls-1.0'
                                    - 'tls-1.1'
                                    - 'tls-1.2'
                                    - 'client'
                            ssl-server-min-version:
                                type: str
                                choices:
                                    - 'ssl-3.0'
                                    - 'tls-1.0'
                                    - 'tls-1.1'
                                    - 'tls-1.2'
                                    - 'client'
                            ssl-server-session-state-max:
                                type: int
                            ssl-server-session-state-timeout:
                                type: int
                            ssl-server-session-state-type:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'time'
                                    - 'count'
                                    - 'both'
                            type:
                                type: str
                                choices:
                                    - 'static-nat'
                                    - 'load-balance'
                                    - 'server-load-balance'
                                    - 'dns-translation'
                                    - 'fqdn'
                            uuid:
                                type: str
                            weblogic-server:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            websphere-server:
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                    extaddr:
                        type: str
                        description: 'External FQDN address name.'
                    extintf:
                        type: str
                        description: 'Interface connected to the source network that receives the packets that will be forwarded to the destination network.'
                    extip:
                        type: str
                        description: 'IP address or address range on the external interface that you want to map to an address or address range on the desti...'
                    extport:
                        type: str
                        description: 'Incoming port number range that you want to map to a port number range on the destination network.'
                    gratuitous-arp-interval:
                        type: int
                        description: 'Enable to have the VIP send gratuitous ARPs. 0=disabled. Set from 5 up to 8640000 seconds to enable.'
                    http-cookie-age:
                        type: int
                        description: 'Time in minutes that client web browsers should keep a cookie. Default is 60 seconds. 0 = no time limit.'
                    http-cookie-domain:
                        type: str
                        description: 'Domain that HTTP cookie persistence should apply to.'
                    http-cookie-domain-from-host:
                        type: str
                        description: 'Enable/disable use of HTTP cookie domain from host field in HTTP.'
                        choices:
                            - 'disable'
                            - 'enable'
                    http-cookie-generation:
                        type: int
                        description: 'Generation of HTTP cookie to be accepted. Changing invalidates all existing cookies.'
                    http-cookie-path:
                        type: str
                        description: 'Limit HTTP cookie persistence to the specified path.'
                    http-cookie-share:
                        type: str
                        description: 'Control sharing of cookies across virtual servers. same-ip means a cookie from one virtual server can be used by anoth...'
                        choices:
                            - 'disable'
                            - 'same-ip'
                    http-ip-header:
                        type: str
                        description: 'For HTTP multiplexing, enable to add the original client IP address in the XForwarded-For HTTP header.'
                        choices:
                            - 'disable'
                            - 'enable'
                    http-ip-header-name:
                        type: str
                        description: 'For HTTP multiplexing, enter a custom HTTPS header name. The original client IP address is added to this header. If em...'
                    http-multiplex:
                        type: str
                        description: 'Enable/disable HTTP multiplexing.'
                        choices:
                            - 'disable'
                            - 'enable'
                    https-cookie-secure:
                        type: str
                        description: 'Enable/disable verification that inserted HTTPS cookies are secure.'
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: 'Custom defined ID.'
                    ldb-method:
                        type: str
                        description: 'Method used to distribute sessions to real servers.'
                        choices:
                            - 'static'
                            - 'round-robin'
                            - 'weighted'
                            - 'least-session'
                            - 'least-rtt'
                            - 'first-alive'
                            - 'http-host'
                    mapped-addr:
                        type: str
                        description: 'Mapped FQDN address name.'
                    mappedip:
                        -
                            type: str
                    mappedport:
                        type: str
                        description: 'Port number range on the destination network to which the external port number range is mapped.'
                    max-embryonic-connections:
                        type: int
                        description: 'Maximum number of incomplete connections.'
                    monitor:
                        type: str
                        description: 'Name of the health check monitor to use when polling to determine a virtual servers connectivity status.'
                    name:
                        type: str
                        description: 'Virtual IP name.'
                    nat-source-vip:
                        type: str
                        description: 'Enable/disable forcing the source NAT mapped IP to the external IP for all traffic.'
                        choices:
                            - 'disable'
                            - 'enable'
                    outlook-web-access:
                        type: str
                        description: 'Enable to add the Front-End-Https header for Microsoft Outlook Web Access.'
                        choices:
                            - 'disable'
                            - 'enable'
                    persistence:
                        type: str
                        description: 'Configure how to make sure that clients connect to the same server every time they make a request that is part of the ...'
                        choices:
                            - 'none'
                            - 'http-cookie'
                            - 'ssl-session-id'
                    portforward:
                        type: str
                        description: 'Enable/disable port forwarding.'
                        choices:
                            - 'disable'
                            - 'enable'
                    portmapping-type:
                        type: str
                        description: 'Port mapping type.'
                        choices:
                            - '1-to-1'
                            - 'm-to-n'
                    protocol:
                        type: str
                        description: 'Protocol to use when forwarding packets.'
                        choices:
                            - 'tcp'
                            - 'udp'
                            - 'sctp'
                            - 'icmp'
                    realservers:
                        -
                            client-ip:
                                -
                                    type: str
                            healthcheck:
                                type: str
                                description: 'Enable to check the responsiveness of the real server before forwarding traffic.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                                    - 'vip'
                            holddown-interval:
                                type: int
                                description: 'Time in seconds that the health check monitor continues to monitor and unresponsive server that should be active.'
                            http-host:
                                type: str
                                description: 'HTTP server domain name in HTTP header.'
                            ip:
                                type: str
                                description: 'IP address of the real server.'
                            max-connections:
                                type: int
                                description: 'Max number of active connections that can be directed to the real server. When reached, sessions are sent to o...'
                            monitor:
                                type: str
                                description: 'Name of the health check monitor to use when polling to determine a virtual servers connectivity status.'
                            port:
                                type: int
                                description: 'Port for communicating with the real server. Required if port forwarding is enabled.'
                            seq:
                                type: int
                            status:
                                type: str
                                description: 'Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no tra...'
                                choices:
                                    - 'active'
                                    - 'standby'
                                    - 'disable'
                            weight:
                                type: int
                                description: 'Weight of the real server. If weighted load balancing is enabled, the server with the highest weight gets more...'
                    server-type:
                        type: str
                        description: 'Protocol to be load balanced by the virtual server (also called the server load balance virtual IP).'
                        choices:
                            - 'http'
                            - 'https'
                            - 'ssl'
                            - 'tcp'
                            - 'udp'
                            - 'ip'
                            - 'imaps'
                            - 'pop3s'
                            - 'smtps'
                    service:
                        type: str
                        description: 'Service name.'
                    src-filter:
                        -
                            type: str
                    srcintf-filter:
                        type: str
                        description: 'Interfaces to which the VIP applies. Separate the names with spaces.'
                    ssl-algorithm:
                        type: str
                        description: 'Permitted encryption algorithms for SSL sessions according to encryption strength.'
                        choices:
                            - 'high'
                            - 'medium'
                            - 'low'
                            - 'custom'
                    ssl-certificate:
                        type: str
                        description: 'The name of the SSL certificate to use for SSL acceleration.'
                    ssl-cipher-suites:
                        -
                            cipher:
                                type: str
                                description: 'Cipher suite name.'
                                choices:
                                    - 'TLS-RSA-WITH-RC4-128-MD5'
                                    - 'TLS-RSA-WITH-RC4-128-SHA'
                                    - 'TLS-RSA-WITH-DES-CBC-SHA'
                                    - 'TLS-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-RSA-WITH-SEED-CBC-SHA'
                                    - 'TLS-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-DHE-RSA-WITH-DES-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-SEED-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-RC4-128-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-SEED-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                            id:
                                type: int
                            versions:
                                -
                                    type: str
                                    choices:
                                        - 'ssl-3.0'
                                        - 'tls-1.0'
                                        - 'tls-1.1'
                                        - 'tls-1.2'
                    ssl-client-fallback:
                        type: str
                        description: 'Enable/disable support for preventing Downgrade Attacks on client connections (RFC 7507).'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-client-renegotiation:
                        type: str
                        description: 'Allow, deny, or require secure renegotiation of client sessions to comply with RFC 5746.'
                        choices:
                            - 'deny'
                            - 'allow'
                            - 'secure'
                    ssl-client-session-state-max:
                        type: int
                        description: 'Maximum number of client to FortiGate SSL session states to keep.'
                    ssl-client-session-state-timeout:
                        type: int
                        description: 'Number of minutes to keep client to FortiGate SSL session state.'
                    ssl-client-session-state-type:
                        type: str
                        description: 'How to expire SSL sessions for the segment of the SSL connection between the client and the FortiGate.'
                        choices:
                            - 'disable'
                            - 'time'
                            - 'count'
                            - 'both'
                    ssl-dh-bits:
                        type: str
                        description: 'Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.'
                        choices:
                            - '768'
                            - '1024'
                            - '1536'
                            - '2048'
                            - '3072'
                            - '4096'
                    ssl-hpkp:
                        type: str
                        description: 'Enable/disable including HPKP header in response.'
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'report-only'
                    ssl-hpkp-age:
                        type: int
                        description: 'Number of seconds the client should honour the HPKP setting.'
                    ssl-hpkp-backup:
                        type: str
                        description: 'Certificate to generate backup HPKP pin from.'
                    ssl-hpkp-include-subdomains:
                        type: str
                        description: 'Indicate that HPKP header applies to all subdomains.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-hpkp-primary:
                        type: str
                        description: 'Certificate to generate primary HPKP pin from.'
                    ssl-hpkp-report-uri:
                        type: str
                        description: 'URL to report HPKP violations to.'
                    ssl-hsts:
                        type: str
                        description: 'Enable/disable including HSTS header in response.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-hsts-age:
                        type: int
                        description: 'Number of seconds the client should honour the HSTS setting.'
                    ssl-hsts-include-subdomains:
                        type: str
                        description: 'Indicate that HSTS header applies to all subdomains.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-http-location-conversion:
                        type: str
                        description: 'Enable to replace HTTP with HTTPS in the replys Location HTTP header field.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-http-match-host:
                        type: str
                        description: 'Enable/disable HTTP host matching for location conversion.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-max-version:
                        type: str
                        description: 'Highest SSL/TLS version acceptable from a client.'
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                    ssl-min-version:
                        type: str
                        description: 'Lowest SSL/TLS version acceptable from a client.'
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                    ssl-mode:
                        type: str
                        description: 'Apply SSL offloading between the client and the FortiGate (half) or from the client to the FortiGate and from the Fort...'
                        choices:
                            - 'half'
                            - 'full'
                    ssl-pfs:
                        type: str
                        description: 'Select the cipher suites that can be used for SSL perfect forward secrecy (PFS). Applies to both client and server ses...'
                        choices:
                            - 'require'
                            - 'deny'
                            - 'allow'
                    ssl-send-empty-frags:
                        type: str
                        description: 'Enable/disable sending empty fragments to avoid CBC IV attacks (SSL 3.0 & TLS 1.0 only). May need to be disabled for c...'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-server-algorithm:
                        type: str
                        description: 'Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.'
                        choices:
                            - 'high'
                            - 'low'
                            - 'medium'
                            - 'custom'
                            - 'client'
                    ssl-server-cipher-suites:
                        -
                            cipher:
                                type: str
                                description: 'Cipher suite name.'
                                choices:
                                    - 'TLS-RSA-WITH-RC4-128-MD5'
                                    - 'TLS-RSA-WITH-RC4-128-SHA'
                                    - 'TLS-RSA-WITH-DES-CBC-SHA'
                                    - 'TLS-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-RSA-WITH-SEED-CBC-SHA'
                                    - 'TLS-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-DHE-RSA-WITH-DES-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-SEED-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-RC4-128-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-SEED-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                            priority:
                                type: int
                                description: 'SSL/TLS cipher suites priority.'
                            versions:
                                -
                                    type: str
                                    choices:
                                        - 'ssl-3.0'
                                        - 'tls-1.0'
                                        - 'tls-1.1'
                                        - 'tls-1.2'
                    ssl-server-max-version:
                        type: str
                        description: 'Highest SSL/TLS version acceptable from a server. Use the client setting by default.'
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'client'
                    ssl-server-min-version:
                        type: str
                        description: 'Lowest SSL/TLS version acceptable from a server. Use the client setting by default.'
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'client'
                    ssl-server-session-state-max:
                        type: int
                        description: 'Maximum number of FortiGate to Server SSL session states to keep.'
                    ssl-server-session-state-timeout:
                        type: int
                        description: 'Number of minutes to keep FortiGate to Server SSL session state.'
                    ssl-server-session-state-type:
                        type: str
                        description: 'How to expire SSL sessions for the segment of the SSL connection between the server and the FortiGate.'
                        choices:
                            - 'disable'
                            - 'time'
                            - 'count'
                            - 'both'
                    type:
                        type: str
                        description: 'Configure a static NAT, load balance, DNS translation, or FQDN VIP.'
                        choices:
                            - 'static-nat'
                            - 'load-balance'
                            - 'server-load-balance'
                            - 'dns-translation'
                            - 'fqdn'
                    uuid:
                        type: str
                        description: 'Universally Unique Identifier (UUID; automatically assigned but can be manually reset).'
                    weblogic-server:
                        type: str
                        description: 'Enable to add an HTTP header to indicate SSL offloading for a WebLogic server.'
                        choices:
                            - 'disable'
                            - 'enable'
                    websphere-server:
                        type: str
                        description: 'Enable to add an HTTP header to indicate SSL offloading for a WebSphere server.'
                        choices:
                            - 'disable'
                            - 'enable'
    schema_object1:
        methods: [get]
        description: 'Configure virtual IP for IPv4.'
        api_categories: [api_tag0]
        api_tag0:
            attr:
                type: str
                description: 'The name of the attribute to retrieve its datasource. Only used with &lt;i&gt;datasrc&lt;/i&gt; option.'
            fields:
                -
                    -
                        type: str
                        choices:
                            - 'arp-reply'
                            - 'color'
                            - 'comment'
                            - 'dns-mapping-ttl'
                            - 'extaddr'
                            - 'extintf'
                            - 'extip'
                            - 'extport'
                            - 'gratuitous-arp-interval'
                            - 'http-cookie-age'
                            - 'http-cookie-domain'
                            - 'http-cookie-domain-from-host'
                            - 'http-cookie-generation'
                            - 'http-cookie-path'
                            - 'http-cookie-share'
                            - 'http-ip-header'
                            - 'http-ip-header-name'
                            - 'http-multiplex'
                            - 'https-cookie-secure'
                            - 'id'
                            - 'ldb-method'
                            - 'mapped-addr'
                            - 'mappedip'
                            - 'mappedport'
                            - 'max-embryonic-connections'
                            - 'monitor'
                            - 'name'
                            - 'nat-source-vip'
                            - 'outlook-web-access'
                            - 'persistence'
                            - 'portforward'
                            - 'portmapping-type'
                            - 'protocol'
                            - 'server-type'
                            - 'service'
                            - 'src-filter'
                            - 'srcintf-filter'
                            - 'ssl-algorithm'
                            - 'ssl-certificate'
                            - 'ssl-client-fallback'
                            - 'ssl-client-renegotiation'
                            - 'ssl-client-session-state-max'
                            - 'ssl-client-session-state-timeout'
                            - 'ssl-client-session-state-type'
                            - 'ssl-dh-bits'
                            - 'ssl-hpkp'
                            - 'ssl-hpkp-age'
                            - 'ssl-hpkp-backup'
                            - 'ssl-hpkp-include-subdomains'
                            - 'ssl-hpkp-primary'
                            - 'ssl-hpkp-report-uri'
                            - 'ssl-hsts'
                            - 'ssl-hsts-age'
                            - 'ssl-hsts-include-subdomains'
                            - 'ssl-http-location-conversion'
                            - 'ssl-http-match-host'
                            - 'ssl-max-version'
                            - 'ssl-min-version'
                            - 'ssl-mode'
                            - 'ssl-pfs'
                            - 'ssl-send-empty-frags'
                            - 'ssl-server-algorithm'
                            - 'ssl-server-max-version'
                            - 'ssl-server-min-version'
                            - 'ssl-server-session-state-max'
                            - 'ssl-server-session-state-timeout'
                            - 'ssl-server-session-state-type'
                            - 'type'
                            - 'uuid'
                            - 'weblogic-server'
                            - 'websphere-server'
            filter:
                -
                    type: str
            get used:
                type: int
            loadsub:
                type: int
                description: 'Enable or disable the return of any sub-objects. If not specified, the default is to return all sub-objects.'
            option:
                type: str
                description:
                 - 'Set fetch option for the request. If no option is specified, by default the attributes of the objects will be returned.'
                 - 'count - Return the number of matching entries instead of the actual entry data.'
                 - 'object member - Return a list of object members along with other attributes.'
                 - 'datasrc - Return all objects that can be referenced by an attribute. Require <i>attr</i> parameter.'
                 - 'get reserved - Also return reserved objects in the result.'
                 - 'syntax - Return the attribute syntax of a table or an object, instead of the actual entry data. All filter parameters will be ignored.'
                choices:
                    - 'count'
                    - 'object member'
                    - 'datasrc'
                    - 'get reserved'
                    - 'syntax'
            range:
                -
                    type: int
            sortings:
                -
                    varidic.attr_name:
                        type: int
                        choices:
                            - 1
                            - -1

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/VIP
      fmgr_firewall_vip:
         method: <value in [add, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               data:
                 -
                     arp-reply: <value in [disable, enable]>
                     color: <value of integer>
                     comment: <value of string>
                     dns-mapping-ttl: <value of integer>
                     dynamic_mapping:
                       -
                           _scope:
                             -
                                 name: <value of string>
                                 vdom: <value of string>
                           arp-reply: <value in [disable, enable]>
                           color: <value of integer>
                           comment: <value of string>
                           dns-mapping-ttl: <value of integer>
                           extaddr: <value of string>
                           extintf: <value of string>
                           extip: <value of string>
                           extport: <value of string>
                           gratuitous-arp-interval: <value of integer>
                           http-cookie-age: <value of integer>
                           http-cookie-domain: <value of string>
                           http-cookie-domain-from-host: <value in [disable, enable]>
                           http-cookie-generation: <value of integer>
                           http-cookie-path: <value of string>
                           http-cookie-share: <value in [disable, same-ip]>
                           http-ip-header: <value in [disable, enable]>
                           http-ip-header-name: <value of string>
                           http-multiplex: <value in [disable, enable]>
                           https-cookie-secure: <value in [disable, enable]>
                           id: <value of integer>
                           ldb-method: <value in [static, round-robin, weighted, ...]>
                           mapped-addr: <value of string>
                           mappedip:
                             - <value of string>
                           mappedport: <value of string>
                           max-embryonic-connections: <value of integer>
                           monitor:
                             - <value of string>
                           nat-source-vip: <value in [disable, enable]>
                           outlook-web-access: <value in [disable, enable]>
                           persistence: <value in [none, http-cookie, ssl-session-id]>
                           portforward: <value in [disable, enable]>
                           portmapping-type: <value in [1-to-1, m-to-n]>
                           protocol: <value in [tcp, udp, sctp, ...]>
                           realservers:
                             -
                                 client-ip:
                                   - <value of string>
                                 healthcheck: <value in [disable, enable, vip]>
                                 holddown-interval: <value of integer>
                                 http-host: <value of string>
                                 ip: <value of string>
                                 max-connections: <value of integer>
                                 monitor: <value of string>
                                 port: <value of integer>
                                 seq: <value of integer>
                                 status: <value in [active, standby, disable]>
                                 weight: <value of integer>
                           server-type: <value in [http, https, ssl, ...]>
                           service: <value of string>
                           src-filter:
                             - <value of string>
                           srcintf-filter:
                             - <value of string>
                           ssl-algorithm: <value in [high, medium, low, ...]>
                           ssl-certificate: <value of string>
                           ssl-cipher-suites:
                             -
                                 cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
                                 id: <value of integer>
                                 versions:
                                   - <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                           ssl-client-fallback: <value in [disable, enable]>
                           ssl-client-renegotiation: <value in [deny, allow, secure]>
                           ssl-client-session-state-max: <value of integer>
                           ssl-client-session-state-timeout: <value of integer>
                           ssl-client-session-state-type: <value in [disable, time, count, ...]>
                           ssl-dh-bits: <value in [768, 1024, 1536, ...]>
                           ssl-hpkp: <value in [disable, enable, report-only]>
                           ssl-hpkp-age: <value of integer>
                           ssl-hpkp-backup: <value of string>
                           ssl-hpkp-include-subdomains: <value in [disable, enable]>
                           ssl-hpkp-primary: <value of string>
                           ssl-hpkp-report-uri: <value of string>
                           ssl-hsts: <value in [disable, enable]>
                           ssl-hsts-age: <value of integer>
                           ssl-hsts-include-subdomains: <value in [disable, enable]>
                           ssl-http-location-conversion: <value in [disable, enable]>
                           ssl-http-match-host: <value in [disable, enable]>
                           ssl-max-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                           ssl-min-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                           ssl-mode: <value in [half, full]>
                           ssl-pfs: <value in [require, deny, allow]>
                           ssl-send-empty-frags: <value in [disable, enable]>
                           ssl-server-algorithm: <value in [high, low, medium, ...]>
                           ssl-server-max-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                           ssl-server-min-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                           ssl-server-session-state-max: <value of integer>
                           ssl-server-session-state-timeout: <value of integer>
                           ssl-server-session-state-type: <value in [disable, time, count, ...]>
                           type: <value in [static-nat, load-balance, server-load-balance, ...]>
                           uuid: <value of string>
                           weblogic-server: <value in [disable, enable]>
                           websphere-server: <value in [disable, enable]>
                     extaddr: <value of string>
                     extintf: <value of string>
                     extip: <value of string>
                     extport: <value of string>
                     gratuitous-arp-interval: <value of integer>
                     http-cookie-age: <value of integer>
                     http-cookie-domain: <value of string>
                     http-cookie-domain-from-host: <value in [disable, enable]>
                     http-cookie-generation: <value of integer>
                     http-cookie-path: <value of string>
                     http-cookie-share: <value in [disable, same-ip]>
                     http-ip-header: <value in [disable, enable]>
                     http-ip-header-name: <value of string>
                     http-multiplex: <value in [disable, enable]>
                     https-cookie-secure: <value in [disable, enable]>
                     id: <value of integer>
                     ldb-method: <value in [static, round-robin, weighted, ...]>
                     mapped-addr: <value of string>
                     mappedip:
                       - <value of string>
                     mappedport: <value of string>
                     max-embryonic-connections: <value of integer>
                     monitor: <value of string>
                     name: <value of string>
                     nat-source-vip: <value in [disable, enable]>
                     outlook-web-access: <value in [disable, enable]>
                     persistence: <value in [none, http-cookie, ssl-session-id]>
                     portforward: <value in [disable, enable]>
                     portmapping-type: <value in [1-to-1, m-to-n]>
                     protocol: <value in [tcp, udp, sctp, ...]>
                     realservers:
                       -
                           client-ip:
                             - <value of string>
                           healthcheck: <value in [disable, enable, vip]>
                           holddown-interval: <value of integer>
                           http-host: <value of string>
                           ip: <value of string>
                           max-connections: <value of integer>
                           monitor: <value of string>
                           port: <value of integer>
                           seq: <value of integer>
                           status: <value in [active, standby, disable]>
                           weight: <value of integer>
                     server-type: <value in [http, https, ssl, ...]>
                     service: <value of string>
                     src-filter:
                       - <value of string>
                     srcintf-filter: <value of string>
                     ssl-algorithm: <value in [high, medium, low, ...]>
                     ssl-certificate: <value of string>
                     ssl-cipher-suites:
                       -
                           cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
                           id: <value of integer>
                           versions:
                             - <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                     ssl-client-fallback: <value in [disable, enable]>
                     ssl-client-renegotiation: <value in [deny, allow, secure]>
                     ssl-client-session-state-max: <value of integer>
                     ssl-client-session-state-timeout: <value of integer>
                     ssl-client-session-state-type: <value in [disable, time, count, ...]>
                     ssl-dh-bits: <value in [768, 1024, 1536, ...]>
                     ssl-hpkp: <value in [disable, enable, report-only]>
                     ssl-hpkp-age: <value of integer>
                     ssl-hpkp-backup: <value of string>
                     ssl-hpkp-include-subdomains: <value in [disable, enable]>
                     ssl-hpkp-primary: <value of string>
                     ssl-hpkp-report-uri: <value of string>
                     ssl-hsts: <value in [disable, enable]>
                     ssl-hsts-age: <value of integer>
                     ssl-hsts-include-subdomains: <value in [disable, enable]>
                     ssl-http-location-conversion: <value in [disable, enable]>
                     ssl-http-match-host: <value in [disable, enable]>
                     ssl-max-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                     ssl-min-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                     ssl-mode: <value in [half, full]>
                     ssl-pfs: <value in [require, deny, allow]>
                     ssl-send-empty-frags: <value in [disable, enable]>
                     ssl-server-algorithm: <value in [high, low, medium, ...]>
                     ssl-server-cipher-suites:
                       -
                           cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
                           priority: <value of integer>
                           versions:
                             - <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                     ssl-server-max-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                     ssl-server-min-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                     ssl-server-session-state-max: <value of integer>
                     ssl-server-session-state-timeout: <value of integer>
                     ssl-server-session-state-type: <value in [disable, time, count, ...]>
                     type: <value in [static-nat, load-balance, server-load-balance, ...]>
                     uuid: <value of string>
                     weblogic-server: <value in [disable, enable]>
                     websphere-server: <value in [disable, enable]>

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/VIP
      fmgr_firewall_vip:
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               attr: <value of string>
               fields:
                 -
                    - <value in [arp-reply, color, comment, ...]>
               filter:
                 - <value of string>
               get used: <value of integer>
               loadsub: <value of integer>
               option: <value in [count, object member, datasrc, ...]>
               range:
                 - <value of integer>
               sortings:
                 -
                     varidic.attr_name: <value in [1, -1]>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[add, set, update]
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
            example: '/pm/config/adom/{adom}/obj/firewall/vip'
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            type: array
            suboptions:
               arp-reply:
                  type: str
                  description: 'Enable to respond to ARP requests for this virtual IP address. Enabled by default.'
               color:
                  type: int
                  description: 'Color of icon on the GUI.'
               comment:
                  type: str
                  description: 'Comment.'
               dns-mapping-ttl:
                  type: int
                  description: 'DNS mapping TTL (Set to zero to use TTL in DNS response, default = 0).'
               dynamic_mapping:
                  type: array
                  suboptions:
                     _scope:
                        type: array
                        suboptions:
                           name:
                              type: str
                           vdom:
                              type: str
                     arp-reply:
                        type: str
                     color:
                        type: int
                     comment:
                        type: str
                     dns-mapping-ttl:
                        type: int
                     extaddr:
                        type: str
                     extintf:
                        type: str
                     extip:
                        type: str
                     extport:
                        type: str
                     gratuitous-arp-interval:
                        type: int
                     http-cookie-age:
                        type: int
                     http-cookie-domain:
                        type: str
                     http-cookie-domain-from-host:
                        type: str
                     http-cookie-generation:
                        type: int
                     http-cookie-path:
                        type: str
                     http-cookie-share:
                        type: str
                     http-ip-header:
                        type: str
                     http-ip-header-name:
                        type: str
                     http-multiplex:
                        type: str
                     https-cookie-secure:
                        type: str
                     id:
                        type: int
                     ldb-method:
                        type: str
                     mapped-addr:
                        type: str
                     mappedip:
                        type: array
                        suboptions:
                           type: str
                     mappedport:
                        type: str
                     max-embryonic-connections:
                        type: int
                     monitor:
                        type: array
                        suboptions:
                           type: str
                     nat-source-vip:
                        type: str
                     outlook-web-access:
                        type: str
                     persistence:
                        type: str
                     portforward:
                        type: str
                     portmapping-type:
                        type: str
                     protocol:
                        type: str
                     realservers:
                        type: array
                        suboptions:
                           client-ip:
                              type: array
                              suboptions:
                                 type: str
                           healthcheck:
                              type: str
                           holddown-interval:
                              type: int
                           http-host:
                              type: str
                           ip:
                              type: str
                           max-connections:
                              type: int
                           monitor:
                              type: str
                           port:
                              type: int
                           seq:
                              type: int
                           status:
                              type: str
                           weight:
                              type: int
                     server-type:
                        type: str
                     service:
                        type: str
                     src-filter:
                        type: array
                        suboptions:
                           type: str
                     srcintf-filter:
                        type: array
                        suboptions:
                           type: str
                     ssl-algorithm:
                        type: str
                     ssl-certificate:
                        type: str
                     ssl-cipher-suites:
                        type: array
                        suboptions:
                           cipher:
                              type: str
                           id:
                              type: int
                           versions:
                              type: array
                              suboptions:
                                 type: str
                     ssl-client-fallback:
                        type: str
                     ssl-client-renegotiation:
                        type: str
                     ssl-client-session-state-max:
                        type: int
                     ssl-client-session-state-timeout:
                        type: int
                     ssl-client-session-state-type:
                        type: str
                     ssl-dh-bits:
                        type: str
                     ssl-hpkp:
                        type: str
                     ssl-hpkp-age:
                        type: int
                     ssl-hpkp-backup:
                        type: str
                     ssl-hpkp-include-subdomains:
                        type: str
                     ssl-hpkp-primary:
                        type: str
                     ssl-hpkp-report-uri:
                        type: str
                     ssl-hsts:
                        type: str
                     ssl-hsts-age:
                        type: int
                     ssl-hsts-include-subdomains:
                        type: str
                     ssl-http-location-conversion:
                        type: str
                     ssl-http-match-host:
                        type: str
                     ssl-max-version:
                        type: str
                     ssl-min-version:
                        type: str
                     ssl-mode:
                        type: str
                     ssl-pfs:
                        type: str
                     ssl-send-empty-frags:
                        type: str
                     ssl-server-algorithm:
                        type: str
                     ssl-server-max-version:
                        type: str
                     ssl-server-min-version:
                        type: str
                     ssl-server-session-state-max:
                        type: int
                     ssl-server-session-state-timeout:
                        type: int
                     ssl-server-session-state-type:
                        type: str
                     type:
                        type: str
                     uuid:
                        type: str
                     weblogic-server:
                        type: str
                     websphere-server:
                        type: str
               extaddr:
                  type: str
                  description: 'External FQDN address name.'
               extintf:
                  type: str
                  description: 'Interface connected to the source network that receives the packets that will be forwarded to the destination network.'
               extip:
                  type: str
                  description: 'IP address or address range on the external interface that you want to map to an address or address range on the destination...'
               extport:
                  type: str
                  description: 'Incoming port number range that you want to map to a port number range on the destination network.'
               gratuitous-arp-interval:
                  type: int
                  description: 'Enable to have the VIP send gratuitous ARPs. 0=disabled. Set from 5 up to 8640000 seconds to enable.'
               http-cookie-age:
                  type: int
                  description: 'Time in minutes that client web browsers should keep a cookie. Default is 60 seconds. 0 = no time limit.'
               http-cookie-domain:
                  type: str
                  description: 'Domain that HTTP cookie persistence should apply to.'
               http-cookie-domain-from-host:
                  type: str
                  description: 'Enable/disable use of HTTP cookie domain from host field in HTTP.'
               http-cookie-generation:
                  type: int
                  description: 'Generation of HTTP cookie to be accepted. Changing invalidates all existing cookies.'
               http-cookie-path:
                  type: str
                  description: 'Limit HTTP cookie persistence to the specified path.'
               http-cookie-share:
                  type: str
                  description: 'Control sharing of cookies across virtual servers. same-ip means a cookie from one virtual server can be used by another. Di...'
               http-ip-header:
                  type: str
                  description: 'For HTTP multiplexing, enable to add the original client IP address in the XForwarded-For HTTP header.'
               http-ip-header-name:
                  type: str
                  description: 'For HTTP multiplexing, enter a custom HTTPS header name. The original client IP address is added to this header. If empty, X...'
               http-multiplex:
                  type: str
                  description: 'Enable/disable HTTP multiplexing.'
               https-cookie-secure:
                  type: str
                  description: 'Enable/disable verification that inserted HTTPS cookies are secure.'
               id:
                  type: int
                  description: 'Custom defined ID.'
               ldb-method:
                  type: str
                  description: 'Method used to distribute sessions to real servers.'
               mapped-addr:
                  type: str
                  description: 'Mapped FQDN address name.'
               mappedip:
                  type: array
                  suboptions:
                     type: str
               mappedport:
                  type: str
                  description: 'Port number range on the destination network to which the external port number range is mapped.'
               max-embryonic-connections:
                  type: int
                  description: 'Maximum number of incomplete connections.'
               monitor:
                  type: str
                  description: 'Name of the health check monitor to use when polling to determine a virtual servers connectivity status.'
               name:
                  type: str
                  description: 'Virtual IP name.'
               nat-source-vip:
                  type: str
                  description: 'Enable/disable forcing the source NAT mapped IP to the external IP for all traffic.'
               outlook-web-access:
                  type: str
                  description: 'Enable to add the Front-End-Https header for Microsoft Outlook Web Access.'
               persistence:
                  type: str
                  description: 'Configure how to make sure that clients connect to the same server every time they make a request that is part of the same s...'
               portforward:
                  type: str
                  description: 'Enable/disable port forwarding.'
               portmapping-type:
                  type: str
                  description: 'Port mapping type.'
               protocol:
                  type: str
                  description: 'Protocol to use when forwarding packets.'
               realservers:
                  type: array
                  suboptions:
                     client-ip:
                        type: array
                        suboptions:
                           type: str
                     healthcheck:
                        type: str
                        description: 'Enable to check the responsiveness of the real server before forwarding traffic.'
                     holddown-interval:
                        type: int
                        description: 'Time in seconds that the health check monitor continues to monitor and unresponsive server that should be active.'
                     http-host:
                        type: str
                        description: 'HTTP server domain name in HTTP header.'
                     ip:
                        type: str
                        description: 'IP address of the real server.'
                     max-connections:
                        type: int
                        description: 'Max number of active connections that can be directed to the real server. When reached, sessions are sent to other rea...'
                     monitor:
                        type: str
                        description: 'Name of the health check monitor to use when polling to determine a virtual servers connectivity status.'
                     port:
                        type: int
                        description: 'Port for communicating with the real server. Required if port forwarding is enabled.'
                     seq:
                        type: int
                     status:
                        type: str
                        description: 'Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is ...'
                     weight:
                        type: int
                        description: 'Weight of the real server. If weighted load balancing is enabled, the server with the highest weight gets more connect...'
               server-type:
                  type: str
                  description: 'Protocol to be load balanced by the virtual server (also called the server load balance virtual IP).'
               service:
                  type: str
                  description: 'Service name.'
               src-filter:
                  type: array
                  suboptions:
                     type: str
               srcintf-filter:
                  type: str
                  description: 'Interfaces to which the VIP applies. Separate the names with spaces.'
               ssl-algorithm:
                  type: str
                  description: 'Permitted encryption algorithms for SSL sessions according to encryption strength.'
               ssl-certificate:
                  type: str
                  description: 'The name of the SSL certificate to use for SSL acceleration.'
               ssl-cipher-suites:
                  type: array
                  suboptions:
                     cipher:
                        type: str
                        description: 'Cipher suite name.'
                     id:
                        type: int
                     versions:
                        type: array
                        suboptions:
                           type: str
               ssl-client-fallback:
                  type: str
                  description: 'Enable/disable support for preventing Downgrade Attacks on client connections (RFC 7507).'
               ssl-client-renegotiation:
                  type: str
                  description: 'Allow, deny, or require secure renegotiation of client sessions to comply with RFC 5746.'
               ssl-client-session-state-max:
                  type: int
                  description: 'Maximum number of client to FortiGate SSL session states to keep.'
               ssl-client-session-state-timeout:
                  type: int
                  description: 'Number of minutes to keep client to FortiGate SSL session state.'
               ssl-client-session-state-type:
                  type: str
                  description: 'How to expire SSL sessions for the segment of the SSL connection between the client and the FortiGate.'
               ssl-dh-bits:
                  type: str
                  description: 'Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.'
               ssl-hpkp:
                  type: str
                  description: 'Enable/disable including HPKP header in response.'
               ssl-hpkp-age:
                  type: int
                  description: 'Number of seconds the client should honour the HPKP setting.'
               ssl-hpkp-backup:
                  type: str
                  description: 'Certificate to generate backup HPKP pin from.'
               ssl-hpkp-include-subdomains:
                  type: str
                  description: 'Indicate that HPKP header applies to all subdomains.'
               ssl-hpkp-primary:
                  type: str
                  description: 'Certificate to generate primary HPKP pin from.'
               ssl-hpkp-report-uri:
                  type: str
                  description: 'URL to report HPKP violations to.'
               ssl-hsts:
                  type: str
                  description: 'Enable/disable including HSTS header in response.'
               ssl-hsts-age:
                  type: int
                  description: 'Number of seconds the client should honour the HSTS setting.'
               ssl-hsts-include-subdomains:
                  type: str
                  description: 'Indicate that HSTS header applies to all subdomains.'
               ssl-http-location-conversion:
                  type: str
                  description: 'Enable to replace HTTP with HTTPS in the replys Location HTTP header field.'
               ssl-http-match-host:
                  type: str
                  description: 'Enable/disable HTTP host matching for location conversion.'
               ssl-max-version:
                  type: str
                  description: 'Highest SSL/TLS version acceptable from a client.'
               ssl-min-version:
                  type: str
                  description: 'Lowest SSL/TLS version acceptable from a client.'
               ssl-mode:
                  type: str
                  description: 'Apply SSL offloading between the client and the FortiGate (half) or from the client to the FortiGate and from the FortiGate ...'
               ssl-pfs:
                  type: str
                  description: 'Select the cipher suites that can be used for SSL perfect forward secrecy (PFS). Applies to both client and server sessions.'
               ssl-send-empty-frags:
                  type: str
                  description: 'Enable/disable sending empty fragments to avoid CBC IV attacks (SSL 3.0 & TLS 1.0 only). May need to be disabled for compati...'
               ssl-server-algorithm:
                  type: str
                  description: 'Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.'
               ssl-server-cipher-suites:
                  type: array
                  suboptions:
                     cipher:
                        type: str
                        description: 'Cipher suite name.'
                     priority:
                        type: int
                        description: 'SSL/TLS cipher suites priority.'
                     versions:
                        type: array
                        suboptions:
                           type: str
               ssl-server-max-version:
                  type: str
                  description: 'Highest SSL/TLS version acceptable from a server. Use the client setting by default.'
               ssl-server-min-version:
                  type: str
                  description: 'Lowest SSL/TLS version acceptable from a server. Use the client setting by default.'
               ssl-server-session-state-max:
                  type: int
                  description: 'Maximum number of FortiGate to Server SSL session states to keep.'
               ssl-server-session-state-timeout:
                  type: int
                  description: 'Number of minutes to keep FortiGate to Server SSL session state.'
               ssl-server-session-state-type:
                  type: str
                  description: 'How to expire SSL sessions for the segment of the SSL connection between the server and the FortiGate.'
               type:
                  type: str
                  description: 'Configure a static NAT, load balance, DNS translation, or FQDN VIP.'
               uuid:
                  type: str
                  description: 'Universally Unique Identifier (UUID; automatically assigned but can be manually reset).'
               weblogic-server:
                  type: str
                  description: 'Enable to add an HTTP header to indicate SSL offloading for a WebLogic server.'
               websphere-server:
                  type: str
                  description: 'Enable to add an HTTP header to indicate SSL offloading for a WebSphere server.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/firewall/vip'

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
        '/pm/config/adom/{adom}/obj/firewall/vip',
        '/pm/config/global/obj/firewall/vip'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        }
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'name': 'data',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'arp-reply': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'color': {
                            'type': 'integer'
                        },
                        'comment': {
                            'type': 'string'
                        },
                        'dns-mapping-ttl': {
                            'type': 'integer'
                        },
                        'dynamic_mapping': {
                            'type': 'array',
                            'items': {
                                '_scope': {
                                    'type': 'array',
                                    'items': {
                                        'name': {
                                            'type': 'string'
                                        },
                                        'vdom': {
                                            'type': 'string'
                                        }
                                    }
                                },
                                'arp-reply': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'color': {
                                    'type': 'integer'
                                },
                                'comment': {
                                    'type': 'string'
                                },
                                'dns-mapping-ttl': {
                                    'type': 'integer'
                                },
                                'extaddr': {
                                    'type': 'string'
                                },
                                'extintf': {
                                    'type': 'string'
                                },
                                'extip': {
                                    'type': 'string'
                                },
                                'extport': {
                                    'type': 'string'
                                },
                                'gratuitous-arp-interval': {
                                    'type': 'integer'
                                },
                                'http-cookie-age': {
                                    'type': 'integer'
                                },
                                'http-cookie-domain': {
                                    'type': 'string'
                                },
                                'http-cookie-domain-from-host': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'http-cookie-generation': {
                                    'type': 'integer'
                                },
                                'http-cookie-path': {
                                    'type': 'string'
                                },
                                'http-cookie-share': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'same-ip'
                                    ]
                                },
                                'http-ip-header': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'http-ip-header-name': {
                                    'type': 'string'
                                },
                                'http-multiplex': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'https-cookie-secure': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'id': {
                                    'type': 'integer'
                                },
                                'ldb-method': {
                                    'type': 'string',
                                    'enum': [
                                        'static',
                                        'round-robin',
                                        'weighted',
                                        'least-session',
                                        'least-rtt',
                                        'first-alive',
                                        'http-host'
                                    ]
                                },
                                'mapped-addr': {
                                    'type': 'string'
                                },
                                'mappedip': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'mappedport': {
                                    'type': 'string'
                                },
                                'max-embryonic-connections': {
                                    'type': 'integer'
                                },
                                'monitor': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'nat-source-vip': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'outlook-web-access': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'persistence': {
                                    'type': 'string',
                                    'enum': [
                                        'none',
                                        'http-cookie',
                                        'ssl-session-id'
                                    ]
                                },
                                'portforward': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'portmapping-type': {
                                    'type': 'string',
                                    'enum': [
                                        '1-to-1',
                                        'm-to-n'
                                    ]
                                },
                                'protocol': {
                                    'type': 'string',
                                    'enum': [
                                        'tcp',
                                        'udp',
                                        'sctp',
                                        'icmp'
                                    ]
                                },
                                'realservers': {
                                    'type': 'array',
                                    'items': {
                                        'client-ip': {
                                            'type': 'array',
                                            'items': {
                                                'type': 'string'
                                            }
                                        },
                                        'healthcheck': {
                                            'type': 'string',
                                            'enum': [
                                                'disable',
                                                'enable',
                                                'vip'
                                            ]
                                        },
                                        'holddown-interval': {
                                            'type': 'integer'
                                        },
                                        'http-host': {
                                            'type': 'string'
                                        },
                                        'ip': {
                                            'type': 'string'
                                        },
                                        'max-connections': {
                                            'type': 'integer'
                                        },
                                        'monitor': {
                                            'type': 'string'
                                        },
                                        'port': {
                                            'type': 'integer'
                                        },
                                        'seq': {
                                            'type': 'integer'
                                        },
                                        'status': {
                                            'type': 'string',
                                            'enum': [
                                                'active',
                                                'standby',
                                                'disable'
                                            ]
                                        },
                                        'weight': {
                                            'type': 'integer'
                                        }
                                    }
                                },
                                'server-type': {
                                    'type': 'string',
                                    'enum': [
                                        'http',
                                        'https',
                                        'ssl',
                                        'tcp',
                                        'udp',
                                        'ip',
                                        'imaps',
                                        'pop3s',
                                        'smtps'
                                    ]
                                },
                                'service': {
                                    'type': 'string'
                                },
                                'src-filter': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'srcintf-filter': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'ssl-algorithm': {
                                    'type': 'string',
                                    'enum': [
                                        'high',
                                        'medium',
                                        'low',
                                        'custom'
                                    ]
                                },
                                'ssl-certificate': {
                                    'type': 'string'
                                },
                                'ssl-cipher-suites': {
                                    'type': 'array',
                                    'items': {
                                        'cipher': {
                                            'type': 'string',
                                            'enum': [
                                                'TLS-RSA-WITH-RC4-128-MD5',
                                                'TLS-RSA-WITH-RC4-128-SHA',
                                                'TLS-RSA-WITH-DES-CBC-SHA',
                                                'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                                                'TLS-RSA-WITH-AES-128-CBC-SHA',
                                                'TLS-RSA-WITH-AES-256-CBC-SHA',
                                                'TLS-RSA-WITH-AES-128-CBC-SHA256',
                                                'TLS-RSA-WITH-AES-256-CBC-SHA256',
                                                'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                                'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                                'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                                'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                                'TLS-RSA-WITH-SEED-CBC-SHA',
                                                'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                                'TLS-RSA-WITH-ARIA-256-CBC-SHA384',
                                                'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-AES-128-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                                'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256',
                                                'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                                'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                                'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                                'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                                'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                                'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                                'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                                                'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                                'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                                                'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                                'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                                                'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384',
                                                'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256',
                                                'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                                'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                                                'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                                'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256',
                                                'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                                'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384',
                                                'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                                'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                                                'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                                'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                                'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384',
                                                'TLS-RSA-WITH-AES-128-GCM-SHA256',
                                                'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                                'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256',
                                                'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                                'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256',
                                                'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                                'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                                'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                                'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                                                'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                                'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                                            ]
                                        },
                                        'id': {
                                            'type': 'integer'
                                        },
                                        'versions': {
                                            'type': 'array',
                                            'items': {
                                                'type': 'string',
                                                'enum': [
                                                    'ssl-3.0',
                                                    'tls-1.0',
                                                    'tls-1.1',
                                                    'tls-1.2'
                                                ]
                                            }
                                        }
                                    }
                                },
                                'ssl-client-fallback': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-client-renegotiation': {
                                    'type': 'string',
                                    'enum': [
                                        'deny',
                                        'allow',
                                        'secure'
                                    ]
                                },
                                'ssl-client-session-state-max': {
                                    'type': 'integer'
                                },
                                'ssl-client-session-state-timeout': {
                                    'type': 'integer'
                                },
                                'ssl-client-session-state-type': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'time',
                                        'count',
                                        'both'
                                    ]
                                },
                                'ssl-dh-bits': {
                                    'type': 'string',
                                    'enum': [
                                        '768',
                                        '1024',
                                        '1536',
                                        '2048',
                                        '3072',
                                        '4096'
                                    ]
                                },
                                'ssl-hpkp': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable',
                                        'report-only'
                                    ]
                                },
                                'ssl-hpkp-age': {
                                    'type': 'integer'
                                },
                                'ssl-hpkp-backup': {
                                    'type': 'string'
                                },
                                'ssl-hpkp-include-subdomains': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-hpkp-primary': {
                                    'type': 'string'
                                },
                                'ssl-hpkp-report-uri': {
                                    'type': 'string'
                                },
                                'ssl-hsts': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-hsts-age': {
                                    'type': 'integer'
                                },
                                'ssl-hsts-include-subdomains': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-http-location-conversion': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-http-match-host': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-max-version': {
                                    'type': 'string',
                                    'enum': [
                                        'ssl-3.0',
                                        'tls-1.0',
                                        'tls-1.1',
                                        'tls-1.2'
                                    ]
                                },
                                'ssl-min-version': {
                                    'type': 'string',
                                    'enum': [
                                        'ssl-3.0',
                                        'tls-1.0',
                                        'tls-1.1',
                                        'tls-1.2'
                                    ]
                                },
                                'ssl-mode': {
                                    'type': 'string',
                                    'enum': [
                                        'half',
                                        'full'
                                    ]
                                },
                                'ssl-pfs': {
                                    'type': 'string',
                                    'enum': [
                                        'require',
                                        'deny',
                                        'allow'
                                    ]
                                },
                                'ssl-send-empty-frags': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-server-algorithm': {
                                    'type': 'string',
                                    'enum': [
                                        'high',
                                        'low',
                                        'medium',
                                        'custom',
                                        'client'
                                    ]
                                },
                                'ssl-server-max-version': {
                                    'type': 'string',
                                    'enum': [
                                        'ssl-3.0',
                                        'tls-1.0',
                                        'tls-1.1',
                                        'tls-1.2',
                                        'client'
                                    ]
                                },
                                'ssl-server-min-version': {
                                    'type': 'string',
                                    'enum': [
                                        'ssl-3.0',
                                        'tls-1.0',
                                        'tls-1.1',
                                        'tls-1.2',
                                        'client'
                                    ]
                                },
                                'ssl-server-session-state-max': {
                                    'type': 'integer'
                                },
                                'ssl-server-session-state-timeout': {
                                    'type': 'integer'
                                },
                                'ssl-server-session-state-type': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'time',
                                        'count',
                                        'both'
                                    ]
                                },
                                'type': {
                                    'type': 'string',
                                    'enum': [
                                        'static-nat',
                                        'load-balance',
                                        'server-load-balance',
                                        'dns-translation',
                                        'fqdn'
                                    ]
                                },
                                'uuid': {
                                    'type': 'string'
                                },
                                'weblogic-server': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'websphere-server': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                }
                            }
                        },
                        'extaddr': {
                            'type': 'string'
                        },
                        'extintf': {
                            'type': 'string'
                        },
                        'extip': {
                            'type': 'string'
                        },
                        'extport': {
                            'type': 'string'
                        },
                        'gratuitous-arp-interval': {
                            'type': 'integer'
                        },
                        'http-cookie-age': {
                            'type': 'integer'
                        },
                        'http-cookie-domain': {
                            'type': 'string'
                        },
                        'http-cookie-domain-from-host': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'http-cookie-generation': {
                            'type': 'integer'
                        },
                        'http-cookie-path': {
                            'type': 'string'
                        },
                        'http-cookie-share': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'same-ip'
                            ]
                        },
                        'http-ip-header': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'http-ip-header-name': {
                            'type': 'string'
                        },
                        'http-multiplex': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'https-cookie-secure': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'id': {
                            'type': 'integer'
                        },
                        'ldb-method': {
                            'type': 'string',
                            'enum': [
                                'static',
                                'round-robin',
                                'weighted',
                                'least-session',
                                'least-rtt',
                                'first-alive',
                                'http-host'
                            ]
                        },
                        'mapped-addr': {
                            'type': 'string'
                        },
                        'mappedip': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'mappedport': {
                            'type': 'string'
                        },
                        'max-embryonic-connections': {
                            'type': 'integer'
                        },
                        'monitor': {
                            'type': 'string'
                        },
                        'name': {
                            'type': 'string'
                        },
                        'nat-source-vip': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'outlook-web-access': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'persistence': {
                            'type': 'string',
                            'enum': [
                                'none',
                                'http-cookie',
                                'ssl-session-id'
                            ]
                        },
                        'portforward': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'portmapping-type': {
                            'type': 'string',
                            'enum': [
                                '1-to-1',
                                'm-to-n'
                            ]
                        },
                        'protocol': {
                            'type': 'string',
                            'enum': [
                                'tcp',
                                'udp',
                                'sctp',
                                'icmp'
                            ]
                        },
                        'realservers': {
                            'type': 'array',
                            'items': {
                                'client-ip': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'healthcheck': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable',
                                        'vip'
                                    ]
                                },
                                'holddown-interval': {
                                    'type': 'integer'
                                },
                                'http-host': {
                                    'type': 'string'
                                },
                                'ip': {
                                    'type': 'string'
                                },
                                'max-connections': {
                                    'type': 'integer'
                                },
                                'monitor': {
                                    'type': 'string'
                                },
                                'port': {
                                    'type': 'integer'
                                },
                                'seq': {
                                    'type': 'integer'
                                },
                                'status': {
                                    'type': 'string',
                                    'enum': [
                                        'active',
                                        'standby',
                                        'disable'
                                    ]
                                },
                                'weight': {
                                    'type': 'integer'
                                }
                            }
                        },
                        'server-type': {
                            'type': 'string',
                            'enum': [
                                'http',
                                'https',
                                'ssl',
                                'tcp',
                                'udp',
                                'ip',
                                'imaps',
                                'pop3s',
                                'smtps'
                            ]
                        },
                        'service': {
                            'type': 'string'
                        },
                        'src-filter': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'srcintf-filter': {
                            'type': 'string'
                        },
                        'ssl-algorithm': {
                            'type': 'string',
                            'enum': [
                                'high',
                                'medium',
                                'low',
                                'custom'
                            ]
                        },
                        'ssl-certificate': {
                            'type': 'string'
                        },
                        'ssl-cipher-suites': {
                            'type': 'array',
                            'items': {
                                'cipher': {
                                    'type': 'string',
                                    'enum': [
                                        'TLS-RSA-WITH-RC4-128-MD5',
                                        'TLS-RSA-WITH-RC4-128-SHA',
                                        'TLS-RSA-WITH-DES-CBC-SHA',
                                        'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-RSA-WITH-AES-256-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                        'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                                    ]
                                },
                                'id': {
                                    'type': 'integer'
                                },
                                'versions': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string',
                                        'enum': [
                                            'ssl-3.0',
                                            'tls-1.0',
                                            'tls-1.1',
                                            'tls-1.2'
                                        ]
                                    }
                                }
                            }
                        },
                        'ssl-client-fallback': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-client-renegotiation': {
                            'type': 'string',
                            'enum': [
                                'deny',
                                'allow',
                                'secure'
                            ]
                        },
                        'ssl-client-session-state-max': {
                            'type': 'integer'
                        },
                        'ssl-client-session-state-timeout': {
                            'type': 'integer'
                        },
                        'ssl-client-session-state-type': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'time',
                                'count',
                                'both'
                            ]
                        },
                        'ssl-dh-bits': {
                            'type': 'string',
                            'enum': [
                                '768',
                                '1024',
                                '1536',
                                '2048',
                                '3072',
                                '4096'
                            ]
                        },
                        'ssl-hpkp': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable',
                                'report-only'
                            ]
                        },
                        'ssl-hpkp-age': {
                            'type': 'integer'
                        },
                        'ssl-hpkp-backup': {
                            'type': 'string'
                        },
                        'ssl-hpkp-include-subdomains': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-hpkp-primary': {
                            'type': 'string'
                        },
                        'ssl-hpkp-report-uri': {
                            'type': 'string'
                        },
                        'ssl-hsts': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-hsts-age': {
                            'type': 'integer'
                        },
                        'ssl-hsts-include-subdomains': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-http-location-conversion': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-http-match-host': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-max-version': {
                            'type': 'string',
                            'enum': [
                                'ssl-3.0',
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2'
                            ]
                        },
                        'ssl-min-version': {
                            'type': 'string',
                            'enum': [
                                'ssl-3.0',
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2'
                            ]
                        },
                        'ssl-mode': {
                            'type': 'string',
                            'enum': [
                                'half',
                                'full'
                            ]
                        },
                        'ssl-pfs': {
                            'type': 'string',
                            'enum': [
                                'require',
                                'deny',
                                'allow'
                            ]
                        },
                        'ssl-send-empty-frags': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-server-algorithm': {
                            'type': 'string',
                            'enum': [
                                'high',
                                'low',
                                'medium',
                                'custom',
                                'client'
                            ]
                        },
                        'ssl-server-cipher-suites': {
                            'type': 'array',
                            'items': {
                                'cipher': {
                                    'type': 'string',
                                    'enum': [
                                        'TLS-RSA-WITH-RC4-128-MD5',
                                        'TLS-RSA-WITH-RC4-128-SHA',
                                        'TLS-RSA-WITH-DES-CBC-SHA',
                                        'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-RSA-WITH-AES-256-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                        'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                                    ]
                                },
                                'priority': {
                                    'type': 'integer'
                                },
                                'versions': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string',
                                        'enum': [
                                            'ssl-3.0',
                                            'tls-1.0',
                                            'tls-1.1',
                                            'tls-1.2'
                                        ]
                                    }
                                }
                            }
                        },
                        'ssl-server-max-version': {
                            'type': 'string',
                            'enum': [
                                'ssl-3.0',
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2',
                                'client'
                            ]
                        },
                        'ssl-server-min-version': {
                            'type': 'string',
                            'enum': [
                                'ssl-3.0',
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2',
                                'client'
                            ]
                        },
                        'ssl-server-session-state-max': {
                            'type': 'integer'
                        },
                        'ssl-server-session-state-timeout': {
                            'type': 'integer'
                        },
                        'ssl-server-session-state-type': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'time',
                                'count',
                                'both'
                            ]
                        },
                        'type': {
                            'type': 'string',
                            'enum': [
                                'static-nat',
                                'load-balance',
                                'server-load-balance',
                                'dns-translation',
                                'fqdn'
                            ]
                        },
                        'uuid': {
                            'type': 'string'
                        },
                        'weblogic-server': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'websphere-server': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        }
                    }
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
                    'name': 'attr',
                    'api_tag': 0
                },
                {
                    'name': 'fields',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'enum': [
                                'arp-reply',
                                'color',
                                'comment',
                                'dns-mapping-ttl',
                                'extaddr',
                                'extintf',
                                'extip',
                                'extport',
                                'gratuitous-arp-interval',
                                'http-cookie-age',
                                'http-cookie-domain',
                                'http-cookie-domain-from-host',
                                'http-cookie-generation',
                                'http-cookie-path',
                                'http-cookie-share',
                                'http-ip-header',
                                'http-ip-header-name',
                                'http-multiplex',
                                'https-cookie-secure',
                                'id',
                                'ldb-method',
                                'mapped-addr',
                                'mappedip',
                                'mappedport',
                                'max-embryonic-connections',
                                'monitor',
                                'name',
                                'nat-source-vip',
                                'outlook-web-access',
                                'persistence',
                                'portforward',
                                'portmapping-type',
                                'protocol',
                                'server-type',
                                'service',
                                'src-filter',
                                'srcintf-filter',
                                'ssl-algorithm',
                                'ssl-certificate',
                                'ssl-client-fallback',
                                'ssl-client-renegotiation',
                                'ssl-client-session-state-max',
                                'ssl-client-session-state-timeout',
                                'ssl-client-session-state-type',
                                'ssl-dh-bits',
                                'ssl-hpkp',
                                'ssl-hpkp-age',
                                'ssl-hpkp-backup',
                                'ssl-hpkp-include-subdomains',
                                'ssl-hpkp-primary',
                                'ssl-hpkp-report-uri',
                                'ssl-hsts',
                                'ssl-hsts-age',
                                'ssl-hsts-include-subdomains',
                                'ssl-http-location-conversion',
                                'ssl-http-match-host',
                                'ssl-max-version',
                                'ssl-min-version',
                                'ssl-mode',
                                'ssl-pfs',
                                'ssl-send-empty-frags',
                                'ssl-server-algorithm',
                                'ssl-server-max-version',
                                'ssl-server-min-version',
                                'ssl-server-session-state-max',
                                'ssl-server-session-state-timeout',
                                'ssl-server-session-state-type',
                                'type',
                                'uuid',
                                'weblogic-server',
                                'websphere-server'
                            ]
                        }
                    }
                },
                {
                    'name': 'filter',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'example': [
                                '<attr>',
                                '==',
                                'test'
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'integer',
                    'name': 'get used',
                    'api_tag': 0
                },
                {
                    'type': 'integer',
                    'name': 'loadsub',
                    'api_tag': 0
                },
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'count',
                            'object member',
                            'datasrc',
                            'get reserved',
                            'syntax'
                        ]
                    },
                    'api_tag': 0
                },
                {
                    'name': 'range',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            'type': 'integer',
                            'example': [
                                2,
                                5
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'name': 'sortings',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            '{attr_name}': {
                                'type': 'integer',
                                'enum': [
                                    1,
                                    -1
                                ]
                            }
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ]
        },
        'method_mapping': {
            'add': 'object0',
            'get': 'object1',
            'set': 'object0',
            'update': 'object0'
        }
    }

    module_arg_spec = {
        'params': {
            'type': 'list',
            'required': False
        },
        'method': {
            'type': 'str',
            'required': True,
            'choices': [
                'add',
                'get',
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

    fmgr = None
    payload = None
    response = DEFAULT_RESULT_OBJ

    if module._socket_path:
        connection = Connection(module._socket_path)
        tools = FMGRCommon()
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
