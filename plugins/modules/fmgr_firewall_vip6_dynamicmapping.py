#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_firewall_vip6_dynamicmapping
short_description: Configure virtual IP for IPv6.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    vip6:
        description: The parameter (vip6) in requested url.
        type: str
        required: true
    firewall_vip6_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _scope:
                type: list
                elements: dict
                description: No description.
                suboptions:
                    name:
                        type: str
                        description: No description.
                    vdom:
                        type: str
                        description: No description.
            arp-reply:
                type: str
                description: Deprecated, please rename it to arp_reply.
                choices:
                    - 'disable'
                    - 'enable'
            color:
                type: int
                description: No description.
            comment:
                type: str
                description: No description.
            extip:
                type: str
                description: No description.
            extport:
                type: str
                description: No description.
            http-cookie-age:
                type: int
                description: Deprecated, please rename it to http_cookie_age.
            http-cookie-domain:
                type: str
                description: Deprecated, please rename it to http_cookie_domain.
            http-cookie-domain-from-host:
                type: str
                description: Deprecated, please rename it to http_cookie_domain_from_host.
                choices:
                    - 'disable'
                    - 'enable'
            http-cookie-generation:
                type: int
                description: Deprecated, please rename it to http_cookie_generation.
            http-cookie-path:
                type: str
                description: Deprecated, please rename it to http_cookie_path.
            http-cookie-share:
                type: str
                description: Deprecated, please rename it to http_cookie_share.
                choices:
                    - 'disable'
                    - 'same-ip'
            http-ip-header:
                type: str
                description: Deprecated, please rename it to http_ip_header.
                choices:
                    - 'disable'
                    - 'enable'
            http-ip-header-name:
                type: str
                description: Deprecated, please rename it to http_ip_header_name.
            http-multiplex:
                type: str
                description: Deprecated, please rename it to http_multiplex.
                choices:
                    - 'disable'
                    - 'enable'
            https-cookie-secure:
                type: str
                description: Deprecated, please rename it to https_cookie_secure.
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: int
                description: No description.
            ldb-method:
                type: str
                description: Deprecated, please rename it to ldb_method.
                choices:
                    - 'static'
                    - 'round-robin'
                    - 'weighted'
                    - 'least-session'
                    - 'least-rtt'
                    - 'first-alive'
                    - 'http-host'
            mappedip:
                type: str
                description: No description.
            mappedport:
                type: str
                description: No description.
            max-embryonic-connections:
                type: int
                description: Deprecated, please rename it to max_embryonic_connections.
            monitor:
                type: raw
                description: (list or str) No description.
            outlook-web-access:
                type: str
                description: Deprecated, please rename it to outlook_web_access.
                choices:
                    - 'disable'
                    - 'enable'
            persistence:
                type: str
                description: No description.
                choices:
                    - 'none'
                    - 'http-cookie'
                    - 'ssl-session-id'
            portforward:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            protocol:
                type: str
                description: No description.
                choices:
                    - 'tcp'
                    - 'udp'
                    - 'sctp'
            server-type:
                type: str
                description: Deprecated, please rename it to server_type.
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
            src-filter:
                type: raw
                description: (list) Deprecated, please rename it to src_filter.
            ssl-algorithm:
                type: str
                description: Deprecated, please rename it to ssl_algorithm.
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
                    - 'custom'
            ssl-certificate:
                type: str
                description: Deprecated, please rename it to ssl_certificate.
            ssl-client-fallback:
                type: str
                description: Deprecated, please rename it to ssl_client_fallback.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-client-renegotiation:
                type: str
                description: Deprecated, please rename it to ssl_client_renegotiation.
                choices:
                    - 'deny'
                    - 'allow'
                    - 'secure'
            ssl-client-session-state-max:
                type: int
                description: Deprecated, please rename it to ssl_client_session_state_max.
            ssl-client-session-state-timeout:
                type: int
                description: Deprecated, please rename it to ssl_client_session_state_timeout.
            ssl-client-session-state-type:
                type: str
                description: Deprecated, please rename it to ssl_client_session_state_type.
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
            ssl-dh-bits:
                type: str
                description: Deprecated, please rename it to ssl_dh_bits.
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
            ssl-hpkp:
                type: str
                description: Deprecated, please rename it to ssl_hpkp.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'report-only'
            ssl-hpkp-age:
                type: int
                description: Deprecated, please rename it to ssl_hpkp_age.
            ssl-hpkp-backup:
                type: str
                description: Deprecated, please rename it to ssl_hpkp_backup.
            ssl-hpkp-include-subdomains:
                type: str
                description: Deprecated, please rename it to ssl_hpkp_include_subdomains.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-hpkp-primary:
                type: str
                description: Deprecated, please rename it to ssl_hpkp_primary.
            ssl-hpkp-report-uri:
                type: str
                description: Deprecated, please rename it to ssl_hpkp_report_uri.
            ssl-hsts:
                type: str
                description: Deprecated, please rename it to ssl_hsts.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-hsts-age:
                type: int
                description: Deprecated, please rename it to ssl_hsts_age.
            ssl-hsts-include-subdomains:
                type: str
                description: Deprecated, please rename it to ssl_hsts_include_subdomains.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-http-location-conversion:
                type: str
                description: Deprecated, please rename it to ssl_http_location_conversion.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-http-match-host:
                type: str
                description: Deprecated, please rename it to ssl_http_match_host.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-max-version:
                type: str
                description: Deprecated, please rename it to ssl_max_version.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl-min-version:
                type: str
                description: Deprecated, please rename it to ssl_min_version.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl-mode:
                type: str
                description: Deprecated, please rename it to ssl_mode.
                choices:
                    - 'half'
                    - 'full'
            ssl-pfs:
                type: str
                description: Deprecated, please rename it to ssl_pfs.
                choices:
                    - 'require'
                    - 'deny'
                    - 'allow'
            ssl-send-empty-frags:
                type: str
                description: Deprecated, please rename it to ssl_send_empty_frags.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-server-algorithm:
                type: str
                description: Deprecated, please rename it to ssl_server_algorithm.
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
                    - 'custom'
                    - 'client'
            ssl-server-max-version:
                type: str
                description: Deprecated, please rename it to ssl_server_max_version.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'client'
                    - 'tls-1.3'
            ssl-server-min-version:
                type: str
                description: Deprecated, please rename it to ssl_server_min_version.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'client'
                    - 'tls-1.3'
            ssl-server-session-state-max:
                type: int
                description: Deprecated, please rename it to ssl_server_session_state_max.
            ssl-server-session-state-timeout:
                type: int
                description: Deprecated, please rename it to ssl_server_session_state_timeout.
            ssl-server-session-state-type:
                type: str
                description: Deprecated, please rename it to ssl_server_session_state_type.
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
            type:
                type: str
                description: No description.
                choices:
                    - 'static-nat'
                    - 'server-load-balance'
                    - 'access-proxy'
            uuid:
                type: str
                description: No description.
            weblogic-server:
                type: str
                description: Deprecated, please rename it to weblogic_server.
                choices:
                    - 'disable'
                    - 'enable'
            websphere-server:
                type: str
                description: Deprecated, please rename it to websphere_server.
                choices:
                    - 'disable'
                    - 'enable'
            http-redirect:
                type: str
                description: Deprecated, please rename it to http_redirect.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-client-rekey-count:
                type: int
                description: Deprecated, please rename it to ssl_client_rekey_count.
            nat-source-vip:
                type: str
                description: Deprecated, please rename it to nat_source_vip.
                choices:
                    - 'disable'
                    - 'enable'
            add-nat64-route:
                type: str
                description: Deprecated, please rename it to add_nat64_route. Enable/disable adding NAT64 route.
                choices:
                    - 'disable'
                    - 'enable'
            embedded-ipv4-address:
                type: str
                description: Deprecated, please rename it to embedded_ipv4_address. Enable/disable use of the lower 32 bits of the external IPv6 addres...
                choices:
                    - 'disable'
                    - 'enable'
            ipv4-mappedip:
                type: str
                description: Deprecated, please rename it to ipv4_mappedip. Range of mapped IP addresses.
            ipv4-mappedport:
                type: str
                description: Deprecated, please rename it to ipv4_mappedport. IPv4 port number range on the destination network to which the external p...
            nat64:
                type: str
                description: Enable/disable DNAT64.
                choices:
                    - 'disable'
                    - 'enable'
            nat66:
                type: str
                description: Enable/disable DNAT66.
                choices:
                    - 'disable'
                    - 'enable'
            realservers:
                type: list
                elements: dict
                description: No description.
                suboptions:
                    client-ip:
                        type: str
                        description: Deprecated, please rename it to client_ip. Only clients in this IP range can connect to this real server.
                    healthcheck:
                        type: str
                        description: Enable to check the responsiveness of the real server before forwarding traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'vip'
                    holddown-interval:
                        type: int
                        description: Deprecated, please rename it to holddown_interval. Time in seconds that the health check monitor continues to moni...
                    http-host:
                        type: str
                        description: Deprecated, please rename it to http_host. HTTP server domain name in HTTP header.
                    id:
                        type: int
                        description: Real server ID.
                    ip:
                        type: str
                        description: IP address of the real server.
                    max-connections:
                        type: int
                        description: Deprecated, please rename it to max_connections. Max number of active connections that can directed to the real se...
                    monitor:
                        type: raw
                        description: (list or str) No description.
                    port:
                        type: int
                        description: Port for communicating with the real server.
                    status:
                        type: str
                        description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic...
                        choices:
                            - 'active'
                            - 'standby'
                            - 'disable'
                    weight:
                        type: int
                        description: Weight of the real server.
                    translate-host:
                        type: str
                        description: Deprecated, please rename it to translate_host. Enable/disable translation of hostname/IP from virtual server to r...
                        choices:
                            - 'disable'
                            - 'enable'
            ssl-accept-ffdhe-groups:
                type: str
                description: Deprecated, please rename it to ssl_accept_ffdhe_groups. Enable/disable FFDHE cipher suite for SSL key exchange.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-cipher-suites:
                type: list
                elements: dict
                description: Deprecated, please rename it to ssl_cipher_suites.
                suboptions:
                    cipher:
                        type: str
                        description: Cipher suite name.
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
                            - 'TLS-AES-128-GCM-SHA256'
                            - 'TLS-AES-256-GCM-SHA384'
                            - 'TLS-CHACHA20-POLY1305-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                    priority:
                        type: int
                        description: SSL/TLS cipher suites priority.
                    versions:
                        type: list
                        elements: str
                        description: No description.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ndp-reply:
                type: str
                description: Deprecated, please rename it to ndp_reply. Enable/disable this FortiGate units ability to respond to NDP requests for this...
                choices:
                    - 'disable'
                    - 'enable'
            ssl-server-renegotiation:
                type: str
                description: Deprecated, please rename it to ssl_server_renegotiation. Enable/disable secure renegotiation to comply with RFC 5746.
                choices:
                    - 'disable'
                    - 'enable'
            h2-support:
                type: str
                description: Deprecated, please rename it to h2_support. Enable/disable HTTP2 support
                choices:
                    - 'disable'
                    - 'enable'
            h3-support:
                type: str
                description: Deprecated, please rename it to h3_support. Enable/disable HTTP3/QUIC support
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure dynamic mappings of virtual IP for IPv6
      fortinet.fortimanager.fmgr_firewall_vip6_dynamicmapping:
        bypass_validation: false
        adom: ansible
        vip6: "ansible-test-vip6" # name
        state: present
        firewall_vip6_dynamicmapping:
          _scope:
            - name: FGT_AWS # need a valid device name
              vdom: root # need a valid vdom name under the device
          arp-reply: disable
          color: 1
          comment: "ansible-comment"
          id: 1

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the dynamic mappings of virtual IP for IPv6
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_vip6_dynamicmapping"
          params:
            adom: "ansible"
            vip6: "ansible-test-vip6" # name
            dynamic_mapping: "your_value"
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping',
        '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}',
        '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}'
    ]

    url_params = ['adom', 'vip6']
    module_primary_key = 'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vip6': {'required': True, 'type': 'str'},
        'firewall_vip6_dynamicmapping': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                'arp-reply': {'choices': ['disable', 'enable'], 'type': 'str'},
                'color': {'type': 'int'},
                'comment': {'type': 'str'},
                'extip': {'type': 'str'},
                'extport': {'type': 'str'},
                'http-cookie-age': {'type': 'int'},
                'http-cookie-domain': {'type': 'str'},
                'http-cookie-domain-from-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'http-cookie-generation': {'type': 'int'},
                'http-cookie-path': {'type': 'str'},
                'http-cookie-share': {'choices': ['disable', 'same-ip'], 'type': 'str'},
                'http-ip-header': {'choices': ['disable', 'enable'], 'type': 'str'},
                'http-ip-header-name': {'type': 'str'},
                'http-multiplex': {'choices': ['disable', 'enable'], 'type': 'str'},
                'https-cookie-secure': {'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'type': 'int'},
                'ldb-method': {'choices': ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt', 'first-alive', 'http-host'], 'type': 'str'},
                'mappedip': {'type': 'str'},
                'mappedport': {'type': 'str'},
                'max-embryonic-connections': {'type': 'int'},
                'monitor': {'type': 'raw'},
                'outlook-web-access': {'choices': ['disable', 'enable'], 'type': 'str'},
                'persistence': {'choices': ['none', 'http-cookie', 'ssl-session-id'], 'type': 'str'},
                'portforward': {'choices': ['disable', 'enable'], 'type': 'str'},
                'protocol': {'choices': ['tcp', 'udp', 'sctp'], 'type': 'str'},
                'server-type': {'choices': ['http', 'https', 'ssl', 'tcp', 'udp', 'ip', 'imaps', 'pop3s', 'smtps'], 'type': 'str'},
                'src-filter': {'type': 'raw'},
                'ssl-algorithm': {'choices': ['high', 'low', 'medium', 'custom'], 'type': 'str'},
                'ssl-certificate': {'type': 'str'},
                'ssl-client-fallback': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-client-renegotiation': {'choices': ['deny', 'allow', 'secure'], 'type': 'str'},
                'ssl-client-session-state-max': {'type': 'int'},
                'ssl-client-session-state-timeout': {'type': 'int'},
                'ssl-client-session-state-type': {'choices': ['disable', 'time', 'count', 'both'], 'type': 'str'},
                'ssl-dh-bits': {'choices': ['768', '1024', '1536', '2048', '3072', '4096'], 'type': 'str'},
                'ssl-hpkp': {'choices': ['disable', 'enable', 'report-only'], 'type': 'str'},
                'ssl-hpkp-age': {'type': 'int'},
                'ssl-hpkp-backup': {'type': 'str'},
                'ssl-hpkp-include-subdomains': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-hpkp-primary': {'type': 'str'},
                'ssl-hpkp-report-uri': {'type': 'str'},
                'ssl-hsts': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-hsts-age': {'type': 'int'},
                'ssl-hsts-include-subdomains': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-http-location-conversion': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-http-match-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-max-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-min-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-mode': {'choices': ['half', 'full'], 'type': 'str'},
                'ssl-pfs': {'choices': ['require', 'deny', 'allow'], 'type': 'str'},
                'ssl-send-empty-frags': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-algorithm': {'choices': ['high', 'low', 'medium', 'custom', 'client'], 'type': 'str'},
                'ssl-server-max-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'], 'type': 'str'},
                'ssl-server-min-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'], 'type': 'str'},
                'ssl-server-session-state-max': {'type': 'int'},
                'ssl-server-session-state-timeout': {'type': 'int'},
                'ssl-server-session-state-type': {'choices': ['disable', 'time', 'count', 'both'], 'type': 'str'},
                'type': {'choices': ['static-nat', 'server-load-balance', 'access-proxy'], 'type': 'str'},
                'uuid': {'type': 'str'},
                'weblogic-server': {'choices': ['disable', 'enable'], 'type': 'str'},
                'websphere-server': {'choices': ['disable', 'enable'], 'type': 'str'},
                'http-redirect': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-client-rekey-count': {'v_range': [['6.2.1', '']], 'no_log': True, 'type': 'int'},
                'nat-source-vip': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'add-nat64-route': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'embedded-ipv4-address': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv4-mappedip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'ipv4-mappedport': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'nat64': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat66': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'realservers': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'options': {
                        'client-ip': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'healthcheck': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable', 'vip'], 'type': 'str'},
                        'holddown-interval': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'http-host': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'id': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'max-connections': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'monitor': {'v_range': [['7.0.2', '']], 'type': 'raw'},
                        'port': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'status': {'v_range': [['7.0.2', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                        'weight': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'translate-host': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ssl-accept-ffdhe-groups': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-cipher-suites': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'v_range': [['7.0.2', '']],
                            'choices': [
                                'TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA', 'TLS-RSA-WITH-DES-CBC-SHA', 'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                                'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA', 'TLS-RSA-WITH-AES-128-CBC-SHA256',
                                'TLS-RSA-WITH-AES-256-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA', 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA',
                                'TLS-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                                'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                                'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-SEED-CBC-SHA', 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-RC4-128-SHA', 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                                'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                                'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                                'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256', 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                                'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384', 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                                'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384', 'TLS-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                                'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA',
                                'TLS-AES-128-GCM-SHA256', 'TLS-AES-256-GCM-SHA384', 'TLS-CHACHA20-POLY1305-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                            ],
                            'type': 'str'
                        },
                        'priority': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'versions': {
                            'v_range': [['7.0.2', '']],
                            'type': 'list',
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ndp-reply': {'v_range': [['7.0.5', '7.0.12'], ['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-renegotiation': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h2-support': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h3-support': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip6_dynamicmapping'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
