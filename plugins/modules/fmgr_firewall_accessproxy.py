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
module: fmgr_firewall_accessproxy
short_description: Configure Access Proxy.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
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
    firewall_accessproxy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            api_gateway:
                type: list
                elements: dict
                description: Api gateway.
                suboptions:
                    http_cookie_age:
                        type: int
                        description: Time in minutes that client web browsers should keep a cookie.
                    http_cookie_domain:
                        type: str
                        description: Domain that HTTP cookie persistence should apply to.
                    http_cookie_domain_from_host:
                        type: str
                        description: Enable/disable use of HTTP cookie domain from host field in HTTP.
                        choices:
                            - 'disable'
                            - 'enable'
                    http_cookie_generation:
                        type: int
                        description: Generation of HTTP cookie to be accepted.
                    http_cookie_path:
                        type: str
                        description: Limit HTTP cookie persistence to the specified path.
                    http_cookie_share:
                        type: str
                        description: Control sharing of cookies across API Gateway.
                        choices:
                            - 'disable'
                            - 'same-ip'
                    https_cookie_secure:
                        type: str
                        description: Enable/disable verification that inserted HTTPS cookies are secure.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: API Gateway ID.
                    ldb_method:
                        type: str
                        description: Method used to distribute sessions to real servers.
                        choices:
                            - 'static'
                            - 'round-robin'
                            - 'weighted'
                            - 'least-session'
                            - 'least-rtt'
                            - 'first-alive'
                            - 'http-host'
                    persistence:
                        type: str
                        description: Configure how to make sure that clients connect to the same server every time they make a request that is part of ...
                        choices:
                            - 'none'
                            - 'http-cookie'
                    realservers:
                        type: list
                        elements: dict
                        description: Realservers.
                        suboptions:
                            address:
                                type: str
                                description: Address or address group of the real server.
                            health_check:
                                type: str
                                description: Enable to check the responsiveness of the real server before forwarding traffic.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            health_check_proto:
                                type: str
                                description: Protocol of the health check monitor to use when polling to determine servers connectivity status.
                                choices:
                                    - 'ping'
                                    - 'http'
                                    - 'tcp-connect'
                            http_host:
                                type: str
                                description: HTTP server domain name in HTTP header.
                            id:
                                type: int
                                description: Real server ID.
                            ip:
                                type: str
                                description: IP address of the real server.
                            mappedport:
                                type: raw
                                description: (list or str) Port for communicating with the real server.
                            port:
                                type: int
                                description: Port for communicating with the real server.
                            status:
                                type: str
                                description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no...
                                choices:
                                    - 'active'
                                    - 'standby'
                                    - 'disable'
                            weight:
                                type: int
                                description: Weight of the real server.
                            addr_type:
                                type: str
                                description: Type of address.
                                choices:
                                    - 'fqdn'
                                    - 'ip'
                            domain:
                                type: str
                                description: Wildcard domain name of the real server.
                            holddown_interval:
                                type: str
                                description: Enable/disable holddown timer.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            ssh_client_cert:
                                type: str
                                description: Set access-proxy SSH client certificate profile.
                            ssh_host_key:
                                type: raw
                                description: (list or str) One or more server host key.
                            ssh_host_key_validation:
                                type: str
                                description: Enable/disable SSH real server host key validation.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            type:
                                type: str
                                description: TCP forwarding server type.
                                choices:
                                    - 'tcp-forwarding'
                                    - 'ssh'
                            translate_host:
                                type: str
                                description: Enable/disable translation of hostname/IP from virtual server to real server.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            external_auth:
                                type: str
                                description: Enable/disable use of external browser as user-agent for SAML user authentication.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            tunnel_encryption:
                                type: str
                                description: Tunnel encryption.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    saml_server:
                        type: str
                        description: SAML service provider configuration for VIP authentication.
                    service:
                        type: str
                        description: Service.
                        choices:
                            - 'http'
                            - 'https'
                            - 'tcp-forwarding'
                            - 'samlsp'
                            - 'web-portal'
                            - 'saas'
                    ssl_algorithm:
                        type: str
                        description: Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                        choices:
                            - 'high'
                            - 'medium'
                            - 'low'
                            - 'custom'
                    ssl_cipher_suites:
                        type: list
                        elements: dict
                        description: Ssl cipher suites.
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
                                description: SSL/TLS versions that the cipher suite can be used with.
                                choices:
                                    - 'tls-1.0'
                                    - 'tls-1.1'
                                    - 'tls-1.2'
                                    - 'tls-1.3'
                    ssl_dh_bits:
                        type: str
                        description: Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
                        choices:
                            - '768'
                            - '1024'
                            - '1536'
                            - '2048'
                            - '3072'
                            - '4096'
                    ssl_max_version:
                        type: str
                        description: Highest SSL/TLS version acceptable from a server.
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_min_version:
                        type: str
                        description: Lowest SSL/TLS version acceptable from a server.
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    url_map:
                        type: str
                        description: URL pattern to match.
                    url_map_type:
                        type: str
                        description: Type of url-map.
                        choices:
                            - 'sub-string'
                            - 'wildcard'
                            - 'regex'
                    virtual_host:
                        type: str
                        description: Virtual host.
                    saml_redirect:
                        type: str
                        description: Enable/disable SAML redirection after successful authentication.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_vpn_web_portal:
                        type: str
                        description: SSL-VPN web portal.
                    application:
                        type: raw
                        description: (list) SaaS application controlled by this Access Proxy.
                    ssl_renegotiation:
                        type: str
                        description: Enable/disable secure renegotiation to comply with RFC 5746.
                        choices:
                            - 'disable'
                            - 'enable'
                    h2_support:
                        type: str
                        description: HTTP2 support, default=Enable.
                        choices:
                            - 'disable'
                            - 'enable'
                    h3_support:
                        type: str
                        description: HTTP3/QUIC support, default=Disable.
                        choices:
                            - 'disable'
                            - 'enable'
                    quic:
                        type: dict
                        description: Quic.
                        suboptions:
                            ack_delay_exponent:
                                type: int
                                description: ACK delay exponent
                            active_connection_id_limit:
                                type: int
                                description: Active connection ID limit
                            active_migration:
                                type: str
                                description: Enable/disable active migration
                                choices:
                                    - 'disable'
                                    - 'enable'
                            grease_quic_bit:
                                type: str
                                description: Enable/disable grease QUIC bit
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max_ack_delay:
                                type: int
                                description: Maximum ACK delay in milliseconds
                            max_datagram_frame_size:
                                type: int
                                description: Maximum datagram frame size in bytes
                            max_idle_timeout:
                                type: int
                                description: Maximum idle timeout milliseconds
                            max_udp_payload_size:
                                type: int
                                description: Maximum UDP payload size in bytes
            client_cert:
                type: str
                description: Enable/disable to request client certificate.
                choices:
                    - 'disable'
                    - 'enable'
            empty_cert_action:
                type: str
                description: Action of an empty client certificate.
                choices:
                    - 'block'
                    - 'accept'
                    - 'accept-unmanageable'
            ldb_method:
                type: str
                description: Method used to distribute sessions to SSL real servers.
                choices:
                    - 'static'
                    - 'round-robin'
                    - 'weighted'
                    - 'least-session'
                    - 'least-rtt'
                    - 'first-alive'
            name:
                type: str
                description: Access Proxy name.
                required: true
            realservers:
                type: list
                elements: dict
                description: Realservers.
                suboptions:
                    id:
                        type: int
                        description: Real server ID.
                    ip:
                        type: str
                        description: IP address of the real server.
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
            server_pubkey_auth:
                type: str
                description: Enable/disable SSH real server public key authentication.
                choices:
                    - 'disable'
                    - 'enable'
            server_pubkey_auth_settings:
                type: dict
                description: Server pubkey auth settings.
                suboptions:
                    auth_ca:
                        type: str
                        description: Name of the SSH server public key authentication CA.
                    cert_extension:
                        type: list
                        elements: dict
                        description: Cert extension.
                        suboptions:
                            critical:
                                type: str
                                description: Critical option.
                                choices:
                                    - 'no'
                                    - 'yes'
                            data:
                                type: str
                                description: Name of certificate extension.
                            name:
                                type: str
                                description: Name of certificate extension.
                            type:
                                type: str
                                description: Type of certificate extension.
                                choices:
                                    - 'fixed'
                                    - 'user'
                    permit_agent_forwarding:
                        type: str
                        description: Enable/disable appending permit-agent-forwarding certificate extension.
                        choices:
                            - 'disable'
                            - 'enable'
                    permit_port_forwarding:
                        type: str
                        description: Enable/disable appending permit-port-forwarding certificate extension.
                        choices:
                            - 'disable'
                            - 'enable'
                    permit_pty:
                        type: str
                        description: Enable/disable appending permit-pty certificate extension.
                        choices:
                            - 'disable'
                            - 'enable'
                    permit_user_rc:
                        type: str
                        description: Enable/disable appending permit-user-rc certificate extension.
                        choices:
                            - 'disable'
                            - 'enable'
                    permit_x11_forwarding:
                        type: str
                        description: Enable/disable appending permit-x11-forwarding certificate extension.
                        choices:
                            - 'disable'
                            - 'enable'
                    source_address:
                        type: str
                        description: Enable/disable appending source-address certificate critical option.
                        choices:
                            - 'disable'
                            - 'enable'
            vip:
                type: str
                description: Virtual IP name.
            api_gateway6:
                type: list
                elements: dict
                description: Api gateway6.
                suboptions:
                    http_cookie_age:
                        type: int
                        description: Time in minutes that client web browsers should keep a cookie.
                    http_cookie_domain:
                        type: str
                        description: Domain that HTTP cookie persistence should apply to.
                    http_cookie_domain_from_host:
                        type: str
                        description: Enable/disable use of HTTP cookie domain from host field in HTTP.
                        choices:
                            - 'disable'
                            - 'enable'
                    http_cookie_generation:
                        type: int
                        description: Generation of HTTP cookie to be accepted.
                    http_cookie_path:
                        type: str
                        description: Limit HTTP cookie persistence to the specified path.
                    http_cookie_share:
                        type: str
                        description: Control sharing of cookies across API Gateway.
                        choices:
                            - 'disable'
                            - 'same-ip'
                    https_cookie_secure:
                        type: str
                        description: Enable/disable verification that inserted HTTPS cookies are secure.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: API Gateway ID.
                    ldb_method:
                        type: str
                        description: Method used to distribute sessions to real servers.
                        choices:
                            - 'static'
                            - 'round-robin'
                            - 'weighted'
                            - 'first-alive'
                            - 'http-host'
                    persistence:
                        type: str
                        description: Configure how to make sure that clients connect to the same server every time they make a request that is part of ...
                        choices:
                            - 'none'
                            - 'http-cookie'
                    realservers:
                        type: list
                        elements: dict
                        description: Realservers.
                        suboptions:
                            addr_type:
                                type: str
                                description: Type of address.
                                choices:
                                    - 'fqdn'
                                    - 'ip'
                            address:
                                type: str
                                description: Address or address group of the real server.
                            domain:
                                type: str
                                description: Wildcard domain name of the real server.
                            health_check:
                                type: str
                                description: Enable to check the responsiveness of the real server before forwarding traffic.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            health_check_proto:
                                type: str
                                description: Protocol of the health check monitor to use when polling to determine servers connectivity status.
                                choices:
                                    - 'ping'
                                    - 'http'
                                    - 'tcp-connect'
                            holddown_interval:
                                type: str
                                description: Enable/disable holddown timer.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            http_host:
                                type: str
                                description: HTTP server domain name in HTTP header.
                            id:
                                type: int
                                description: Real server ID.
                            ip:
                                type: str
                                description: IPv6 address of the real server.
                            mappedport:
                                type: raw
                                description: (list or str) Port for communicating with the real server.
                            port:
                                type: int
                                description: Port for communicating with the real server.
                            ssh_client_cert:
                                type: str
                                description: Set access-proxy SSH client certificate profile.
                            ssh_host_key:
                                type: raw
                                description: (list or str) One or more server host key.
                            ssh_host_key_validation:
                                type: str
                                description: Enable/disable SSH real server host key validation.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            status:
                                type: str
                                description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no...
                                choices:
                                    - 'active'
                                    - 'standby'
                                    - 'disable'
                            type:
                                type: str
                                description: TCP forwarding server type.
                                choices:
                                    - 'tcp-forwarding'
                                    - 'ssh'
                            weight:
                                type: int
                                description: Weight of the real server.
                            translate_host:
                                type: str
                                description: Enable/disable translation of hostname/IP from virtual server to real server.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            external_auth:
                                type: str
                                description: Enable/disable use of external browser as user-agent for SAML user authentication.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            tunnel_encryption:
                                type: str
                                description: Tunnel encryption.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    saml_redirect:
                        type: str
                        description: Enable/disable SAML redirection after successful authentication.
                        choices:
                            - 'disable'
                            - 'enable'
                    saml_server:
                        type: str
                        description: SAML service provider configuration for VIP authentication.
                    service:
                        type: str
                        description: Service.
                        choices:
                            - 'http'
                            - 'https'
                            - 'tcp-forwarding'
                            - 'samlsp'
                            - 'web-portal'
                            - 'saas'
                    ssl_algorithm:
                        type: str
                        description: Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                        choices:
                            - 'high'
                            - 'medium'
                            - 'low'
                    ssl_cipher_suites:
                        type: list
                        elements: dict
                        description: Ssl cipher suites.
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
                                description: SSL/TLS versions that the cipher suite can be used with.
                                choices:
                                    - 'tls-1.0'
                                    - 'tls-1.1'
                                    - 'tls-1.2'
                                    - 'tls-1.3'
                    ssl_dh_bits:
                        type: str
                        description: Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
                        choices:
                            - '768'
                            - '1024'
                            - '1536'
                            - '2048'
                            - '3072'
                            - '4096'
                    ssl_max_version:
                        type: str
                        description: Highest SSL/TLS version acceptable from a server.
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_min_version:
                        type: str
                        description: Lowest SSL/TLS version acceptable from a server.
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_vpn_web_portal:
                        type: str
                        description: SSL-VPN web portal.
                    url_map:
                        type: str
                        description: URL pattern to match.
                    url_map_type:
                        type: str
                        description: Type of url-map.
                        choices:
                            - 'sub-string'
                            - 'wildcard'
                            - 'regex'
                    virtual_host:
                        type: str
                        description: Virtual host.
                    application:
                        type: raw
                        description: (list) SaaS application controlled by this Access Proxy.
                    ssl_renegotiation:
                        type: str
                        description: Enable/disable secure renegotiation to comply with RFC 5746.
                        choices:
                            - 'disable'
                            - 'enable'
                    h2_support:
                        type: str
                        description: HTTP2 support, default=Enable.
                        choices:
                            - 'disable'
                            - 'enable'
                    h3_support:
                        type: str
                        description: HTTP3/QUIC support, default=Disable.
                        choices:
                            - 'disable'
                            - 'enable'
                    quic:
                        type: dict
                        description: Quic.
                        suboptions:
                            ack_delay_exponent:
                                type: int
                                description: ACK delay exponent
                            active_connection_id_limit:
                                type: int
                                description: Active connection ID limit
                            active_migration:
                                type: str
                                description: Enable/disable active migration
                                choices:
                                    - 'disable'
                                    - 'enable'
                            grease_quic_bit:
                                type: str
                                description: Enable/disable grease QUIC bit
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max_ack_delay:
                                type: int
                                description: Maximum ACK delay in milliseconds
                            max_datagram_frame_size:
                                type: int
                                description: Maximum datagram frame size in bytes
                            max_idle_timeout:
                                type: int
                                description: Maximum idle timeout milliseconds
                            max_udp_payload_size:
                                type: int
                                description: Maximum UDP payload size in bytes
            auth_portal:
                type: str
                description: Enable/disable authentication portal.
                choices:
                    - 'disable'
                    - 'enable'
            auth_virtual_host:
                type: str
                description: Virtual host for authentication portal.
            decrypted_traffic_mirror:
                type: str
                description: Decrypted traffic mirror.
            log_blocked_traffic:
                type: str
                description: Enable/disable logging of blocked traffic.
                choices:
                    - 'disable'
                    - 'enable'
            add_vhost_domain_to_dnsdb:
                type: str
                description: Enable/disable adding vhost/domain to dnsdb for ztna dox tunnel.
                choices:
                    - 'disable'
                    - 'enable'
            user_agent_detect:
                type: str
                description: Enable/disable to detect device type by HTTP user-agent if no client certificate provided.
                choices:
                    - 'disable'
                    - 'enable'
            http_supported_max_version:
                type: str
                description: Maximum supported HTTP versions.
                choices:
                    - 'http1'
                    - 'http2'
            svr_pool_multiplex:
                type: str
                description: Enable/disable server pool multiplexing.
                choices:
                    - 'disable'
                    - 'enable'
            svr_pool_server_max_request:
                type: int
                description: Maximum number of requests that servers in server pool handle before disconnecting
            svr_pool_ttl:
                type: int
                description: Time-to-live in the server pool for idle connections to servers.
            svr_pool_server_max_concurrent_request:
                type: int
                description: Maximum number of concurrent requests that servers in server pool could handle
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure Access Proxy.
      fortinet.fortimanager.fmgr_firewall_accessproxy:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        firewall_accessproxy:
          api_gateway:
            -
              http_cookie_age: <integer>
              http_cookie_domain: <string>
              http_cookie_domain_from_host: <value in [disable, enable]>
              http_cookie_generation: <integer>
              http_cookie_path: <string>
              http_cookie_share: <value in [disable, same-ip]>
              https_cookie_secure: <value in [disable, enable]>
              id: <integer>
              ldb_method: <value in [static, round-robin, weighted, ...]>
              persistence: <value in [none, http-cookie]>
              realservers:
                -
                  address: <string>
                  health_check: <value in [disable, enable]>
                  health_check_proto: <value in [ping, http, tcp-connect]>
                  http_host: <string>
                  id: <integer>
                  ip: <string>
                  mappedport: <list or string>
                  port: <integer>
                  status: <value in [active, standby, disable]>
                  weight: <integer>
                  addr_type: <value in [fqdn, ip]>
                  domain: <string>
                  holddown_interval: <value in [disable, enable]>
                  ssh_client_cert: <string>
                  ssh_host_key: <list or string>
                  ssh_host_key_validation: <value in [disable, enable]>
                  type: <value in [tcp-forwarding, ssh]>
                  translate_host: <value in [disable, enable]>
                  external_auth: <value in [disable, enable]>
                  tunnel_encryption: <value in [disable, enable]>
              saml_server: <string>
              service: <value in [http, https, tcp-forwarding, ...]>
              ssl_algorithm: <value in [high, medium, low, ...]>
              ssl_cipher_suites:
                -
                  cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
                  priority: <integer>
                  versions:
                    - "tls-1.0"
                    - "tls-1.1"
                    - "tls-1.2"
                    - "tls-1.3"
              ssl_dh_bits: <value in [768, 1024, 1536, ...]>
              ssl_max_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
              ssl_min_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
              url_map: <string>
              url_map_type: <value in [sub-string, wildcard, regex]>
              virtual_host: <string>
              saml_redirect: <value in [disable, enable]>
              ssl_vpn_web_portal: <string>
              application: <list or string>
              ssl_renegotiation: <value in [disable, enable]>
              h2_support: <value in [disable, enable]>
              h3_support: <value in [disable, enable]>
              quic:
                ack_delay_exponent: <integer>
                active_connection_id_limit: <integer>
                active_migration: <value in [disable, enable]>
                grease_quic_bit: <value in [disable, enable]>
                max_ack_delay: <integer>
                max_datagram_frame_size: <integer>
                max_idle_timeout: <integer>
                max_udp_payload_size: <integer>
          client_cert: <value in [disable, enable]>
          empty_cert_action: <value in [block, accept, accept-unmanageable]>
          ldb_method: <value in [static, round-robin, weighted, ...]>
          name: <string>
          realservers:
            -
              id: <integer>
              ip: <string>
              port: <integer>
              status: <value in [active, standby, disable]>
              weight: <integer>
          server_pubkey_auth: <value in [disable, enable]>
          server_pubkey_auth_settings:
            auth_ca: <string>
            cert_extension:
              -
                critical: <value in [no, yes]>
                data: <string>
                name: <string>
                type: <value in [fixed, user]>
            permit_agent_forwarding: <value in [disable, enable]>
            permit_port_forwarding: <value in [disable, enable]>
            permit_pty: <value in [disable, enable]>
            permit_user_rc: <value in [disable, enable]>
            permit_x11_forwarding: <value in [disable, enable]>
            source_address: <value in [disable, enable]>
          vip: <string>
          api_gateway6:
            -
              http_cookie_age: <integer>
              http_cookie_domain: <string>
              http_cookie_domain_from_host: <value in [disable, enable]>
              http_cookie_generation: <integer>
              http_cookie_path: <string>
              http_cookie_share: <value in [disable, same-ip]>
              https_cookie_secure: <value in [disable, enable]>
              id: <integer>
              ldb_method: <value in [static, round-robin, weighted, ...]>
              persistence: <value in [none, http-cookie]>
              realservers:
                -
                  addr_type: <value in [fqdn, ip]>
                  address: <string>
                  domain: <string>
                  health_check: <value in [disable, enable]>
                  health_check_proto: <value in [ping, http, tcp-connect]>
                  holddown_interval: <value in [disable, enable]>
                  http_host: <string>
                  id: <integer>
                  ip: <string>
                  mappedport: <list or string>
                  port: <integer>
                  ssh_client_cert: <string>
                  ssh_host_key: <list or string>
                  ssh_host_key_validation: <value in [disable, enable]>
                  status: <value in [active, standby, disable]>
                  type: <value in [tcp-forwarding, ssh]>
                  weight: <integer>
                  translate_host: <value in [disable, enable]>
                  external_auth: <value in [disable, enable]>
                  tunnel_encryption: <value in [disable, enable]>
              saml_redirect: <value in [disable, enable]>
              saml_server: <string>
              service: <value in [http, https, tcp-forwarding, ...]>
              ssl_algorithm: <value in [high, medium, low]>
              ssl_cipher_suites:
                -
                  cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
                  priority: <integer>
                  versions:
                    - "tls-1.0"
                    - "tls-1.1"
                    - "tls-1.2"
                    - "tls-1.3"
              ssl_dh_bits: <value in [768, 1024, 1536, ...]>
              ssl_max_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
              ssl_min_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
              ssl_vpn_web_portal: <string>
              url_map: <string>
              url_map_type: <value in [sub-string, wildcard, regex]>
              virtual_host: <string>
              application: <list or string>
              ssl_renegotiation: <value in [disable, enable]>
              h2_support: <value in [disable, enable]>
              h3_support: <value in [disable, enable]>
              quic:
                ack_delay_exponent: <integer>
                active_connection_id_limit: <integer>
                active_migration: <value in [disable, enable]>
                grease_quic_bit: <value in [disable, enable]>
                max_ack_delay: <integer>
                max_datagram_frame_size: <integer>
                max_idle_timeout: <integer>
                max_udp_payload_size: <integer>
          auth_portal: <value in [disable, enable]>
          auth_virtual_host: <string>
          decrypted_traffic_mirror: <string>
          log_blocked_traffic: <value in [disable, enable]>
          add_vhost_domain_to_dnsdb: <value in [disable, enable]>
          user_agent_detect: <value in [disable, enable]>
          http_supported_max_version: <value in [http1, http2]>
          svr_pool_multiplex: <value in [disable, enable]>
          svr_pool_server_max_request: <integer>
          svr_pool_ttl: <integer>
          svr_pool_server_max_concurrent_request: <integer>
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/firewall/access-proxy',
        '/pm/config/global/obj/firewall/access-proxy'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'firewall_accessproxy': {
            'type': 'dict',
            'v_range': [['7.0.0', '']],
            'options': {
                'api-gateway': {
                    'v_range': [['7.0.0', '']],
                    'type': 'list',
                    'options': {
                        'http-cookie-age': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'http-cookie-domain': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'http-cookie-domain-from-host': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-cookie-generation': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'http-cookie-path': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'http-cookie-share': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'same-ip'], 'type': 'str'},
                        'https-cookie-secure': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'ldb-method': {
                            'v_range': [['7.0.0', '']],
                            'choices': ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt', 'first-alive', 'http-host'],
                            'type': 'str'
                        },
                        'persistence': {'v_range': [['7.0.0', '']], 'choices': ['none', 'http-cookie'], 'type': 'str'},
                        'realservers': {
                            'v_range': [['7.0.0', '']],
                            'type': 'list',
                            'options': {
                                'address': {'v_range': [['7.0.0', '']], 'type': 'str'},
                                'health-check': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'health-check-proto': {'v_range': [['7.0.0', '']], 'choices': ['ping', 'http', 'tcp-connect'], 'type': 'str'},
                                'http-host': {'v_range': [['7.0.0', '']], 'type': 'str'},
                                'id': {'v_range': [['7.0.0', '']], 'type': 'int'},
                                'ip': {'v_range': [['7.0.0', '']], 'type': 'str'},
                                'mappedport': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                                'port': {'v_range': [['7.0.0', '']], 'type': 'int'},
                                'status': {'v_range': [['7.0.0', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                                'weight': {'v_range': [['7.0.0', '']], 'type': 'int'},
                                'addr-type': {'v_range': [['7.0.2', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                                'domain': {'v_range': [['7.0.3', '']], 'type': 'str'},
                                'holddown-interval': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'ssh-client-cert': {'v_range': [['7.0.1', '']], 'type': 'str'},
                                'ssh-host-key': {'v_range': [['7.0.1', '']], 'no_log': True, 'type': 'raw'},
                                'ssh-host-key-validation': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'type': {'v_range': [['7.0.1', '']], 'choices': ['tcp-forwarding', 'ssh'], 'type': 'str'},
                                'translate-host': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'external-auth': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'tunnel-encryption': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'saml-server': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'service': {
                            'v_range': [['7.0.0', '']],
                            'choices': ['http', 'https', 'tcp-forwarding', 'samlsp', 'web-portal', 'saas'],
                            'type': 'str'
                        },
                        'ssl-algorithm': {'v_range': [['7.0.0', '']], 'choices': ['high', 'medium', 'low', 'custom'], 'type': 'str'},
                        'ssl-cipher-suites': {
                            'v_range': [['7.0.0', '']],
                            'type': 'list',
                            'options': {
                                'cipher': {
                                    'v_range': [['7.0.0', '']],
                                    'choices': [
                                        'TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA', 'TLS-RSA-WITH-DES-CBC-SHA',
                                        'TLS-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA256', 'TLS-RSA-WITH-AES-256-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA', 'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-RSA-WITH-DES-CBC-SHA', 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                        'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA', 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256', 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA', 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384', 'TLS-RSA-WITH-AES-128-GCM-SHA256', 'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-SEED-CBC-SHA', 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256', 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA', 'TLS-AES-128-GCM-SHA256',
                                        'TLS-AES-256-GCM-SHA384', 'TLS-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                                    ],
                                    'type': 'str'
                                },
                                'priority': {'v_range': [['7.0.0', '']], 'type': 'int'},
                                'versions': {
                                    'v_range': [['7.0.0', '']],
                                    'type': 'list',
                                    'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                                    'elements': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'ssl-dh-bits': {'v_range': [['7.0.0', '']], 'choices': ['768', '1024', '1536', '2048', '3072', '4096'], 'type': 'str'},
                        'ssl-max-version': {'v_range': [['7.0.0', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                        'ssl-min-version': {'v_range': [['7.0.0', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                        'url-map': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'url-map-type': {'v_range': [['7.0.0', '']], 'choices': ['sub-string', 'wildcard', 'regex'], 'type': 'str'},
                        'virtual-host': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'saml-redirect': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-vpn-web-portal': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'application': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'ssl-renegotiation': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h2-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h3-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'quic': {
                            'v_range': [['7.4.1', '']],
                            'type': 'dict',
                            'options': {
                                'ack-delay-exponent': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'active-connection-id-limit': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'active-migration': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'grease-quic-bit': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-ack-delay': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-datagram-frame-size': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-idle-timeout': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-udp-payload-size': {'v_range': [['7.4.1', '']], 'type': 'int'}
                            }
                        }
                    },
                    'elements': 'dict'
                },
                'client-cert': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'empty-cert-action': {'v_range': [['7.0.0', '']], 'choices': ['block', 'accept', 'accept-unmanageable'], 'type': 'str'},
                'ldb-method': {
                    'v_range': [['7.0.0', '']],
                    'choices': ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt', 'first-alive'],
                    'type': 'str'
                },
                'name': {'v_range': [['7.0.0', '']], 'required': True, 'type': 'str'},
                'realservers': {
                    'v_range': [['7.0.0', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'port': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'status': {'v_range': [['7.0.0', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                        'weight': {'v_range': [['7.0.0', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'server-pubkey-auth': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'server-pubkey-auth-settings': {
                    'v_range': [['7.0.0', '']],
                    'type': 'dict',
                    'options': {
                        'auth-ca': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'cert-extension': {
                            'v_range': [['7.0.0', '']],
                            'type': 'list',
                            'options': {
                                'critical': {'v_range': [['7.0.0', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                                'data': {'v_range': [['7.0.0', '']], 'type': 'str'},
                                'name': {'v_range': [['7.0.0', '']], 'type': 'str'},
                                'type': {'v_range': [['7.0.0', '']], 'choices': ['fixed', 'user'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'permit-agent-forwarding': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'permit-port-forwarding': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'permit-pty': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'permit-user-rc': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'permit-x11-forwarding': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'source-address': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'vip': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'api-gateway6': {
                    'v_range': [['7.0.1', '']],
                    'type': 'list',
                    'options': {
                        'http-cookie-age': {'v_range': [['7.0.1', '']], 'type': 'int'},
                        'http-cookie-domain': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'http-cookie-domain-from-host': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-cookie-generation': {'v_range': [['7.0.1', '']], 'type': 'int'},
                        'http-cookie-path': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'http-cookie-share': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'same-ip'], 'type': 'str'},
                        'https-cookie-secure': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'v_range': [['7.0.1', '']], 'type': 'int'},
                        'ldb-method': {
                            'v_range': [['7.0.1', '']],
                            'choices': ['static', 'round-robin', 'weighted', 'first-alive', 'http-host'],
                            'type': 'str'
                        },
                        'persistence': {'v_range': [['7.0.1', '']], 'choices': ['none', 'http-cookie'], 'type': 'str'},
                        'realservers': {
                            'v_range': [['7.0.1', '']],
                            'type': 'list',
                            'options': {
                                'addr-type': {'v_range': [['7.0.2', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                                'address': {'v_range': [['7.0.1', '']], 'type': 'str'},
                                'domain': {'v_range': [['7.0.3', '']], 'type': 'str'},
                                'health-check': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'health-check-proto': {'v_range': [['7.0.1', '']], 'choices': ['ping', 'http', 'tcp-connect'], 'type': 'str'},
                                'holddown-interval': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'http-host': {'v_range': [['7.0.1', '']], 'type': 'str'},
                                'id': {'v_range': [['7.0.1', '']], 'type': 'int'},
                                'ip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                                'mappedport': {'v_range': [['7.0.1', '']], 'type': 'raw'},
                                'port': {'v_range': [['7.0.1', '']], 'type': 'int'},
                                'ssh-client-cert': {'v_range': [['7.0.1', '']], 'type': 'str'},
                                'ssh-host-key': {'v_range': [['7.0.1', '']], 'no_log': True, 'type': 'raw'},
                                'ssh-host-key-validation': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'status': {'v_range': [['7.0.1', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                                'type': {'v_range': [['7.0.1', '']], 'choices': ['tcp-forwarding', 'ssh'], 'type': 'str'},
                                'weight': {'v_range': [['7.0.1', '']], 'type': 'int'},
                                'translate-host': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'external-auth': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'tunnel-encryption': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'saml-redirect': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'saml-server': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'service': {
                            'v_range': [['7.0.1', '']],
                            'choices': ['http', 'https', 'tcp-forwarding', 'samlsp', 'web-portal', 'saas'],
                            'type': 'str'
                        },
                        'ssl-algorithm': {'v_range': [['7.0.1', '']], 'choices': ['high', 'medium', 'low'], 'type': 'str'},
                        'ssl-cipher-suites': {
                            'v_range': [['7.0.1', '']],
                            'type': 'list',
                            'options': {
                                'cipher': {
                                    'v_range': [['7.0.1', '']],
                                    'choices': [
                                        'TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA', 'TLS-RSA-WITH-DES-CBC-SHA',
                                        'TLS-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA256', 'TLS-RSA-WITH-AES-256-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA', 'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-RSA-WITH-DES-CBC-SHA', 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                        'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA', 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256', 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA', 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384', 'TLS-RSA-WITH-AES-128-GCM-SHA256', 'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-SEED-CBC-SHA', 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256', 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA', 'TLS-AES-128-GCM-SHA256',
                                        'TLS-AES-256-GCM-SHA384', 'TLS-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                                    ],
                                    'type': 'str'
                                },
                                'priority': {'v_range': [['7.0.1', '']], 'type': 'int'},
                                'versions': {
                                    'v_range': [['7.0.1', '']],
                                    'type': 'list',
                                    'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                                    'elements': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'ssl-dh-bits': {'v_range': [['7.0.1', '']], 'choices': ['768', '1024', '1536', '2048', '3072', '4096'], 'type': 'str'},
                        'ssl-max-version': {'v_range': [['7.0.1', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                        'ssl-min-version': {'v_range': [['7.0.1', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                        'ssl-vpn-web-portal': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'url-map': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'url-map-type': {'v_range': [['7.0.1', '']], 'choices': ['sub-string', 'wildcard', 'regex'], 'type': 'str'},
                        'virtual-host': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'application': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'ssl-renegotiation': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h2-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h3-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'quic': {
                            'v_range': [['7.4.1', '']],
                            'type': 'dict',
                            'options': {
                                'ack-delay-exponent': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'active-connection-id-limit': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'active-migration': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'grease-quic-bit': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-ack-delay': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-datagram-frame-size': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-idle-timeout': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-udp-payload-size': {'v_range': [['7.4.1', '']], 'type': 'int'}
                            }
                        }
                    },
                    'elements': 'dict'
                },
                'auth-portal': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-virtual-host': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'decrypted-traffic-mirror': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'log-blocked-traffic': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'add-vhost-domain-to-dnsdb': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-agent-detect': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-supported-max-version': {'v_range': [['7.2.2', '']], 'choices': ['http1', 'http2'], 'type': 'str'},
                'svr-pool-multiplex': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'svr-pool-server-max-request': {'v_range': [['7.2.2', '']], 'type': 'int'},
                'svr-pool-ttl': {'v_range': [['7.2.2', '']], 'type': 'int'},
                'svr-pool-server-max-concurrent-request': {'v_range': [['7.4.1', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_accessproxy'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
