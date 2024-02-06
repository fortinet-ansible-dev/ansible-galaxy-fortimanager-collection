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
module: fmgr_firewall_accessproxy6_apigateway6
short_description: Set IPv6 API Gateway.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    access-proxy6:
        description: Deprecated, please use "access_proxy6"
        type: str
    access_proxy6:
        description: The parameter (access-proxy6) in requested url.
        type: str
    firewall_accessproxy6_apigateway6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            application:
                type: raw
                description: (list) No description.
            http-cookie-age:
                type: int
                description: Deprecated, please rename it to http_cookie_age. Time in minutes that client web browsers should keep a cookie.
            http-cookie-domain:
                type: str
                description: Deprecated, please rename it to http_cookie_domain. Domain that HTTP cookie persistence should apply to.
            http-cookie-domain-from-host:
                type: str
                description: Deprecated, please rename it to http_cookie_domain_from_host. Enable/disable use of HTTP cookie domain from host field in ...
                choices:
                    - 'disable'
                    - 'enable'
            http-cookie-generation:
                type: int
                description: Deprecated, please rename it to http_cookie_generation. Generation of HTTP cookie to be accepted.
            http-cookie-path:
                type: str
                description: Deprecated, please rename it to http_cookie_path. Limit HTTP cookie persistence to the specified path.
            http-cookie-share:
                type: str
                description: Deprecated, please rename it to http_cookie_share. Control sharing of cookies across API Gateway.
                choices:
                    - 'disable'
                    - 'same-ip'
            https-cookie-secure:
                type: str
                description: Deprecated, please rename it to https_cookie_secure. Enable/disable verification that inserted HTTPS cookies are secure.
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: int
                description: API Gateway ID.
                required: true
            ldb-method:
                type: str
                description: Deprecated, please rename it to ldb_method. Method used to distribute sessions to real servers.
                choices:
                    - 'static'
                    - 'round-robin'
                    - 'weighted'
                    - 'first-alive'
                    - 'http-host'
            persistence:
                type: str
                description: Configure how to make sure that clients connect to the same server every time they make a request that is part of the same...
                choices:
                    - 'none'
                    - 'http-cookie'
            realservers:
                type: list
                elements: dict
                description: No description.
                suboptions:
                    addr-type:
                        type: str
                        description: Deprecated, please rename it to addr_type. Type of address.
                        choices:
                            - 'fqdn'
                            - 'ip'
                    address:
                        type: str
                        description: Address or address group of the real server.
                    domain:
                        type: str
                        description: Wildcard domain name of the real server.
                    health-check:
                        type: str
                        description: Deprecated, please rename it to health_check. Enable to check the responsiveness of the real server before forward...
                        choices:
                            - 'disable'
                            - 'enable'
                    health-check-proto:
                        type: str
                        description: Deprecated, please rename it to health_check_proto. Protocol of the health check monitor to use when polling to de...
                        choices:
                            - 'ping'
                            - 'http'
                            - 'tcp-connect'
                    holddown-interval:
                        type: str
                        description: Deprecated, please rename it to holddown_interval. Enable/disable holddown timer.
                        choices:
                            - 'disable'
                            - 'enable'
                    http-host:
                        type: str
                        description: Deprecated, please rename it to http_host. HTTP server domain name in HTTP header.
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
                    ssh-client-cert:
                        type: str
                        description: Deprecated, please rename it to ssh_client_cert. Set access-proxy SSH client certificate profile.
                    ssh-host-key:
                        type: raw
                        description: (list) Deprecated, please rename it to ssh_host_key.
                    ssh-host-key-validation:
                        type: str
                        description: Deprecated, please rename it to ssh_host_key_validation. Enable/disable SSH real server host key validation.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic...
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
                    translate-host:
                        type: str
                        description: Deprecated, please rename it to translate_host. Enable/disable translation of hostname/IP from virtual server to r...
                        choices:
                            - 'disable'
                            - 'enable'
                    external-auth:
                        type: str
                        description: Deprecated, please rename it to external_auth. Enable/disable use of external browser as user-agent for SAML user ...
                        choices:
                            - 'disable'
                            - 'enable'
                    tunnel-encryption:
                        type: str
                        description: Deprecated, please rename it to tunnel_encryption. Tunnel encryption.
                        choices:
                            - 'disable'
                            - 'enable'
            saml-redirect:
                type: str
                description: Deprecated, please rename it to saml_redirect. Enable/disable SAML redirection after successful authentication.
                choices:
                    - 'disable'
                    - 'enable'
            saml-server:
                type: str
                description: Deprecated, please rename it to saml_server. SAML service provider configuration for VIP authentication.
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
            ssl-algorithm:
                type: str
                description: Deprecated, please rename it to ssl_algorithm. Permitted encryption algorithms for the server side of SSL full mode sessio...
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
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
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssl-dh-bits:
                type: str
                description: Deprecated, please rename it to ssl_dh_bits. Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SS...
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
            ssl-max-version:
                type: str
                description: Deprecated, please rename it to ssl_max_version. Highest SSL/TLS version acceptable from a server.
                choices:
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl-min-version:
                type: str
                description: Deprecated, please rename it to ssl_min_version. Lowest SSL/TLS version acceptable from a server.
                choices:
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl-vpn-web-portal:
                type: str
                description: Deprecated, please rename it to ssl_vpn_web_portal. SSL-VPN web portal.
            url-map:
                type: str
                description: Deprecated, please rename it to url_map. URL pattern to match.
            url-map-type:
                type: str
                description: Deprecated, please rename it to url_map_type. Type of url-map.
                choices:
                    - 'sub-string'
                    - 'wildcard'
                    - 'regex'
            virtual-host:
                type: str
                description: Deprecated, please rename it to virtual_host. Virtual host.
            ssl-renegotiation:
                type: str
                description: Deprecated, please rename it to ssl_renegotiation. Enable/disable secure renegotiation to comply with RFC 5746.
                choices:
                    - 'disable'
                    - 'enable'
            h2-support:
                type: str
                description: Deprecated, please rename it to h2_support. HTTP2 support, default=Enable.
                choices:
                    - 'disable'
                    - 'enable'
            h3-support:
                type: str
                description: Deprecated, please rename it to h3_support. HTTP3/QUIC support, default=Disable.
                choices:
                    - 'disable'
                    - 'enable'
            quic:
                type: dict
                description: No description.
                suboptions:
                    ack-delay-exponent:
                        type: int
                        description: Deprecated, please rename it to ack_delay_exponent. ACK delay exponent
                    active-connection-id-limit:
                        type: int
                        description: Deprecated, please rename it to active_connection_id_limit. Active connection ID limit
                    active-migration:
                        type: str
                        description: Deprecated, please rename it to active_migration. Enable/disable active migration
                        choices:
                            - 'disable'
                            - 'enable'
                    grease-quic-bit:
                        type: str
                        description: Deprecated, please rename it to grease_quic_bit. Enable/disable grease QUIC bit
                        choices:
                            - 'disable'
                            - 'enable'
                    max-ack-delay:
                        type: int
                        description: Deprecated, please rename it to max_ack_delay. Maximum ACK delay in milliseconds
                    max-datagram-frame-size:
                        type: int
                        description: Deprecated, please rename it to max_datagram_frame_size. Maximum datagram frame size in bytes
                    max-idle-timeout:
                        type: int
                        description: Deprecated, please rename it to max_idle_timeout. Maximum idle timeout milliseconds
                    max-udp-payload-size:
                        type: int
                        description: Deprecated, please rename it to max_udp_payload_size. Maximum UDP payload size in bytes
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
    - name: Set IPv6 API Gateway.
      fortinet.fortimanager.fmgr_firewall_accessproxy6_apigateway6:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        access_proxy6: <your own value>
        state: present # <value in [present, absent]>
        firewall_accessproxy6_apigateway6:
          application: <list or string>
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
                - tls-1.0
                - tls-1.1
                - tls-1.2
                - tls-1.3
          ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          ssl_max_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
          ssl_min_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
          ssl_vpn_web_portal: <string>
          url_map: <string>
          url_map_type: <value in [sub-string, wildcard, regex]>
          virtual_host: <string>
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
        '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6',
        '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}',
        '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}'
    ]

    url_params = ['adom', 'access-proxy6']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'access-proxy6': {'type': 'str', 'api_name': 'access_proxy6'},
        'access_proxy6': {'type': 'str'},
        'firewall_accessproxy6_apigateway6': {
            'type': 'dict',
            'v_range': [['7.2.1', '']],
            'options': {
                'application': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'http-cookie-age': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'http-cookie-domain': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'http-cookie-domain-from-host': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-cookie-generation': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'http-cookie-path': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'http-cookie-share': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'same-ip'], 'type': 'str'},
                'https-cookie-secure': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'v_range': [['7.2.1', '']], 'required': True, 'type': 'int'},
                'ldb-method': {'v_range': [['7.2.1', '']], 'choices': ['static', 'round-robin', 'weighted', 'first-alive', 'http-host'], 'type': 'str'},
                'persistence': {'v_range': [['7.2.1', '']], 'choices': ['none', 'http-cookie'], 'type': 'str'},
                'realservers': {
                    'v_range': [['7.2.1', '']],
                    'type': 'list',
                    'options': {
                        'addr-type': {'v_range': [['7.2.1', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                        'address': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'domain': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'health-check': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'health-check-proto': {'v_range': [['7.2.1', '']], 'choices': ['ping', 'http', 'tcp-connect'], 'type': 'str'},
                        'holddown-interval': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-host': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'mappedport': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'port': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'ssh-client-cert': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'ssh-host-key': {'v_range': [['7.2.1', '']], 'no_log': True, 'type': 'raw'},
                        'ssh-host-key-validation': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['7.2.1', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                        'type': {'v_range': [['7.2.1', '']], 'choices': ['tcp-forwarding', 'ssh'], 'type': 'str'},
                        'weight': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'translate-host': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'external-auth': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tunnel-encryption': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'saml-redirect': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'saml-server': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'service': {'v_range': [['7.2.1', '']], 'choices': ['http', 'https', 'tcp-forwarding', 'samlsp', 'web-portal', 'saas'], 'type': 'str'},
                'ssl-algorithm': {'v_range': [['7.2.1', '']], 'choices': ['high', 'medium', 'low'], 'type': 'str'},
                'ssl-cipher-suites': {
                    'v_range': [['7.2.1', '']],
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'v_range': [['7.2.1', '']],
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
                        'priority': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'versions': {
                            'v_range': [['7.2.1', '']],
                            'type': 'list',
                            'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ssl-dh-bits': {'v_range': [['7.2.1', '']], 'choices': ['768', '1024', '1536', '2048', '3072', '4096'], 'type': 'str'},
                'ssl-max-version': {'v_range': [['7.2.1', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-min-version': {'v_range': [['7.2.1', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-vpn-web-portal': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'url-map': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'url-map-type': {'v_range': [['7.2.1', '']], 'choices': ['sub-string', 'wildcard', 'regex'], 'type': 'str'},
                'virtual-host': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'ssl-renegotiation': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h2-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h3-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'quic': {
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
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_accessproxy6_apigateway6'),
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
