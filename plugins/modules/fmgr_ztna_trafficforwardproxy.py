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
module: fmgr_ztna_trafficforwardproxy
short_description: Configure ZTNA traffic forward proxy.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "2.12.0"
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
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
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
    ztna_trafficforwardproxy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_portal:
                aliases: ['auth-portal']
                type: str
                description: Enable/disable authentication portal.
                choices:
                    - 'disable'
                    - 'enable'
            auth_virtual_host:
                aliases: ['auth-virtual-host']
                type: list
                elements: str
                description: Virtual host for authentication portal.
            decrypted_traffic_mirror:
                aliases: ['decrypted-traffic-mirror']
                type: list
                elements: str
                description: Decrypted traffic mirror.
            host:
                type: list
                elements: str
                description: Virtual or real host name.
            log_blocked_traffic:
                aliases: ['log-blocked-traffic']
                type: str
                description: Enable/disable logging of blocked traffic.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: ZTNA proxy name.
                required: true
            url_route:
                aliases: ['url-route']
                type: list
                elements: dict
                description: Url route.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    service_connector:
                        aliases: ['service-connector']
                        type: list
                        elements: str
                        description: Service connector.
                    url_pattern:
                        aliases: ['url-pattern']
                        type: str
                        description: Url pattern.
            vip:
                type: list
                elements: str
                description: Virtual IP name.
            ssl_client_session_state_max:
                aliases: ['ssl-client-session-state-max']
                type: int
                description: Ssl client session state max.
            ssl_send_empty_frags:
                aliases: ['ssl-send-empty-frags']
                type: str
                description: Ssl send empty frags.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server_max_version:
                aliases: ['ssl-server-max-version']
                type: str
                description: Ssl server max version.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'client'
                    - 'tls-1.3'
            ssl_accept_ffdhe_groups:
                aliases: ['ssl-accept-ffdhe-groups']
                type: str
                description: Ssl accept ffdhe groups.
                choices:
                    - 'disable'
                    - 'enable'
            empty_cert_action:
                aliases: ['empty-cert-action']
                type: str
                description: Empty cert action.
                choices:
                    - 'accept'
                    - 'block'
                    - 'accept-unmanageable'
            quic:
                type: dict
                description: Quic.
                suboptions:
                    ack_delay_exponent:
                        aliases: ['ack-delay-exponent']
                        type: int
                        description: Ack delay exponent.
                    active_connection_id_limit:
                        aliases: ['active-connection-id-limit']
                        type: int
                        description: Active connection id limit.
                    active_migration:
                        aliases: ['active-migration']
                        type: str
                        description: Active migration.
                        choices:
                            - 'disable'
                            - 'enable'
                    grease_quic_bit:
                        aliases: ['grease-quic-bit']
                        type: str
                        description: Grease quic bit.
                        choices:
                            - 'disable'
                            - 'enable'
                    max_ack_delay:
                        aliases: ['max-ack-delay']
                        type: int
                        description: Max ack delay.
                    max_datagram_frame_size:
                        aliases: ['max-datagram-frame-size']
                        type: int
                        description: Max datagram frame size.
                    max_idle_timeout:
                        aliases: ['max-idle-timeout']
                        type: int
                        description: Max idle timeout.
                    max_udp_payload_size:
                        aliases: ['max-udp-payload-size']
                        type: int
                        description: Max udp payload size.
            ssl_server_session_state_max:
                aliases: ['ssl-server-session-state-max']
                type: int
                description: Ssl server session state max.
            ssl_client_session_state_type:
                aliases: ['ssl-client-session-state-type']
                type: str
                description: Ssl client session state type.
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
            ssl_hpkp_age:
                aliases: ['ssl-hpkp-age']
                type: int
                description: Ssl hpkp age.
            ssl_hpkp_report_uri:
                aliases: ['ssl-hpkp-report-uri']
                type: str
                description: Ssl hpkp report uri.
            ssl_min_version:
                aliases: ['ssl-min-version']
                type: str
                description: Ssl min version.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_mode:
                aliases: ['ssl-mode']
                type: str
                description: Ssl mode.
                choices:
                    - 'half'
                    - 'full'
            ssl_client_session_state_timeout:
                aliases: ['ssl-client-session-state-timeout']
                type: int
                description: Ssl client session state timeout.
            ssl_hsts_age:
                aliases: ['ssl-hsts-age']
                type: int
                description: Ssl hsts age.
            interface:
                type: list
                elements: str
                description: Interface.
            ssl_client_renegotiation:
                aliases: ['ssl-client-renegotiation']
                type: str
                description: Ssl client renegotiation.
                choices:
                    - 'allow'
                    - 'deny'
                    - 'secure'
            ssl_server_session_state_timeout:
                aliases: ['ssl-server-session-state-timeout']
                type: int
                description: Ssl server session state timeout.
            ssl_server_min_version:
                aliases: ['ssl-server-min-version']
                type: str
                description: Ssl server min version.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'client'
                    - 'tls-1.3'
            ssl_cipher_suites:
                aliases: ['ssl-cipher-suites']
                type: list
                elements: dict
                description: Ssl cipher suites.
                suboptions:
                    cipher:
                        type: str
                        description: Cipher.
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
                        description: Priority.
                    versions:
                        type: list
                        elements: str
                        description: Versions.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssl_client_rekey_count:
                aliases: ['ssl-client-rekey-count']
                type: int
                description: Ssl client rekey count.
            svr_pool_server_max_request:
                aliases: ['svr-pool-server-max-request']
                type: int
                description: Svr pool server max request.
            ssl_dh_bits:
                aliases: ['ssl-dh-bits']
                type: str
                description: Ssl dh bits.
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
            port:
                type: str
                description: Port.
            ssl_http_match_host:
                aliases: ['ssl-http-match-host']
                type: str
                description: Ssl http match host.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server_session_state_type:
                aliases: ['ssl-server-session-state-type']
                type: str
                description: Ssl server session state type.
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
            status:
                type: str
                description: Status.
                choices:
                    - 'disable'
                    - 'enable'
            svr_pool_multiplex:
                aliases: ['svr-pool-multiplex']
                type: str
                description: Svr pool multiplex.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_hpkp:
                aliases: ['ssl-hpkp']
                type: str
                description: Ssl hpkp.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'report-only'
            ssl_hsts:
                aliases: ['ssl-hsts']
                type: str
                description: Ssl hsts.
                choices:
                    - 'disable'
                    - 'enable'
            svr_pool_server_max_concurrent_request:
                aliases: ['svr-pool-server-max-concurrent-request']
                type: int
                description: Svr pool server max concurrent request.
            h3_support:
                aliases: ['h3-support']
                type: str
                description: H3 support.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_http_location_conversion:
                aliases: ['ssl-http-location-conversion']
                type: str
                description: Ssl http location conversion.
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comment.
            ssl_pfs:
                aliases: ['ssl-pfs']
                type: str
                description: Ssl pfs.
                choices:
                    - 'require'
                    - 'deny'
                    - 'allow'
            ssl_hsts_include_subdomains:
                aliases: ['ssl-hsts-include-subdomains']
                type: str
                description: Ssl hsts include subdomains.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_certificate:
                aliases: ['ssl-certificate']
                type: list
                elements: str
                description: Ssl certificate.
            ssl_max_version:
                aliases: ['ssl-max-version']
                type: str
                description: Ssl max version.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_hpkp_backup:
                aliases: ['ssl-hpkp-backup']
                type: list
                elements: str
                description: Ssl hpkp backup.
            client_cert:
                aliases: ['client-cert']
                type: str
                description: Client cert.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_client_fallback:
                aliases: ['ssl-client-fallback']
                type: str
                description: Ssl client fallback.
                choices:
                    - 'disable'
                    - 'enable'
            vip6:
                type: list
                elements: str
                description: Virtual IPv6 name.
            ssl_algorithm:
                aliases: ['ssl-algorithm']
                type: str
                description: Ssl algorithm.
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
                    - 'custom'
            ssl_server_algorithm:
                aliases: ['ssl-server-algorithm']
                type: str
                description: Ssl server algorithm.
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
                    - 'custom'
                    - 'client'
            ssl_hpkp_include_subdomains:
                aliases: ['ssl-hpkp-include-subdomains']
                type: str
                description: Ssl hpkp include subdomains.
                choices:
                    - 'disable'
                    - 'enable'
            user_agent_detect:
                aliases: ['user-agent-detect']
                type: str
                description: User agent detect.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server_renegotiation:
                aliases: ['ssl-server-renegotiation']
                type: str
                description: Ssl server renegotiation.
                choices:
                    - 'disable'
                    - 'enable'
            svr_pool_ttl:
                aliases: ['svr-pool-ttl']
                type: int
                description: Svr pool ttl.
            ssl_server_cipher_suites:
                aliases: ['ssl-server-cipher-suites']
                type: list
                elements: dict
                description: Ssl server cipher suites.
                suboptions:
                    cipher:
                        type: str
                        description: Cipher.
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
                        description: Priority.
                    versions:
                        type: list
                        elements: str
                        description: Versions.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssl_hpkp_primary:
                aliases: ['ssl-hpkp-primary']
                type: list
                elements: str
                description: Ssl hpkp primary.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure ZTNA traffic forward proxy.
      fortinet.fortimanager.fmgr_ztna_trafficforwardproxy:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        ztna_trafficforwardproxy:
          name: "your value" # Required variable, string
          # auth_portal: <value in [disable, enable]>
          # auth_virtual_host: <list or string>
          # decrypted_traffic_mirror: <list or string>
          # host: <list or string>
          # log_blocked_traffic: <value in [disable, enable]>
          # url_route:
          #   - name: <string>
          #     service_connector: <list or string>
          #     url_pattern: <string>
          # vip: <list or string>
          # ssl_client_session_state_max: <integer>
          # ssl_send_empty_frags: <value in [disable, enable]>
          # ssl_server_max_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_accept_ffdhe_groups: <value in [disable, enable]>
          # empty_cert_action: <value in [accept, block, accept-unmanageable]>
          # quic:
          #   ack_delay_exponent: <integer>
          #   active_connection_id_limit: <integer>
          #   active_migration: <value in [disable, enable]>
          #   grease_quic_bit: <value in [disable, enable]>
          #   max_ack_delay: <integer>
          #   max_datagram_frame_size: <integer>
          #   max_idle_timeout: <integer>
          #   max_udp_payload_size: <integer>
          # ssl_server_session_state_max: <integer>
          # ssl_client_session_state_type: <value in [disable, time, count, ...]>
          # ssl_hpkp_age: <integer>
          # ssl_hpkp_report_uri: <string>
          # ssl_min_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_mode: <value in [half, full]>
          # ssl_client_session_state_timeout: <integer>
          # ssl_hsts_age: <integer>
          # interface: <list or string>
          # ssl_client_renegotiation: <value in [allow, deny, secure]>
          # ssl_server_session_state_timeout: <integer>
          # ssl_server_min_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_cipher_suites:
          #   - cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
          #     priority: <integer>
          #     versions:
          #       - "ssl-3.0"
          #       - "tls-1.0"
          #       - "tls-1.1"
          #       - "tls-1.2"
          #       - "tls-1.3"
          # ssl_client_rekey_count: <integer>
          # svr_pool_server_max_request: <integer>
          # ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          # port: <string>
          # ssl_http_match_host: <value in [disable, enable]>
          # ssl_server_session_state_type: <value in [disable, time, count, ...]>
          # status: <value in [disable, enable]>
          # svr_pool_multiplex: <value in [disable, enable]>
          # ssl_hpkp: <value in [disable, enable, report-only]>
          # ssl_hsts: <value in [disable, enable]>
          # svr_pool_server_max_concurrent_request: <integer>
          # h3_support: <value in [disable, enable]>
          # ssl_http_location_conversion: <value in [disable, enable]>
          # comment: <string>
          # ssl_pfs: <value in [require, deny, allow]>
          # ssl_hsts_include_subdomains: <value in [disable, enable]>
          # ssl_certificate: <list or string>
          # ssl_max_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_hpkp_backup: <list or string>
          # client_cert: <value in [disable, enable]>
          # ssl_client_fallback: <value in [disable, enable]>
          # vip6: <list or string>
          # ssl_algorithm: <value in [high, low, medium, ...]>
          # ssl_server_algorithm: <value in [high, low, medium, ...]>
          # ssl_hpkp_include_subdomains: <value in [disable, enable]>
          # user_agent_detect: <value in [disable, enable]>
          # ssl_server_renegotiation: <value in [disable, enable]>
          # svr_pool_ttl: <integer>
          # ssl_server_cipher_suites:
          #   - cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
          #     priority: <integer>
          #     versions:
          #       - "ssl-3.0"
          #       - "tls-1.0"
          #       - "tls-1.1"
          #       - "tls-1.2"
          #       - "tls-1.3"
          # ssl_hpkp_primary: <list or string>
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
        '/pm/config/adom/{adom}/obj/ztna/traffic-forward-proxy',
        '/pm/config/global/obj/ztna/traffic-forward-proxy'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'ztna_trafficforwardproxy': {
            'type': 'dict',
            'v_range': [['7.6.4', '']],
            'options': {
                'auth-portal': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-virtual-host': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'decrypted-traffic-mirror': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'host': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'log-blocked-traffic': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'str'},
                'url-route': {
                    'v_range': [['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'service-connector': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'url-pattern': {'v_range': [['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'vip': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-client-session-state-max': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'ssl-send-empty-frags': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-max-version': {
                    'v_range': [['7.6.4', '']],
                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'],
                    'type': 'str'
                },
                'ssl-accept-ffdhe-groups': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'empty-cert-action': {'v_range': [['7.6.4', '']], 'choices': ['accept', 'block', 'accept-unmanageable'], 'type': 'str'},
                'quic': {
                    'v_range': [['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'ack-delay-exponent': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'active-connection-id-limit': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'active-migration': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'grease-quic-bit': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-ack-delay': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'max-datagram-frame-size': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'max-idle-timeout': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'max-udp-payload-size': {'v_range': [['7.6.4', '']], 'type': 'int'}
                    }
                },
                'ssl-server-session-state-max': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'ssl-client-session-state-type': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'time', 'count', 'both'], 'type': 'str'},
                'ssl-hpkp-age': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'ssl-hpkp-report-uri': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'ssl-min-version': {'v_range': [['7.6.4', '']], 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-mode': {'v_range': [['7.6.4', '']], 'choices': ['half', 'full'], 'type': 'str'},
                'ssl-client-session-state-timeout': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'ssl-hsts-age': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'interface': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-client-renegotiation': {'v_range': [['7.6.4', '']], 'choices': ['allow', 'deny', 'secure'], 'type': 'str'},
                'ssl-server-session-state-timeout': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'ssl-server-min-version': {
                    'v_range': [['7.6.4', '']],
                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'],
                    'type': 'str'
                },
                'ssl-cipher-suites': {
                    'v_range': [['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'v_range': [['7.6.4', '']],
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
                        'priority': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'versions': {
                            'v_range': [['7.6.4', '']],
                            'type': 'list',
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ssl-client-rekey-count': {'v_range': [['7.6.4', '']], 'no_log': True, 'type': 'int'},
                'svr-pool-server-max-request': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'ssl-dh-bits': {'v_range': [['7.6.4', '']], 'choices': ['768', '1024', '1536', '2048', '3072', '4096'], 'type': 'str'},
                'port': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'ssl-http-match-host': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-session-state-type': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'time', 'count', 'both'], 'type': 'str'},
                'status': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'svr-pool-multiplex': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-hpkp': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable', 'report-only'], 'type': 'str'},
                'ssl-hsts': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'svr-pool-server-max-concurrent-request': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'h3-support': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-http-location-conversion': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'ssl-pfs': {'v_range': [['7.6.4', '']], 'choices': ['require', 'deny', 'allow'], 'type': 'str'},
                'ssl-hsts-include-subdomains': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-certificate': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-max-version': {'v_range': [['7.6.4', '']], 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-hpkp-backup': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'client-cert': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-client-fallback': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vip6': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-algorithm': {'v_range': [['7.6.4', '']], 'choices': ['high', 'low', 'medium', 'custom'], 'type': 'str'},
                'ssl-server-algorithm': {'v_range': [['7.6.4', '']], 'choices': ['high', 'low', 'medium', 'custom', 'client'], 'type': 'str'},
                'ssl-hpkp-include-subdomains': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-agent-detect': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-renegotiation': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'svr-pool-ttl': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'ssl-server-cipher-suites': {
                    'v_range': [['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'v_range': [['7.6.4', '']],
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
                        'priority': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'versions': {
                            'v_range': [['7.6.4', '']],
                            'type': 'list',
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ssl-hpkp-primary': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ztna_trafficforwardproxy'),
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
