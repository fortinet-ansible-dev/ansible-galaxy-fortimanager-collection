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
module: fmgr_vap
short_description: Configure Virtual Access Points
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
    vap:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _centmgmt:
                type: str
                description: _Centmgmt.
                choices:
                    - 'disable'
                    - 'enable'
            _dhcp_svr_id:
                type: str
                description: _Dhcp_Svr_Id.
            _intf_allowaccess:
                type: list
                elements: str
                description: _Intf_Allowaccess.
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
                    - 'fgfm'
                    - 'auto-ipsec'
                    - 'radius-acct'
                    - 'probe-response'
                    - 'capwap'
                    - 'dnp'
                    - 'ftm'
                    - 'fabric'
                    - 'speed-test'
            _intf_device-identification:
                type: str
                description: Deprecated, please rename it to _intf_device_identification. _Intf_Device-Identification.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_device-netscan:
                type: str
                description: Deprecated, please rename it to _intf_device_netscan. _Intf_Device-Netscan.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_dhcp-relay-ip:
                type: raw
                description: (list) Deprecated, please rename it to _intf_dhcp_relay_ip. _Intf_Dhcp-Relay-Ip.
            _intf_dhcp-relay-service:
                type: str
                description: Deprecated, please rename it to _intf_dhcp_relay_service. _Intf_Dhcp-Relay-Service.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_dhcp-relay-type:
                type: str
                description: Deprecated, please rename it to _intf_dhcp_relay_type. _Intf_Dhcp-Relay-Type.
                choices:
                    - 'regular'
                    - 'ipsec'
            _intf_dhcp6-relay-ip:
                type: str
                description: Deprecated, please rename it to _intf_dhcp6_relay_ip. _Intf_Dhcp6-Relay-Ip.
            _intf_dhcp6-relay-service:
                type: str
                description: Deprecated, please rename it to _intf_dhcp6_relay_service. _Intf_Dhcp6-Relay-Service.
                choices:
                    - 'disable'
                    - 'enable'
            _intf_dhcp6-relay-type:
                type: str
                description: Deprecated, please rename it to _intf_dhcp6_relay_type. _Intf_Dhcp6-Relay-Type.
                choices:
                    - 'regular'
            _intf_ip:
                type: str
                description: _Intf_Ip.
            _intf_ip6-address:
                type: str
                description: Deprecated, please rename it to _intf_ip6_address. _Intf_Ip6-Address.
            _intf_ip6-allowaccess:
                type: list
                elements: str
                description: Deprecated, please rename it to _intf_ip6_allowaccess. _Intf_Ip6-Allowaccess.
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
                    - 'any'
                    - 'fgfm'
                    - 'capwap'
            _intf_listen-forticlient-connection:
                type: str
                description: Deprecated, please rename it to _intf_listen_forticlient_connection. _Intf_Listen-Forticlient-Connection.
                choices:
                    - 'disable'
                    - 'enable'
            acct-interim-interval:
                type: int
                description: Deprecated, please rename it to acct_interim_interval. WiFi RADIUS accounting interim interval
            alias:
                type: str
                description: Alias.
            auth:
                type: str
                description: Authentication protocol.
                choices:
                    - 'PSK'
                    - 'psk'
                    - 'RADIUS'
                    - 'radius'
                    - 'usergroup'
            broadcast-ssid:
                type: str
                description: Deprecated, please rename it to broadcast_ssid. Enable/disable broadcasting the SSID
                choices:
                    - 'disable'
                    - 'enable'
            broadcast-suppression:
                type: list
                elements: str
                description: Deprecated, please rename it to broadcast_suppression. Optional suppression of broadcast messages.
                choices:
                    - 'dhcp'
                    - 'arp'
                    - 'dhcp2'
                    - 'arp2'
                    - 'netbios-ns'
                    - 'netbios-ds'
                    - 'arp3'
                    - 'dhcp-up'
                    - 'dhcp-down'
                    - 'arp-known'
                    - 'arp-unknown'
                    - 'arp-reply'
                    - 'ipv6'
                    - 'dhcp-starvation'
                    - 'arp-poison'
                    - 'all-other-mc'
                    - 'all-other-bc'
                    - 'arp-proxy'
                    - 'dhcp-ucast'
            captive-portal-ac-name:
                type: str
                description: Deprecated, please rename it to captive_portal_ac_name. Local-bridging captive portal ac-name.
            captive-portal-macauth-radius-secret:
                type: raw
                description: (list) Deprecated, please rename it to captive_portal_macauth_radius_secret. Secret key to access the macauth RADIUS server.
            captive-portal-macauth-radius-server:
                type: str
                description: Deprecated, please rename it to captive_portal_macauth_radius_server. Captive portal external RADIUS server domain name or...
            captive-portal-radius-secret:
                type: raw
                description: (list) Deprecated, please rename it to captive_portal_radius_secret. Secret key to access the RADIUS server.
            captive-portal-radius-server:
                type: str
                description: Deprecated, please rename it to captive_portal_radius_server. Captive portal RADIUS server domain name or IP address.
            captive-portal-session-timeout-interval:
                type: int
                description: Deprecated, please rename it to captive_portal_session_timeout_interval. Session timeout interval
            dhcp-lease-time:
                type: int
                description: Deprecated, please rename it to dhcp_lease_time. DHCP lease time in seconds for NAT IP address.
            dhcp-option82-circuit-id-insertion:
                type: str
                description: Deprecated, please rename it to dhcp_option82_circuit_id_insertion. Enable/disable DHCP option 82 circuit-id insert
                choices:
                    - 'disable'
                    - 'style-1'
                    - 'style-2'
                    - 'style-3'
            dhcp-option82-insertion:
                type: str
                description: Deprecated, please rename it to dhcp_option82_insertion. Enable/disable DHCP option 82 insert
                choices:
                    - 'disable'
                    - 'enable'
            dhcp-option82-remote-id-insertion:
                type: str
                description: Deprecated, please rename it to dhcp_option82_remote_id_insertion. Enable/disable DHCP option 82 remote-id insert
                choices:
                    - 'disable'
                    - 'style-1'
            dynamic-vlan:
                type: str
                description: Deprecated, please rename it to dynamic_vlan. Enable/disable dynamic VLAN assignment.
                choices:
                    - 'disable'
                    - 'enable'
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic_Mapping.
                suboptions:
                    _centmgmt:
                        type: str
                        description: _Centmgmt.
                        choices:
                            - 'disable'
                            - 'enable'
                    _dhcp_svr_id:
                        type: str
                        description: _Dhcp_Svr_Id.
                    _intf_allowaccess:
                        type: list
                        elements: str
                        description: _Intf_Allowaccess.
                        choices:
                            - 'https'
                            - 'ping'
                            - 'ssh'
                            - 'snmp'
                            - 'http'
                            - 'telnet'
                            - 'fgfm'
                            - 'auto-ipsec'
                            - 'radius-acct'
                            - 'probe-response'
                            - 'capwap'
                            - 'dnp'
                            - 'ftm'
                            - 'fabric'
                            - 'speed-test'
                    _intf_device-identification:
                        type: str
                        description: Deprecated, please rename it to _intf_device_identification. _Intf_Device-Identification.
                        choices:
                            - 'disable'
                            - 'enable'
                    _intf_device-netscan:
                        type: str
                        description: Deprecated, please rename it to _intf_device_netscan. _Intf_Device-Netscan.
                        choices:
                            - 'disable'
                            - 'enable'
                    _intf_dhcp-relay-ip:
                        type: raw
                        description: (list) Deprecated, please rename it to _intf_dhcp_relay_ip. _Intf_Dhcp-Relay-Ip.
                    _intf_dhcp-relay-service:
                        type: str
                        description: Deprecated, please rename it to _intf_dhcp_relay_service. _Intf_Dhcp-Relay-Service.
                        choices:
                            - 'disable'
                            - 'enable'
                    _intf_dhcp-relay-type:
                        type: str
                        description: Deprecated, please rename it to _intf_dhcp_relay_type. _Intf_Dhcp-Relay-Type.
                        choices:
                            - 'regular'
                            - 'ipsec'
                    _intf_dhcp6-relay-ip:
                        type: str
                        description: Deprecated, please rename it to _intf_dhcp6_relay_ip. _Intf_Dhcp6-Relay-Ip.
                    _intf_dhcp6-relay-service:
                        type: str
                        description: Deprecated, please rename it to _intf_dhcp6_relay_service. _Intf_Dhcp6-Relay-Service.
                        choices:
                            - 'disable'
                            - 'enable'
                    _intf_dhcp6-relay-type:
                        type: str
                        description: Deprecated, please rename it to _intf_dhcp6_relay_type. _Intf_Dhcp6-Relay-Type.
                        choices:
                            - 'regular'
                    _intf_ip:
                        type: str
                        description: _Intf_Ip.
                    _intf_ip6-address:
                        type: str
                        description: Deprecated, please rename it to _intf_ip6_address. _Intf_Ip6-Address.
                    _intf_ip6-allowaccess:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to _intf_ip6_allowaccess. _Intf_Ip6-Allowaccess.
                        choices:
                            - 'https'
                            - 'ping'
                            - 'ssh'
                            - 'snmp'
                            - 'http'
                            - 'telnet'
                            - 'any'
                            - 'fgfm'
                            - 'capwap'
                    _intf_listen-forticlient-connection:
                        type: str
                        description: Deprecated, please rename it to _intf_listen_forticlient_connection. _Intf_Listen-Forticlient-Connection.
                        choices:
                            - 'disable'
                            - 'enable'
                    _scope:
                        type: list
                        elements: dict
                        description: _Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    acct-interim-interval:
                        type: int
                        description: Deprecated, please rename it to acct_interim_interval. WiFi RADIUS accounting interim interval
                    address-group:
                        type: str
                        description: Deprecated, please rename it to address_group. Address group ID.
                    alias:
                        type: str
                        description: Alias.
                    atf-weight:
                        type: int
                        description: Deprecated, please rename it to atf_weight. Airtime weight in percentage
                    auth:
                        type: str
                        description: Authentication protocol.
                        choices:
                            - 'PSK'
                            - 'psk'
                            - 'RADIUS'
                            - 'radius'
                            - 'usergroup'
                    broadcast-ssid:
                        type: str
                        description: Deprecated, please rename it to broadcast_ssid. Enable/disable broadcasting the SSID
                        choices:
                            - 'disable'
                            - 'enable'
                    broadcast-suppression:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to broadcast_suppression. Optional suppression of broadcast messages.
                        choices:
                            - 'dhcp'
                            - 'arp'
                            - 'dhcp2'
                            - 'arp2'
                            - 'netbios-ns'
                            - 'netbios-ds'
                            - 'arp3'
                            - 'dhcp-up'
                            - 'dhcp-down'
                            - 'arp-known'
                            - 'arp-unknown'
                            - 'arp-reply'
                            - 'ipv6'
                            - 'dhcp-starvation'
                            - 'arp-poison'
                            - 'all-other-mc'
                            - 'all-other-bc'
                            - 'arp-proxy'
                            - 'dhcp-ucast'
                    captive-portal-ac-name:
                        type: str
                        description: Deprecated, please rename it to captive_portal_ac_name. Local-bridging captive portal ac-name.
                    captive-portal-macauth-radius-secret:
                        type: raw
                        description: (list) Deprecated, please rename it to captive_portal_macauth_radius_secret. Secret key to access the macauth RADI...
                    captive-portal-macauth-radius-server:
                        type: str
                        description: Deprecated, please rename it to captive_portal_macauth_radius_server. Captive portal external RADIUS server domain...
                    captive-portal-radius-secret:
                        type: raw
                        description: (list) Deprecated, please rename it to captive_portal_radius_secret. Secret key to access the RADIUS server.
                    captive-portal-radius-server:
                        type: str
                        description: Deprecated, please rename it to captive_portal_radius_server. Captive portal RADIUS server domain name or IP address.
                    captive-portal-session-timeout-interval:
                        type: int
                        description: Deprecated, please rename it to captive_portal_session_timeout_interval. Session timeout interval
                    client-count:
                        type: int
                        description: Deprecated, please rename it to client_count. Client-Count.
                    dhcp-lease-time:
                        type: int
                        description: Deprecated, please rename it to dhcp_lease_time. DHCP lease time in seconds for NAT IP address.
                    dhcp-option82-circuit-id-insertion:
                        type: str
                        description: Deprecated, please rename it to dhcp_option82_circuit_id_insertion. Enable/disable DHCP option 82 circuit-id insert
                        choices:
                            - 'disable'
                            - 'style-1'
                            - 'style-2'
                            - 'style-3'
                    dhcp-option82-insertion:
                        type: str
                        description: Deprecated, please rename it to dhcp_option82_insertion. Enable/disable DHCP option 82 insert
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp-option82-remote-id-insertion:
                        type: str
                        description: Deprecated, please rename it to dhcp_option82_remote_id_insertion. Enable/disable DHCP option 82 remote-id insert
                        choices:
                            - 'disable'
                            - 'style-1'
                    dynamic-vlan:
                        type: str
                        description: Deprecated, please rename it to dynamic_vlan. Enable/disable dynamic VLAN assignment.
                        choices:
                            - 'disable'
                            - 'enable'
                    eap-reauth:
                        type: str
                        description: Deprecated, please rename it to eap_reauth. Enable/disable EAP re-authentication for WPA-Enterprise security.
                        choices:
                            - 'disable'
                            - 'enable'
                    eap-reauth-intv:
                        type: int
                        description: Deprecated, please rename it to eap_reauth_intv. EAP re-authentication interval
                    eapol-key-retries:
                        type: str
                        description: Deprecated, please rename it to eapol_key_retries. Enable/disable retransmission of EAPOL-Key frames
                        choices:
                            - 'disable'
                            - 'enable'
                    encrypt:
                        type: str
                        description: Encryption protocol to use
                        choices:
                            - 'TKIP'
                            - 'AES'
                            - 'TKIP-AES'
                    external-fast-roaming:
                        type: str
                        description: Deprecated, please rename it to external_fast_roaming. Enable/disable fast roaming or pre-authentication with exte...
                        choices:
                            - 'disable'
                            - 'enable'
                    external-logout:
                        type: str
                        description: Deprecated, please rename it to external_logout. URL of external authentication logout server.
                    external-web:
                        type: str
                        description: Deprecated, please rename it to external_web. URL of external authentication web server.
                    fast-bss-transition:
                        type: str
                        description: Deprecated, please rename it to fast_bss_transition. Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    fast-roaming:
                        type: str
                        description: Deprecated, please rename it to fast_roaming. Enable/disable fast-roaming, or pre-authentication, where supported ...
                        choices:
                            - 'disable'
                            - 'enable'
                    ft-mobility-domain:
                        type: int
                        description: Deprecated, please rename it to ft_mobility_domain. Mobility domain identifier in FT
                    ft-over-ds:
                        type: str
                        description: Deprecated, please rename it to ft_over_ds. Enable/disable FT over the Distribution System
                        choices:
                            - 'disable'
                            - 'enable'
                    ft-r0-key-lifetime:
                        type: int
                        description: Deprecated, please rename it to ft_r0_key_lifetime. Lifetime of the PMK-R0 key in FT, 1-65535 minutes.
                    gtk-rekey:
                        type: str
                        description: Deprecated, please rename it to gtk_rekey. Enable/disable GTK rekey for WPA security.
                        choices:
                            - 'disable'
                            - 'enable'
                    gtk-rekey-intv:
                        type: int
                        description: Deprecated, please rename it to gtk_rekey_intv. GTK rekey interval
                    hotspot20-profile:
                        type: str
                        description: Deprecated, please rename it to hotspot20_profile. Hotspot 2.
                    intra-vap-privacy:
                        type: str
                        description: Deprecated, please rename it to intra_vap_privacy. Enable/disable blocking communication between clients on the sa...
                        choices:
                            - 'disable'
                            - 'enable'
                    ip:
                        type: str
                        description: IP address and subnet mask for the local standalone NAT subnet.
                    key:
                        type: raw
                        description: (list) WEP Key.
                    keyindex:
                        type: int
                        description: WEP key index
                    ldpc:
                        type: str
                        description: VAP low-density parity-check
                        choices:
                            - 'disable'
                            - 'tx'
                            - 'rx'
                            - 'rxtx'
                    local-authentication:
                        type: str
                        description: Deprecated, please rename it to local_authentication. Enable/disable AP local authentication.
                        choices:
                            - 'disable'
                            - 'enable'
                    local-bridging:
                        type: str
                        description: Deprecated, please rename it to local_bridging. Enable/disable bridging of wireless and Ethernet interfaces on the...
                        choices:
                            - 'disable'
                            - 'enable'
                    local-lan:
                        type: str
                        description: Deprecated, please rename it to local_lan. Allow/deny traffic destined for a Class A, B, or C private IP address
                        choices:
                            - 'deny'
                            - 'allow'
                    local-standalone:
                        type: str
                        description: Deprecated, please rename it to local_standalone. Enable/disable AP local standalone
                        choices:
                            - 'disable'
                            - 'enable'
                    local-standalone-nat:
                        type: str
                        description: Deprecated, please rename it to local_standalone_nat. Enable/disable AP local standalone NAT mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    local-switching:
                        type: str
                        description: Deprecated, please rename it to local_switching. Local-Switching.
                        choices:
                            - 'disable'
                            - 'enable'
                    mac-auth-bypass:
                        type: str
                        description: Deprecated, please rename it to mac_auth_bypass. Enable/disable MAC authentication bypass.
                        choices:
                            - 'disable'
                            - 'enable'
                    mac-filter:
                        type: str
                        description: Deprecated, please rename it to mac_filter. Enable/disable MAC filtering to block wireless clients by mac address.
                        choices:
                            - 'disable'
                            - 'enable'
                    mac-filter-policy-other:
                        type: str
                        description: Deprecated, please rename it to mac_filter_policy_other. Allow or block clients with MAC addresses that are not in...
                        choices:
                            - 'deny'
                            - 'allow'
                    max-clients:
                        type: int
                        description: Deprecated, please rename it to max_clients. Maximum number of clients that can connect simultaneously to the VAP
                    max-clients-ap:
                        type: int
                        description: Deprecated, please rename it to max_clients_ap. Maximum number of clients that can connect simultaneously to the V...
                    me-disable-thresh:
                        type: int
                        description: Deprecated, please rename it to me_disable_thresh. Disable multicast enhancement when this many clients are receiv...
                    mesh-backhaul:
                        type: str
                        description: Deprecated, please rename it to mesh_backhaul. Enable/disable using this VAP as a WiFi mesh backhaul
                        choices:
                            - 'disable'
                            - 'enable'
                    mpsk:
                        type: str
                        description: Enable/disable multiple PSK authentication.
                        choices:
                            - 'disable'
                            - 'enable'
                    mpsk-concurrent-clients:
                        type: int
                        description: Deprecated, please rename it to mpsk_concurrent_clients. Maximum number of concurrent clients that connect using t...
                    multicast-enhance:
                        type: str
                        description: Deprecated, please rename it to multicast_enhance. Enable/disable converting multicast to unicast to improve perfo...
                        choices:
                            - 'disable'
                            - 'enable'
                    multicast-rate:
                        type: str
                        description: Deprecated, please rename it to multicast_rate. Multicast rate
                        choices:
                            - '0'
                            - '6000'
                            - '12000'
                            - '24000'
                    okc:
                        type: str
                        description: Enable/disable Opportunistic Key Caching
                        choices:
                            - 'disable'
                            - 'enable'
                    owe-groups:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to owe_groups. OWE-Groups.
                        choices:
                            - '19'
                            - '20'
                            - '21'
                    owe-transition:
                        type: str
                        description: Deprecated, please rename it to owe_transition. Enable/disable OWE transition mode support.
                        choices:
                            - 'disable'
                            - 'enable'
                    owe-transition-ssid:
                        type: str
                        description: Deprecated, please rename it to owe_transition_ssid. OWE transition mode peer SSID.
                    passphrase:
                        type: raw
                        description: (list) WPA pre-shared key
                    pmf:
                        type: str
                        description: Protected Management Frames
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'optional'
                    pmf-assoc-comeback-timeout:
                        type: int
                        description: Deprecated, please rename it to pmf_assoc_comeback_timeout. Protected Management Frames
                    pmf-sa-query-retry-timeout:
                        type: int
                        description: Deprecated, please rename it to pmf_sa_query_retry_timeout. Protected Management Frames
                    portal-message-override-group:
                        type: str
                        description: Deprecated, please rename it to portal_message_override_group. Replacement message group for this VAP
                    portal-type:
                        type: str
                        description: Deprecated, please rename it to portal_type. Captive portal functionality.
                        choices:
                            - 'auth'
                            - 'auth+disclaimer'
                            - 'disclaimer'
                            - 'email-collect'
                            - 'cmcc'
                            - 'cmcc-macauth'
                            - 'auth-mac'
                            - 'external-auth'
                            - 'external-macauth'
                    probe-resp-suppression:
                        type: str
                        description: Deprecated, please rename it to probe_resp_suppression. Enable/disable probe response suppression
                        choices:
                            - 'disable'
                            - 'enable'
                    probe-resp-threshold:
                        type: str
                        description: Deprecated, please rename it to probe_resp_threshold. Minimum signal level/threshold in dBm required for the AP re...
                    ptk-rekey:
                        type: str
                        description: Deprecated, please rename it to ptk_rekey. Enable/disable PTK rekey for WPA-Enterprise security.
                        choices:
                            - 'disable'
                            - 'enable'
                    ptk-rekey-intv:
                        type: int
                        description: Deprecated, please rename it to ptk_rekey_intv. PTK rekey interval
                    qos-profile:
                        type: str
                        description: Deprecated, please rename it to qos_profile. Quality of service profile name.
                    quarantine:
                        type: str
                        description: Enable/disable station quarantine
                        choices:
                            - 'disable'
                            - 'enable'
                    radio-2g-threshold:
                        type: str
                        description: Deprecated, please rename it to radio_2g_threshold. Minimum signal level/threshold in dBm required for the AP resp...
                    radio-5g-threshold:
                        type: str
                        description: Deprecated, please rename it to radio_5g_threshold. Minimum signal level/threshold in dBm required for the AP resp...
                    radio-sensitivity:
                        type: str
                        description: Deprecated, please rename it to radio_sensitivity. Enable/disable software radio sensitivity
                        choices:
                            - 'disable'
                            - 'enable'
                    radius-mac-auth:
                        type: str
                        description: Deprecated, please rename it to radius_mac_auth. Enable/disable RADIUS-based MAC authentication of clients
                        choices:
                            - 'disable'
                            - 'enable'
                    radius-mac-auth-server:
                        type: str
                        description: Deprecated, please rename it to radius_mac_auth_server. RADIUS-based MAC authentication server.
                    radius-mac-auth-usergroups:
                        type: raw
                        description: (list) Deprecated, please rename it to radius_mac_auth_usergroups. Selective user groups that are permitted for RA...
                    radius-server:
                        type: str
                        description: Deprecated, please rename it to radius_server. RADIUS server to be used to authenticate WiFi users.
                    rates-11a:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to rates_11a. Allowed data rates for 802.
                        choices:
                            - '1'
                            - '1-basic'
                            - '2'
                            - '2-basic'
                            - '5.5'
                            - '5.5-basic'
                            - '6'
                            - '6-basic'
                            - '9'
                            - '9-basic'
                            - '12'
                            - '12-basic'
                            - '18'
                            - '18-basic'
                            - '24'
                            - '24-basic'
                            - '36'
                            - '36-basic'
                            - '48'
                            - '48-basic'
                            - '54'
                            - '54-basic'
                            - '11'
                            - '11-basic'
                    rates-11ac-ss12:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to rates_11ac_ss12. Allowed data rates for 802.
                        choices:
                            - 'mcs0/1'
                            - 'mcs1/1'
                            - 'mcs2/1'
                            - 'mcs3/1'
                            - 'mcs4/1'
                            - 'mcs5/1'
                            - 'mcs6/1'
                            - 'mcs7/1'
                            - 'mcs8/1'
                            - 'mcs9/1'
                            - 'mcs0/2'
                            - 'mcs1/2'
                            - 'mcs2/2'
                            - 'mcs3/2'
                            - 'mcs4/2'
                            - 'mcs5/2'
                            - 'mcs6/2'
                            - 'mcs7/2'
                            - 'mcs8/2'
                            - 'mcs9/2'
                            - 'mcs10/1'
                            - 'mcs11/1'
                            - 'mcs10/2'
                            - 'mcs11/2'
                    rates-11ac-ss34:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to rates_11ac_ss34. Allowed data rates for 802.
                        choices:
                            - 'mcs0/3'
                            - 'mcs1/3'
                            - 'mcs2/3'
                            - 'mcs3/3'
                            - 'mcs4/3'
                            - 'mcs5/3'
                            - 'mcs6/3'
                            - 'mcs7/3'
                            - 'mcs8/3'
                            - 'mcs9/3'
                            - 'mcs0/4'
                            - 'mcs1/4'
                            - 'mcs2/4'
                            - 'mcs3/4'
                            - 'mcs4/4'
                            - 'mcs5/4'
                            - 'mcs6/4'
                            - 'mcs7/4'
                            - 'mcs8/4'
                            - 'mcs9/4'
                            - 'mcs10/3'
                            - 'mcs11/3'
                            - 'mcs10/4'
                            - 'mcs11/4'
                    rates-11bg:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to rates_11bg. Allowed data rates for 802.
                        choices:
                            - '1'
                            - '1-basic'
                            - '2'
                            - '2-basic'
                            - '5.5'
                            - '5.5-basic'
                            - '6'
                            - '6-basic'
                            - '9'
                            - '9-basic'
                            - '12'
                            - '12-basic'
                            - '18'
                            - '18-basic'
                            - '24'
                            - '24-basic'
                            - '36'
                            - '36-basic'
                            - '48'
                            - '48-basic'
                            - '54'
                            - '54-basic'
                            - '11'
                            - '11-basic'
                    rates-11n-ss12:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to rates_11n_ss12. Allowed data rates for 802.
                        choices:
                            - 'mcs0/1'
                            - 'mcs1/1'
                            - 'mcs2/1'
                            - 'mcs3/1'
                            - 'mcs4/1'
                            - 'mcs5/1'
                            - 'mcs6/1'
                            - 'mcs7/1'
                            - 'mcs8/2'
                            - 'mcs9/2'
                            - 'mcs10/2'
                            - 'mcs11/2'
                            - 'mcs12/2'
                            - 'mcs13/2'
                            - 'mcs14/2'
                            - 'mcs15/2'
                    rates-11n-ss34:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to rates_11n_ss34. Allowed data rates for 802.
                        choices:
                            - 'mcs16/3'
                            - 'mcs17/3'
                            - 'mcs18/3'
                            - 'mcs19/3'
                            - 'mcs20/3'
                            - 'mcs21/3'
                            - 'mcs22/3'
                            - 'mcs23/3'
                            - 'mcs24/4'
                            - 'mcs25/4'
                            - 'mcs26/4'
                            - 'mcs27/4'
                            - 'mcs28/4'
                            - 'mcs29/4'
                            - 'mcs30/4'
                            - 'mcs31/4'
                    sae-groups:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to sae_groups. SAE-Groups.
                        choices:
                            - '1'
                            - '2'
                            - '5'
                            - '14'
                            - '15'
                            - '16'
                            - '17'
                            - '18'
                            - '19'
                            - '20'
                            - '21'
                            - '27'
                            - '28'
                            - '29'
                            - '30'
                            - '31'
                    sae-password:
                        type: raw
                        description: (list) Deprecated, please rename it to sae_password. WPA3 SAE password to be used to authenticate WiFi users.
                    schedule:
                        type: raw
                        description: (list or str) Firewall schedules for enabling this VAP on the FortiAP.
                    security:
                        type: str
                        description: Security mode for the wireless interface
                        choices:
                            - 'None'
                            - 'WEP64'
                            - 'wep64'
                            - 'WEP128'
                            - 'wep128'
                            - 'WPA_PSK'
                            - 'WPA_RADIUS'
                            - 'WPA'
                            - 'WPA2'
                            - 'WPA2_AUTO'
                            - 'open'
                            - 'wpa-personal'
                            - 'wpa-enterprise'
                            - 'captive-portal'
                            - 'wpa-only-personal'
                            - 'wpa-only-enterprise'
                            - 'wpa2-only-personal'
                            - 'wpa2-only-enterprise'
                            - 'wpa-personal+captive-portal'
                            - 'wpa-only-personal+captive-portal'
                            - 'wpa2-only-personal+captive-portal'
                            - 'osen'
                            - 'wpa3-enterprise'
                            - 'sae'
                            - 'sae-transition'
                            - 'owe'
                            - 'wpa3-sae'
                            - 'wpa3-sae-transition'
                            - 'wpa3-only-enterprise'
                            - 'wpa3-enterprise-transition'
                    security-exempt-list:
                        type: str
                        description: Deprecated, please rename it to security_exempt_list. Optional security exempt list for captive portal authentication.
                    security-obsolete-option:
                        type: str
                        description: Deprecated, please rename it to security_obsolete_option. Enable/disable obsolete security options.
                        choices:
                            - 'disable'
                            - 'enable'
                    security-redirect-url:
                        type: str
                        description: Deprecated, please rename it to security_redirect_url. Optional URL for redirecting users after they pass captive ...
                    selected-usergroups:
                        type: raw
                        description: (list or str) Deprecated, please rename it to selected_usergroups. Selective user groups that are permitted to aut...
                    split-tunneling:
                        type: str
                        description: Deprecated, please rename it to split_tunneling. Enable/disable split tunneling
                        choices:
                            - 'disable'
                            - 'enable'
                    ssid:
                        type: str
                        description: IEEE 802.
                    tkip-counter-measure:
                        type: str
                        description: Deprecated, please rename it to tkip_counter_measure. Enable/disable TKIP counter measure.
                        choices:
                            - 'disable'
                            - 'enable'
                    usergroup:
                        type: raw
                        description: (list or str) Firewall user group to be used to authenticate WiFi users.
                    utm-profile:
                        type: str
                        description: Deprecated, please rename it to utm_profile. UTM profile name.
                    vdom:
                        type: raw
                        description: (list or str) Vdom.
                    vlan-auto:
                        type: str
                        description: Deprecated, please rename it to vlan_auto. Enable/disable automatic management of SSID VLAN interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    vlan-pooling:
                        type: str
                        description: Deprecated, please rename it to vlan_pooling. Enable/disable VLAN pooling, to allow grouping of multiple wireless ...
                        choices:
                            - 'wtp-group'
                            - 'round-robin'
                            - 'hash'
                            - 'disable'
                    vlanid:
                        type: int
                        description: Optional VLAN ID.
                    voice-enterprise:
                        type: str
                        description: Deprecated, please rename it to voice_enterprise. Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    mu-mimo:
                        type: str
                        description: Deprecated, please rename it to mu_mimo. Enable/disable Multi-user MIMO
                        choices:
                            - 'disable'
                            - 'enable'
                    _intf_device-access-list:
                        type: str
                        description: Deprecated, please rename it to _intf_device_access_list. _Intf_Device-Access-List.
                    external-web-format:
                        type: str
                        description: Deprecated, please rename it to external_web_format. URL query parameter detection
                        choices:
                            - 'auto-detect'
                            - 'no-query-string'
                            - 'partial-query-string'
                    high-efficiency:
                        type: str
                        description: Deprecated, please rename it to high_efficiency. Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    primary-wag-profile:
                        type: str
                        description: Deprecated, please rename it to primary_wag_profile. Primary wireless access gateway profile name.
                    secondary-wag-profile:
                        type: str
                        description: Deprecated, please rename it to secondary_wag_profile. Secondary wireless access gateway profile name.
                    target-wake-time:
                        type: str
                        description: Deprecated, please rename it to target_wake_time. Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    tunnel-echo-interval:
                        type: int
                        description: Deprecated, please rename it to tunnel_echo_interval. The time interval to send echo to both primary and secondary...
                    tunnel-fallback-interval:
                        type: int
                        description: Deprecated, please rename it to tunnel_fallback_interval. The time interval for secondary tunnel to fall back to p...
                    access-control-list:
                        type: str
                        description: Deprecated, please rename it to access_control_list. Access-Control-List.
                    captive-portal-auth-timeout:
                        type: int
                        description: Deprecated, please rename it to captive_portal_auth_timeout. Captive-Portal-Auth-Timeout.
                    ipv6-rules:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to ipv6_rules. Ipv6-Rules.
                        choices:
                            - 'drop-icmp6ra'
                            - 'drop-icmp6rs'
                            - 'drop-llmnr6'
                            - 'drop-icmp6mld2'
                            - 'drop-dhcp6s'
                            - 'drop-dhcp6c'
                            - 'ndp-proxy'
                            - 'drop-ns-dad'
                            - 'drop-ns-nondad'
                    sticky-client-remove:
                        type: str
                        description: Deprecated, please rename it to sticky_client_remove. Sticky-Client-Remove.
                        choices:
                            - 'disable'
                            - 'enable'
                    sticky-client-threshold-2g:
                        type: str
                        description: Deprecated, please rename it to sticky_client_threshold_2g. Sticky-Client-Threshold-2G.
                    sticky-client-threshold-5g:
                        type: str
                        description: Deprecated, please rename it to sticky_client_threshold_5g. Sticky-Client-Threshold-5G.
                    bss-color-partial:
                        type: str
                        description: Deprecated, please rename it to bss_color_partial. Bss-Color-Partial.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp-option43-insertion:
                        type: str
                        description: Deprecated, please rename it to dhcp_option43_insertion. Dhcp-Option43-Insertion.
                        choices:
                            - 'disable'
                            - 'enable'
                    mpsk-profile:
                        type: str
                        description: Deprecated, please rename it to mpsk_profile. Mpsk-Profile.
                    igmp-snooping:
                        type: str
                        description: Deprecated, please rename it to igmp_snooping. Enable/disable IGMP snooping.
                        choices:
                            - 'disable'
                            - 'enable'
                    port-macauth:
                        type: str
                        description: Deprecated, please rename it to port_macauth. Enable/disable LAN port MAC authentication
                        choices:
                            - 'disable'
                            - 'radius'
                            - 'address-group'
                    port-macauth-reauth-timeout:
                        type: int
                        description: Deprecated, please rename it to port_macauth_reauth_timeout. LAN port MAC authentication re-authentication timeout...
                    port-macauth-timeout:
                        type: int
                        description: Deprecated, please rename it to port_macauth_timeout. LAN port MAC authentication idle timeout value
                    additional-akms:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to additional_akms. Additional-Akms.
                        choices:
                            - 'akm6'
                    bstm-disassociation-imminent:
                        type: str
                        description: Deprecated, please rename it to bstm_disassociation_imminent. Enable/disable forcing of disassociation after the B...
                        choices:
                            - 'disable'
                            - 'enable'
                    bstm-load-balancing-disassoc-timer:
                        type: int
                        description: Deprecated, please rename it to bstm_load_balancing_disassoc_timer. Time interval for client to voluntarily leave ...
                    bstm-rssi-disassoc-timer:
                        type: int
                        description: Deprecated, please rename it to bstm_rssi_disassoc_timer. Time interval for client to voluntarily leave AP before ...
                    dhcp-address-enforcement:
                        type: str
                        description: Deprecated, please rename it to dhcp_address_enforcement. Enable/disable DHCP address enforcement
                        choices:
                            - 'disable'
                            - 'enable'
                    gas-comeback-delay:
                        type: int
                        description: Deprecated, please rename it to gas_comeback_delay. GAS comeback delay
                    gas-fragmentation-limit:
                        type: int
                        description: Deprecated, please rename it to gas_fragmentation_limit. GAS fragmentation limit
                    mac-called-station-delimiter:
                        type: str
                        description: Deprecated, please rename it to mac_called_station_delimiter. MAC called station delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac-calling-station-delimiter:
                        type: str
                        description: Deprecated, please rename it to mac_calling_station_delimiter. MAC calling station delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac-case:
                        type: str
                        description: Deprecated, please rename it to mac_case. MAC case
                        choices:
                            - 'uppercase'
                            - 'lowercase'
                    mac-password-delimiter:
                        type: str
                        description: Deprecated, please rename it to mac_password_delimiter. MAC authentication password delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac-username-delimiter:
                        type: str
                        description: Deprecated, please rename it to mac_username_delimiter. MAC authentication username delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mbo:
                        type: str
                        description: Enable/disable Multiband Operation
                        choices:
                            - 'disable'
                            - 'enable'
                    mbo-cell-data-conn-pref:
                        type: str
                        description: Deprecated, please rename it to mbo_cell_data_conn_pref. MBO cell data connection preference
                        choices:
                            - 'excluded'
                            - 'prefer-not'
                            - 'prefer-use'
                    nac:
                        type: str
                        description: Enable/disable network access control.
                        choices:
                            - 'disable'
                            - 'enable'
                    nac-profile:
                        type: str
                        description: Deprecated, please rename it to nac_profile. NAC profile name.
                    neighbor-report-dual-band:
                        type: str
                        description: Deprecated, please rename it to neighbor_report_dual_band. Enable/disable dual-band neighbor report
                        choices:
                            - 'disable'
                            - 'enable'
                    address-group-policy:
                        type: str
                        description: Deprecated, please rename it to address_group_policy. Configure MAC address filtering policy for MAC addresses tha...
                        choices:
                            - 'disable'
                            - 'allow'
                            - 'deny'
                    antivirus-profile:
                        type: str
                        description: Deprecated, please rename it to antivirus_profile. AntiVirus profile name.
                    application-detection-engine:
                        type: str
                        description: Deprecated, please rename it to application_detection_engine. Enable/disable application detection engine
                        choices:
                            - 'disable'
                            - 'enable'
                    application-list:
                        type: str
                        description: Deprecated, please rename it to application_list. Application control list name.
                    application-report-intv:
                        type: int
                        description: Deprecated, please rename it to application_report_intv. Application report interval
                    auth-cert:
                        type: str
                        description: Deprecated, please rename it to auth_cert. HTTPS server certificate.
                    auth-portal-addr:
                        type: str
                        description: Deprecated, please rename it to auth_portal_addr. Address of captive portal.
                    beacon-advertising:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to beacon_advertising.
                        choices:
                            - 'name'
                            - 'model'
                            - 'serial-number'
                    ips-sensor:
                        type: str
                        description: Deprecated, please rename it to ips_sensor. IPS sensor name.
                    l3-roaming:
                        type: str
                        description: Deprecated, please rename it to l3_roaming. Enable/disable layer 3 roaming
                        choices:
                            - 'disable'
                            - 'enable'
                    local-standalone-dns:
                        type: str
                        description: Deprecated, please rename it to local_standalone_dns. Enable/disable AP local standalone DNS.
                        choices:
                            - 'disable'
                            - 'enable'
                    local-standalone-dns-ip:
                        type: raw
                        description: (list) Deprecated, please rename it to local_standalone_dns_ip.
                    osen:
                        type: str
                        description: Enable/disable OSEN as part of key management
                        choices:
                            - 'disable'
                            - 'enable'
                    radius-mac-mpsk-auth:
                        type: str
                        description: Deprecated, please rename it to radius_mac_mpsk_auth. Enable/disable RADIUS-based MAC authentication of clients fo...
                        choices:
                            - 'disable'
                            - 'enable'
                    radius-mac-mpsk-timeout:
                        type: int
                        description: Deprecated, please rename it to radius_mac_mpsk_timeout. RADIUS MAC MPSK cache timeout interval
                    rates-11ax-ss12:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to rates_11ax_ss12.
                        choices:
                            - 'mcs0/1'
                            - 'mcs1/1'
                            - 'mcs2/1'
                            - 'mcs3/1'
                            - 'mcs4/1'
                            - 'mcs5/1'
                            - 'mcs6/1'
                            - 'mcs7/1'
                            - 'mcs8/1'
                            - 'mcs9/1'
                            - 'mcs10/1'
                            - 'mcs11/1'
                            - 'mcs0/2'
                            - 'mcs1/2'
                            - 'mcs2/2'
                            - 'mcs3/2'
                            - 'mcs4/2'
                            - 'mcs5/2'
                            - 'mcs6/2'
                            - 'mcs7/2'
                            - 'mcs8/2'
                            - 'mcs9/2'
                            - 'mcs10/2'
                            - 'mcs11/2'
                    rates-11ax-ss34:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to rates_11ax_ss34.
                        choices:
                            - 'mcs0/3'
                            - 'mcs1/3'
                            - 'mcs2/3'
                            - 'mcs3/3'
                            - 'mcs4/3'
                            - 'mcs5/3'
                            - 'mcs6/3'
                            - 'mcs7/3'
                            - 'mcs8/3'
                            - 'mcs9/3'
                            - 'mcs10/3'
                            - 'mcs11/3'
                            - 'mcs0/4'
                            - 'mcs1/4'
                            - 'mcs2/4'
                            - 'mcs3/4'
                            - 'mcs4/4'
                            - 'mcs5/4'
                            - 'mcs6/4'
                            - 'mcs7/4'
                            - 'mcs8/4'
                            - 'mcs9/4'
                            - 'mcs10/4'
                            - 'mcs11/4'
                    scan-botnet-connections:
                        type: str
                        description: Deprecated, please rename it to scan_botnet_connections. Block or monitor connections to Botnet servers or disable...
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    utm-log:
                        type: str
                        description: Deprecated, please rename it to utm_log. Enable/disable UTM logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    utm-status:
                        type: str
                        description: Deprecated, please rename it to utm_status. Enable to add one or more security profiles
                        choices:
                            - 'disable'
                            - 'enable'
                    webfilter-profile:
                        type: str
                        description: Deprecated, please rename it to webfilter_profile. WebFilter profile name.
                    sae-h2e-only:
                        type: str
                        description: Deprecated, please rename it to sae_h2e_only. Use hash-to-element-only mechanism for PWE derivation
                        choices:
                            - 'disable'
                            - 'enable'
                    sae-pk:
                        type: str
                        description: Deprecated, please rename it to sae_pk. Enable/disable WPA3 SAE-PK
                        choices:
                            - 'disable'
                            - 'enable'
                    sae-private-key:
                        type: str
                        description: Deprecated, please rename it to sae_private_key. Private key used for WPA3 SAE-PK authentication.
                    sticky-client-threshold-6g:
                        type: str
                        description: Deprecated, please rename it to sticky_client_threshold_6g. Minimum signal level/threshold in dBm required for the...
                    application-dscp-marking:
                        type: str
                        description: Deprecated, please rename it to application_dscp_marking. Enable/disable application attribute based DSCP marking
                        choices:
                            - 'disable'
                            - 'enable'
                    l3-roaming-mode:
                        type: str
                        description: Deprecated, please rename it to l3_roaming_mode. Select the way that layer 3 roaming traffic is passed
                        choices:
                            - 'direct'
                            - 'indirect'
                    rates-11ac-mcs-map:
                        type: str
                        description: Deprecated, please rename it to rates_11ac_mcs_map. Comma separated list of max supported VHT MCS for spatial stre...
                    rates-11ax-mcs-map:
                        type: str
                        description: Deprecated, please rename it to rates_11ax_mcs_map. Comma separated list of max supported HE MCS for spatial strea...
                    captive-portal-fw-accounting:
                        type: str
                        description: Deprecated, please rename it to captive_portal_fw_accounting. Enable/disable RADIUS accounting for captive portal ...
                        choices:
                            - 'disable'
                            - 'enable'
                    radius-mac-auth-block-interval:
                        type: int
                        description: Deprecated, please rename it to radius_mac_auth_block_interval. Dont send RADIUS MAC auth request again if the cli...
                    _is_factory_setting:
                        type: str
                        description: No description.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'ext'
                    80211k:
                        type: str
                        description: Deprecated, please rename it to d80211k. Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    80211v:
                        type: str
                        description: Deprecated, please rename it to d80211v. Enable/disable 802.
                        choices:
                            - 'disable'
                            - 'enable'
                    roaming-acct-interim-update:
                        type: str
                        description: Deprecated, please rename it to roaming_acct_interim_update. Enable/disable using accounting interim update instea...
                        choices:
                            - 'disable'
                            - 'enable'
                    sae-hnp-only:
                        type: str
                        description: Deprecated, please rename it to sae_hnp_only. Use hunting-and-pecking-only mechanism for PWE derivation
                        choices:
                            - 'disable'
                            - 'enable'
            eap-reauth:
                type: str
                description: Deprecated, please rename it to eap_reauth. Enable/disable EAP re-authentication for WPA-Enterprise security.
                choices:
                    - 'disable'
                    - 'enable'
            eap-reauth-intv:
                type: int
                description: Deprecated, please rename it to eap_reauth_intv. EAP re-authentication interval
            eapol-key-retries:
                type: str
                description: Deprecated, please rename it to eapol_key_retries. Enable/disable retransmission of EAPOL-Key frames
                choices:
                    - 'disable'
                    - 'enable'
            encrypt:
                type: str
                description: Encryption protocol to use
                choices:
                    - 'TKIP'
                    - 'AES'
                    - 'TKIP-AES'
            external-fast-roaming:
                type: str
                description: Deprecated, please rename it to external_fast_roaming. Enable/disable fast roaming or pre-authentication with external APs...
                choices:
                    - 'disable'
                    - 'enable'
            external-logout:
                type: str
                description: Deprecated, please rename it to external_logout. URL of external authentication logout server.
            external-web:
                type: str
                description: Deprecated, please rename it to external_web. URL of external authentication web server.
            fast-bss-transition:
                type: str
                description: Deprecated, please rename it to fast_bss_transition. Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            fast-roaming:
                type: str
                description: Deprecated, please rename it to fast_roaming. Enable/disable fast-roaming, or pre-authentication, where supported by clients
                choices:
                    - 'disable'
                    - 'enable'
            ft-mobility-domain:
                type: int
                description: Deprecated, please rename it to ft_mobility_domain. Mobility domain identifier in FT
            ft-over-ds:
                type: str
                description: Deprecated, please rename it to ft_over_ds. Enable/disable FT over the Distribution System
                choices:
                    - 'disable'
                    - 'enable'
            ft-r0-key-lifetime:
                type: int
                description: Deprecated, please rename it to ft_r0_key_lifetime. Lifetime of the PMK-R0 key in FT, 1-65535 minutes.
            gtk-rekey:
                type: str
                description: Deprecated, please rename it to gtk_rekey. Enable/disable GTK rekey for WPA security.
                choices:
                    - 'disable'
                    - 'enable'
            gtk-rekey-intv:
                type: int
                description: Deprecated, please rename it to gtk_rekey_intv. GTK rekey interval
            hotspot20-profile:
                type: str
                description: Deprecated, please rename it to hotspot20_profile. Hotspot 2.
            intra-vap-privacy:
                type: str
                description: Deprecated, please rename it to intra_vap_privacy. Enable/disable blocking communication between clients on the same SSID
                choices:
                    - 'disable'
                    - 'enable'
            ip:
                type: str
                description: IP address and subnet mask for the local standalone NAT subnet.
            key:
                type: raw
                description: (list) WEP Key.
            keyindex:
                type: int
                description: WEP key index
            ldpc:
                type: str
                description: VAP low-density parity-check
                choices:
                    - 'disable'
                    - 'tx'
                    - 'rx'
                    - 'rxtx'
            local-authentication:
                type: str
                description: Deprecated, please rename it to local_authentication. Enable/disable AP local authentication.
                choices:
                    - 'disable'
                    - 'enable'
            local-bridging:
                type: str
                description: Deprecated, please rename it to local_bridging. Enable/disable bridging of wireless and Ethernet interfaces on the FortiAP
                choices:
                    - 'disable'
                    - 'enable'
            local-lan:
                type: str
                description: Deprecated, please rename it to local_lan. Allow/deny traffic destined for a Class A, B, or C private IP address
                choices:
                    - 'deny'
                    - 'allow'
            local-standalone:
                type: str
                description: Deprecated, please rename it to local_standalone. Enable/disable AP local standalone
                choices:
                    - 'disable'
                    - 'enable'
            local-standalone-nat:
                type: str
                description: Deprecated, please rename it to local_standalone_nat. Enable/disable AP local standalone NAT mode.
                choices:
                    - 'disable'
                    - 'enable'
            mac-auth-bypass:
                type: str
                description: Deprecated, please rename it to mac_auth_bypass. Enable/disable MAC authentication bypass.
                choices:
                    - 'disable'
                    - 'enable'
            mac-filter:
                type: str
                description: Deprecated, please rename it to mac_filter. Enable/disable MAC filtering to block wireless clients by mac address.
                choices:
                    - 'disable'
                    - 'enable'
            mac-filter-list:
                type: list
                elements: dict
                description: Deprecated, please rename it to mac_filter_list. Mac-Filter-List.
                suboptions:
                    id:
                        type: int
                        description: ID.
                    mac:
                        type: str
                        description: MAC address.
                    mac-filter-policy:
                        type: str
                        description: Deprecated, please rename it to mac_filter_policy. Deny or allow the client with this MAC address.
                        choices:
                            - 'deny'
                            - 'allow'
            mac-filter-policy-other:
                type: str
                description: Deprecated, please rename it to mac_filter_policy_other. Allow or block clients with MAC addresses that are not in the fil...
                choices:
                    - 'deny'
                    - 'allow'
            max-clients:
                type: int
                description: Deprecated, please rename it to max_clients. Maximum number of clients that can connect simultaneously to the VAP
            max-clients-ap:
                type: int
                description: Deprecated, please rename it to max_clients_ap. Maximum number of clients that can connect simultaneously to each radio
            me-disable-thresh:
                type: int
                description: Deprecated, please rename it to me_disable_thresh. Disable multicast enhancement when this many clients are receiving mult...
            mesh-backhaul:
                type: str
                description: Deprecated, please rename it to mesh_backhaul. Enable/disable using this VAP as a WiFi mesh backhaul
                choices:
                    - 'disable'
                    - 'enable'
            mpsk:
                type: str
                description: Enable/disable multiple pre-shared keys
                choices:
                    - 'disable'
                    - 'enable'
            mpsk-concurrent-clients:
                type: int
                description: Deprecated, please rename it to mpsk_concurrent_clients. Number of pre-shared keys
            mpsk-key:
                type: list
                elements: dict
                description: Deprecated, please rename it to mpsk_key. Mpsk-Key.
                suboptions:
                    comment:
                        type: str
                        description: Comment.
                    concurrent-clients:
                        type: str
                        description: Deprecated, please rename it to concurrent_clients. Number of clients that can connect using this pre-shared key.
                    key-name:
                        type: str
                        description: Deprecated, please rename it to key_name. Pre-shared key name.
                    passphrase:
                        type: raw
                        description: (list) WPA Pre-shared key.
                    mpsk-schedules:
                        type: raw
                        description: (list or str) Deprecated, please rename it to mpsk_schedules. Firewall schedule for MPSK passphrase.
            multicast-enhance:
                type: str
                description: Deprecated, please rename it to multicast_enhance. Enable/disable converting multicast to unicast to improve performance
                choices:
                    - 'disable'
                    - 'enable'
            multicast-rate:
                type: str
                description: Deprecated, please rename it to multicast_rate. Multicast rate
                choices:
                    - '0'
                    - '6000'
                    - '12000'
                    - '24000'
            name:
                type: str
                description: Virtual AP name.
                required: true
            okc:
                type: str
                description: Enable/disable Opportunistic Key Caching
                choices:
                    - 'disable'
                    - 'enable'
            passphrase:
                type: raw
                description: (list) WPA pre-shared key
            pmf:
                type: str
                description: Protected Management Frames
                choices:
                    - 'disable'
                    - 'enable'
                    - 'optional'
            pmf-assoc-comeback-timeout:
                type: int
                description: Deprecated, please rename it to pmf_assoc_comeback_timeout. Protected Management Frames
            pmf-sa-query-retry-timeout:
                type: int
                description: Deprecated, please rename it to pmf_sa_query_retry_timeout. Protected Management Frames
            portal-message-override-group:
                type: str
                description: Deprecated, please rename it to portal_message_override_group. Replacement message group for this VAP
            portal-type:
                type: str
                description: Deprecated, please rename it to portal_type. Captive portal functionality.
                choices:
                    - 'auth'
                    - 'auth+disclaimer'
                    - 'disclaimer'
                    - 'email-collect'
                    - 'cmcc'
                    - 'cmcc-macauth'
                    - 'auth-mac'
                    - 'external-auth'
                    - 'external-macauth'
            probe-resp-suppression:
                type: str
                description: Deprecated, please rename it to probe_resp_suppression. Enable/disable probe response suppression
                choices:
                    - 'disable'
                    - 'enable'
            probe-resp-threshold:
                type: str
                description: Deprecated, please rename it to probe_resp_threshold. Minimum signal level/threshold in dBm required for the AP response t...
            ptk-rekey:
                type: str
                description: Deprecated, please rename it to ptk_rekey. Enable/disable PTK rekey for WPA-Enterprise security.
                choices:
                    - 'disable'
                    - 'enable'
            ptk-rekey-intv:
                type: int
                description: Deprecated, please rename it to ptk_rekey_intv. PTK rekey interval
            qos-profile:
                type: str
                description: Deprecated, please rename it to qos_profile. Quality of service profile name.
            quarantine:
                type: str
                description: Enable/disable station quarantine
                choices:
                    - 'disable'
                    - 'enable'
            radio-2g-threshold:
                type: str
                description: Deprecated, please rename it to radio_2g_threshold. Minimum signal level/threshold in dBm required for the AP response to ...
            radio-5g-threshold:
                type: str
                description: Deprecated, please rename it to radio_5g_threshold. Minimum signal level/threshold in dBm required for the AP response to ...
            radio-sensitivity:
                type: str
                description: Deprecated, please rename it to radio_sensitivity. Enable/disable software radio sensitivity
                choices:
                    - 'disable'
                    - 'enable'
            radius-mac-auth:
                type: str
                description: Deprecated, please rename it to radius_mac_auth. Enable/disable RADIUS-based MAC authentication of clients
                choices:
                    - 'disable'
                    - 'enable'
            radius-mac-auth-server:
                type: str
                description: Deprecated, please rename it to radius_mac_auth_server. RADIUS-based MAC authentication server.
            radius-mac-auth-usergroups:
                type: raw
                description: (list) Deprecated, please rename it to radius_mac_auth_usergroups. Selective user groups that are permitted for RADIUS mac...
            radius-server:
                type: str
                description: Deprecated, please rename it to radius_server. RADIUS server to be used to authenticate WiFi users.
            rates-11a:
                type: list
                elements: str
                description: Deprecated, please rename it to rates_11a. Allowed data rates for 802.
                choices:
                    - '1'
                    - '1-basic'
                    - '2'
                    - '2-basic'
                    - '5.5'
                    - '5.5-basic'
                    - '6'
                    - '6-basic'
                    - '9'
                    - '9-basic'
                    - '12'
                    - '12-basic'
                    - '18'
                    - '18-basic'
                    - '24'
                    - '24-basic'
                    - '36'
                    - '36-basic'
                    - '48'
                    - '48-basic'
                    - '54'
                    - '54-basic'
                    - '11'
                    - '11-basic'
            rates-11ac-ss12:
                type: list
                elements: str
                description: Deprecated, please rename it to rates_11ac_ss12. Allowed data rates for 802.
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/1'
                    - 'mcs9/1'
                    - 'mcs0/2'
                    - 'mcs1/2'
                    - 'mcs2/2'
                    - 'mcs3/2'
                    - 'mcs4/2'
                    - 'mcs5/2'
                    - 'mcs6/2'
                    - 'mcs7/2'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/1'
                    - 'mcs11/1'
                    - 'mcs10/2'
                    - 'mcs11/2'
            rates-11ac-ss34:
                type: list
                elements: str
                description: Deprecated, please rename it to rates_11ac_ss34. Allowed data rates for 802.
                choices:
                    - 'mcs0/3'
                    - 'mcs1/3'
                    - 'mcs2/3'
                    - 'mcs3/3'
                    - 'mcs4/3'
                    - 'mcs5/3'
                    - 'mcs6/3'
                    - 'mcs7/3'
                    - 'mcs8/3'
                    - 'mcs9/3'
                    - 'mcs0/4'
                    - 'mcs1/4'
                    - 'mcs2/4'
                    - 'mcs3/4'
                    - 'mcs4/4'
                    - 'mcs5/4'
                    - 'mcs6/4'
                    - 'mcs7/4'
                    - 'mcs8/4'
                    - 'mcs9/4'
                    - 'mcs10/3'
                    - 'mcs11/3'
                    - 'mcs10/4'
                    - 'mcs11/4'
            rates-11bg:
                type: list
                elements: str
                description: Deprecated, please rename it to rates_11bg. Allowed data rates for 802.
                choices:
                    - '1'
                    - '1-basic'
                    - '2'
                    - '2-basic'
                    - '5.5'
                    - '5.5-basic'
                    - '6'
                    - '6-basic'
                    - '9'
                    - '9-basic'
                    - '12'
                    - '12-basic'
                    - '18'
                    - '18-basic'
                    - '24'
                    - '24-basic'
                    - '36'
                    - '36-basic'
                    - '48'
                    - '48-basic'
                    - '54'
                    - '54-basic'
                    - '11'
                    - '11-basic'
            rates-11n-ss12:
                type: list
                elements: str
                description: Deprecated, please rename it to rates_11n_ss12. Allowed data rates for 802.
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/2'
                    - 'mcs11/2'
                    - 'mcs12/2'
                    - 'mcs13/2'
                    - 'mcs14/2'
                    - 'mcs15/2'
            rates-11n-ss34:
                type: list
                elements: str
                description: Deprecated, please rename it to rates_11n_ss34. Allowed data rates for 802.
                choices:
                    - 'mcs16/3'
                    - 'mcs17/3'
                    - 'mcs18/3'
                    - 'mcs19/3'
                    - 'mcs20/3'
                    - 'mcs21/3'
                    - 'mcs22/3'
                    - 'mcs23/3'
                    - 'mcs24/4'
                    - 'mcs25/4'
                    - 'mcs26/4'
                    - 'mcs27/4'
                    - 'mcs28/4'
                    - 'mcs29/4'
                    - 'mcs30/4'
                    - 'mcs31/4'
            schedule:
                type: raw
                description: (list or str) VAP schedule name.
            security:
                type: str
                description: Security mode for the wireless interface
                choices:
                    - 'None'
                    - 'WEP64'
                    - 'wep64'
                    - 'WEP128'
                    - 'wep128'
                    - 'WPA_PSK'
                    - 'WPA_RADIUS'
                    - 'WPA'
                    - 'WPA2'
                    - 'WPA2_AUTO'
                    - 'open'
                    - 'wpa-personal'
                    - 'wpa-enterprise'
                    - 'captive-portal'
                    - 'wpa-only-personal'
                    - 'wpa-only-enterprise'
                    - 'wpa2-only-personal'
                    - 'wpa2-only-enterprise'
                    - 'wpa-personal+captive-portal'
                    - 'wpa-only-personal+captive-portal'
                    - 'wpa2-only-personal+captive-portal'
                    - 'osen'
                    - 'wpa3-enterprise'
                    - 'sae'
                    - 'sae-transition'
                    - 'owe'
                    - 'wpa3-sae'
                    - 'wpa3-sae-transition'
                    - 'wpa3-only-enterprise'
                    - 'wpa3-enterprise-transition'
            security-exempt-list:
                type: str
                description: Deprecated, please rename it to security_exempt_list. Optional security exempt list for captive portal authentication.
            security-obsolete-option:
                type: str
                description: Deprecated, please rename it to security_obsolete_option. Enable/disable obsolete security options.
                choices:
                    - 'disable'
                    - 'enable'
            security-redirect-url:
                type: str
                description: Deprecated, please rename it to security_redirect_url. Optional URL for redirecting users after they pass captive portal a...
            selected-usergroups:
                type: raw
                description: (list or str) Deprecated, please rename it to selected_usergroups. Selective user groups that are permitted to authenticate.
            split-tunneling:
                type: str
                description: Deprecated, please rename it to split_tunneling. Enable/disable split tunneling
                choices:
                    - 'disable'
                    - 'enable'
            ssid:
                type: str
                description: IEEE 802.
            tkip-counter-measure:
                type: str
                description: Deprecated, please rename it to tkip_counter_measure. Enable/disable TKIP counter measure.
                choices:
                    - 'disable'
                    - 'enable'
            usergroup:
                type: raw
                description: (list or str) Firewall user group to be used to authenticate WiFi users.
            utm-profile:
                type: str
                description: Deprecated, please rename it to utm_profile. UTM profile name.
            vdom:
                type: str
                description: Name of the VDOM that the Virtual AP has been added to.
            vlan-auto:
                type: str
                description: Deprecated, please rename it to vlan_auto. Enable/disable automatic management of SSID VLAN interface.
                choices:
                    - 'disable'
                    - 'enable'
            vlan-pool:
                type: list
                elements: dict
                description: Deprecated, please rename it to vlan_pool. Vlan-Pool.
                suboptions:
                    _wtp-group:
                        type: str
                        description: Deprecated, please rename it to _wtp_group. _Wtp-Group.
                    id:
                        type: int
                        description: ID.
                    wtp-group:
                        type: str
                        description: Deprecated, please rename it to wtp_group. WTP group name.
            vlan-pooling:
                type: str
                description: Deprecated, please rename it to vlan_pooling. Enable/disable VLAN pooling, to allow grouping of multiple wireless controll...
                choices:
                    - 'wtp-group'
                    - 'round-robin'
                    - 'hash'
                    - 'disable'
            vlanid:
                type: int
                description: Optional VLAN ID.
            voice-enterprise:
                type: str
                description: Deprecated, please rename it to voice_enterprise. Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            address-group:
                type: str
                description: Deprecated, please rename it to address_group. Address group ID.
            atf-weight:
                type: int
                description: Deprecated, please rename it to atf_weight. Airtime weight in percentage
            mu-mimo:
                type: str
                description: Deprecated, please rename it to mu_mimo. Enable/disable Multi-user MIMO
                choices:
                    - 'disable'
                    - 'enable'
            owe-groups:
                type: list
                elements: str
                description: Deprecated, please rename it to owe_groups. OWE-Groups.
                choices:
                    - '19'
                    - '20'
                    - '21'
            owe-transition:
                type: str
                description: Deprecated, please rename it to owe_transition. Enable/disable OWE transition mode support.
                choices:
                    - 'disable'
                    - 'enable'
            owe-transition-ssid:
                type: str
                description: Deprecated, please rename it to owe_transition_ssid. OWE transition mode peer SSID.
            sae-groups:
                type: list
                elements: str
                description: Deprecated, please rename it to sae_groups. SAE-Groups.
                choices:
                    - '1'
                    - '2'
                    - '5'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
            sae-password:
                type: raw
                description: (list) Deprecated, please rename it to sae_password. WPA3 SAE password to be used to authenticate WiFi users.
            _intf_device-access-list:
                type: str
                description: Deprecated, please rename it to _intf_device_access_list. _Intf_Device-Access-List.
            external-web-format:
                type: str
                description: Deprecated, please rename it to external_web_format. URL query parameter detection
                choices:
                    - 'auto-detect'
                    - 'no-query-string'
                    - 'partial-query-string'
            high-efficiency:
                type: str
                description: Deprecated, please rename it to high_efficiency. Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            primary-wag-profile:
                type: str
                description: Deprecated, please rename it to primary_wag_profile. Primary wireless access gateway profile name.
            secondary-wag-profile:
                type: str
                description: Deprecated, please rename it to secondary_wag_profile. Secondary wireless access gateway profile name.
            target-wake-time:
                type: str
                description: Deprecated, please rename it to target_wake_time. Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            tunnel-echo-interval:
                type: int
                description: Deprecated, please rename it to tunnel_echo_interval. The time interval to send echo to both primary and secondary tunnel ...
            tunnel-fallback-interval:
                type: int
                description: Deprecated, please rename it to tunnel_fallback_interval. The time interval for secondary tunnel to fall back to primary t...
            access-control-list:
                type: str
                description: Deprecated, please rename it to access_control_list. Access-control-list profile name.
            captive-portal-auth-timeout:
                type: int
                description: Deprecated, please rename it to captive_portal_auth_timeout. Hard timeout - AP will always clear the session after timeout...
            ipv6-rules:
                type: list
                elements: str
                description: Deprecated, please rename it to ipv6_rules. Optional rules of IPv6 packets.
                choices:
                    - 'drop-icmp6ra'
                    - 'drop-icmp6rs'
                    - 'drop-llmnr6'
                    - 'drop-icmp6mld2'
                    - 'drop-dhcp6s'
                    - 'drop-dhcp6c'
                    - 'ndp-proxy'
                    - 'drop-ns-dad'
                    - 'drop-ns-nondad'
            sticky-client-remove:
                type: str
                description: Deprecated, please rename it to sticky_client_remove. Enable/disable sticky client remove to maintain good signal level cl...
                choices:
                    - 'disable'
                    - 'enable'
            sticky-client-threshold-2g:
                type: str
                description: Deprecated, please rename it to sticky_client_threshold_2g. Minimum signal level/threshold in dBm required for the 2G clie...
            sticky-client-threshold-5g:
                type: str
                description: Deprecated, please rename it to sticky_client_threshold_5g. Minimum signal level/threshold in dBm required for the 5G clie...
            bss-color-partial:
                type: str
                description: Deprecated, please rename it to bss_color_partial. Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp-option43-insertion:
                type: str
                description: Deprecated, please rename it to dhcp_option43_insertion. Enable/disable insertion of DHCP option 43
                choices:
                    - 'disable'
                    - 'enable'
            mpsk-profile:
                type: str
                description: Deprecated, please rename it to mpsk_profile. MPSK profile name.
            igmp-snooping:
                type: str
                description: Deprecated, please rename it to igmp_snooping. Enable/disable IGMP snooping.
                choices:
                    - 'disable'
                    - 'enable'
            port-macauth:
                type: str
                description: Deprecated, please rename it to port_macauth. Enable/disable LAN port MAC authentication
                choices:
                    - 'disable'
                    - 'radius'
                    - 'address-group'
            port-macauth-reauth-timeout:
                type: int
                description: Deprecated, please rename it to port_macauth_reauth_timeout. LAN port MAC authentication re-authentication timeout value
            port-macauth-timeout:
                type: int
                description: Deprecated, please rename it to port_macauth_timeout. LAN port MAC authentication idle timeout value
            portal-message-overrides:
                type: dict
                description: Deprecated, please rename it to portal_message_overrides.
                suboptions:
                    auth-disclaimer-page:
                        type: str
                        description: Deprecated, please rename it to auth_disclaimer_page. Override auth-disclaimer-page message with message from port...
                    auth-login-failed-page:
                        type: str
                        description: Deprecated, please rename it to auth_login_failed_page. Override auth-login-failed-page message with message from ...
                    auth-login-page:
                        type: str
                        description: Deprecated, please rename it to auth_login_page. Override auth-login-page message with message from portal-message...
                    auth-reject-page:
                        type: str
                        description: Deprecated, please rename it to auth_reject_page. Override auth-reject-page message with message from portal-messa...
            additional-akms:
                type: list
                elements: str
                description: Deprecated, please rename it to additional_akms. Additional AKMs.
                choices:
                    - 'akm6'
            bstm-disassociation-imminent:
                type: str
                description: Deprecated, please rename it to bstm_disassociation_imminent. Enable/disable forcing of disassociation after the BSTM requ...
                choices:
                    - 'disable'
                    - 'enable'
            bstm-load-balancing-disassoc-timer:
                type: int
                description: Deprecated, please rename it to bstm_load_balancing_disassoc_timer. Time interval for client to voluntarily leave AP befor...
            bstm-rssi-disassoc-timer:
                type: int
                description: Deprecated, please rename it to bstm_rssi_disassoc_timer. Time interval for client to voluntarily leave AP before forcing ...
            dhcp-address-enforcement:
                type: str
                description: Deprecated, please rename it to dhcp_address_enforcement. Enable/disable DHCP address enforcement
                choices:
                    - 'disable'
                    - 'enable'
            gas-comeback-delay:
                type: int
                description: Deprecated, please rename it to gas_comeback_delay. GAS comeback delay
            gas-fragmentation-limit:
                type: int
                description: Deprecated, please rename it to gas_fragmentation_limit. GAS fragmentation limit
            mac-called-station-delimiter:
                type: str
                description: Deprecated, please rename it to mac_called_station_delimiter. MAC called station delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac-calling-station-delimiter:
                type: str
                description: Deprecated, please rename it to mac_calling_station_delimiter. MAC calling station delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac-case:
                type: str
                description: Deprecated, please rename it to mac_case. MAC case
                choices:
                    - 'uppercase'
                    - 'lowercase'
            mac-password-delimiter:
                type: str
                description: Deprecated, please rename it to mac_password_delimiter. MAC authentication password delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac-username-delimiter:
                type: str
                description: Deprecated, please rename it to mac_username_delimiter. MAC authentication username delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mbo:
                type: str
                description: Enable/disable Multiband Operation
                choices:
                    - 'disable'
                    - 'enable'
            mbo-cell-data-conn-pref:
                type: str
                description: Deprecated, please rename it to mbo_cell_data_conn_pref. MBO cell data connection preference
                choices:
                    - 'excluded'
                    - 'prefer-not'
                    - 'prefer-use'
            nac:
                type: str
                description: Enable/disable network access control.
                choices:
                    - 'disable'
                    - 'enable'
            nac-profile:
                type: str
                description: Deprecated, please rename it to nac_profile. NAC profile name.
            neighbor-report-dual-band:
                type: str
                description: Deprecated, please rename it to neighbor_report_dual_band. Enable/disable dual-band neighbor report
                choices:
                    - 'disable'
                    - 'enable'
            address-group-policy:
                type: str
                description: Deprecated, please rename it to address_group_policy. Configure MAC address filtering policy for MAC addresses that are in...
                choices:
                    - 'disable'
                    - 'allow'
                    - 'deny'
            antivirus-profile:
                type: str
                description: Deprecated, please rename it to antivirus_profile. AntiVirus profile name.
            application-detection-engine:
                type: str
                description: Deprecated, please rename it to application_detection_engine. Enable/disable application detection engine
                choices:
                    - 'disable'
                    - 'enable'
            application-list:
                type: str
                description: Deprecated, please rename it to application_list. Application control list name.
            application-report-intv:
                type: int
                description: Deprecated, please rename it to application_report_intv. Application report interval
            auth-cert:
                type: str
                description: Deprecated, please rename it to auth_cert. HTTPS server certificate.
            auth-portal-addr:
                type: str
                description: Deprecated, please rename it to auth_portal_addr. Address of captive portal.
            beacon-advertising:
                type: list
                elements: str
                description: Deprecated, please rename it to beacon_advertising.
                choices:
                    - 'name'
                    - 'model'
                    - 'serial-number'
            ips-sensor:
                type: str
                description: Deprecated, please rename it to ips_sensor. IPS sensor name.
            l3-roaming:
                type: str
                description: Deprecated, please rename it to l3_roaming. Enable/disable layer 3 roaming
                choices:
                    - 'disable'
                    - 'enable'
            local-standalone-dns:
                type: str
                description: Deprecated, please rename it to local_standalone_dns. Enable/disable AP local standalone DNS.
                choices:
                    - 'disable'
                    - 'enable'
            local-standalone-dns-ip:
                type: raw
                description: (list) Deprecated, please rename it to local_standalone_dns_ip.
            osen:
                type: str
                description: Enable/disable OSEN as part of key management
                choices:
                    - 'disable'
                    - 'enable'
            radius-mac-mpsk-auth:
                type: str
                description: Deprecated, please rename it to radius_mac_mpsk_auth. Enable/disable RADIUS-based MAC authentication of clients for MPSK a...
                choices:
                    - 'disable'
                    - 'enable'
            radius-mac-mpsk-timeout:
                type: int
                description: Deprecated, please rename it to radius_mac_mpsk_timeout. RADIUS MAC MPSK cache timeout interval
            rates-11ax-ss12:
                type: list
                elements: str
                description: Deprecated, please rename it to rates_11ax_ss12.
                choices:
                    - 'mcs0/1'
                    - 'mcs1/1'
                    - 'mcs2/1'
                    - 'mcs3/1'
                    - 'mcs4/1'
                    - 'mcs5/1'
                    - 'mcs6/1'
                    - 'mcs7/1'
                    - 'mcs8/1'
                    - 'mcs9/1'
                    - 'mcs10/1'
                    - 'mcs11/1'
                    - 'mcs0/2'
                    - 'mcs1/2'
                    - 'mcs2/2'
                    - 'mcs3/2'
                    - 'mcs4/2'
                    - 'mcs5/2'
                    - 'mcs6/2'
                    - 'mcs7/2'
                    - 'mcs8/2'
                    - 'mcs9/2'
                    - 'mcs10/2'
                    - 'mcs11/2'
            rates-11ax-ss34:
                type: list
                elements: str
                description: Deprecated, please rename it to rates_11ax_ss34.
                choices:
                    - 'mcs0/3'
                    - 'mcs1/3'
                    - 'mcs2/3'
                    - 'mcs3/3'
                    - 'mcs4/3'
                    - 'mcs5/3'
                    - 'mcs6/3'
                    - 'mcs7/3'
                    - 'mcs8/3'
                    - 'mcs9/3'
                    - 'mcs10/3'
                    - 'mcs11/3'
                    - 'mcs0/4'
                    - 'mcs1/4'
                    - 'mcs2/4'
                    - 'mcs3/4'
                    - 'mcs4/4'
                    - 'mcs5/4'
                    - 'mcs6/4'
                    - 'mcs7/4'
                    - 'mcs8/4'
                    - 'mcs9/4'
                    - 'mcs10/4'
                    - 'mcs11/4'
            scan-botnet-connections:
                type: str
                description: Deprecated, please rename it to scan_botnet_connections. Block or monitor connections to Botnet servers or disable Botnet ...
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            utm-log:
                type: str
                description: Deprecated, please rename it to utm_log. Enable/disable UTM logging.
                choices:
                    - 'disable'
                    - 'enable'
            utm-status:
                type: str
                description: Deprecated, please rename it to utm_status. Enable to add one or more security profiles
                choices:
                    - 'disable'
                    - 'enable'
            vlan-name:
                type: list
                elements: dict
                description: Deprecated, please rename it to vlan_name.
                suboptions:
                    name:
                        type: str
                        description: VLAN name.
                    vlan-id:
                        type: int
                        description: Deprecated, please rename it to vlan_id. VLAN ID.
            webfilter-profile:
                type: str
                description: Deprecated, please rename it to webfilter_profile. WebFilter profile name.
            sae-h2e-only:
                type: str
                description: Deprecated, please rename it to sae_h2e_only. Use hash-to-element-only mechanism for PWE derivation
                choices:
                    - 'disable'
                    - 'enable'
            sae-pk:
                type: str
                description: Deprecated, please rename it to sae_pk. Enable/disable WPA3 SAE-PK
                choices:
                    - 'disable'
                    - 'enable'
            sae-private-key:
                type: str
                description: Deprecated, please rename it to sae_private_key. Private key used for WPA3 SAE-PK authentication.
            sticky-client-threshold-6g:
                type: str
                description: Deprecated, please rename it to sticky_client_threshold_6g. Minimum signal level/threshold in dBm required for the 6G clie...
            application-dscp-marking:
                type: str
                description: Deprecated, please rename it to application_dscp_marking. Enable/disable application attribute based DSCP marking
                choices:
                    - 'disable'
                    - 'enable'
            l3-roaming-mode:
                type: str
                description: Deprecated, please rename it to l3_roaming_mode. Select the way that layer 3 roaming traffic is passed
                choices:
                    - 'direct'
                    - 'indirect'
            rates-11ac-mcs-map:
                type: str
                description: Deprecated, please rename it to rates_11ac_mcs_map. Comma separated list of max supported VHT MCS for spatial streams 1 th...
            rates-11ax-mcs-map:
                type: str
                description: Deprecated, please rename it to rates_11ax_mcs_map. Comma separated list of max supported HE MCS for spatial streams 1 thr...
            captive-portal-fw-accounting:
                type: str
                description: Deprecated, please rename it to captive_portal_fw_accounting. Enable/disable RADIUS accounting for captive portal firewall...
                choices:
                    - 'disable'
                    - 'enable'
            radius-mac-auth-block-interval:
                type: int
                description: Deprecated, please rename it to radius_mac_auth_block_interval. Dont send RADIUS MAC auth request again if the client has ...
            _is_factory_setting:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'ext'
            80211k:
                type: str
                description: Deprecated, please rename it to d80211k. Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            80211v:
                type: str
                description: Deprecated, please rename it to d80211v. Enable/disable 802.
                choices:
                    - 'disable'
                    - 'enable'
            roaming-acct-interim-update:
                type: str
                description: Deprecated, please rename it to roaming_acct_interim_update. Enable/disable using accounting interim update instead of acc...
                choices:
                    - 'disable'
                    - 'enable'
            sae-hnp-only:
                type: str
                description: Deprecated, please rename it to sae_hnp_only. Use hunting-and-pecking-only mechanism for PWE derivation
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Configure Virtual Access Points
      fortinet.fortimanager.fmgr_vap:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        vap:
          _centmgmt: <value in [disable, enable]>
          _dhcp_svr_id: <string>
          _intf_allowaccess:
            - https
            - ping
            - ssh
            - snmp
            - http
            - telnet
            - fgfm
            - auto-ipsec
            - radius-acct
            - probe-response
            - capwap
            - dnp
            - ftm
            - fabric
            - speed-test
          _intf_device_identification: <value in [disable, enable]>
          _intf_device_netscan: <value in [disable, enable]>
          _intf_dhcp_relay_ip: <list or string>
          _intf_dhcp_relay_service: <value in [disable, enable]>
          _intf_dhcp_relay_type: <value in [regular, ipsec]>
          _intf_dhcp6_relay_ip: <string>
          _intf_dhcp6_relay_service: <value in [disable, enable]>
          _intf_dhcp6_relay_type: <value in [regular]>
          _intf_ip: <string>
          _intf_ip6_address: <string>
          _intf_ip6_allowaccess:
            - https
            - ping
            - ssh
            - snmp
            - http
            - telnet
            - any
            - fgfm
            - capwap
          _intf_listen_forticlient_connection: <value in [disable, enable]>
          acct_interim_interval: <integer>
          alias: <string>
          auth: <value in [PSK, psk, RADIUS, ...]>
          broadcast_ssid: <value in [disable, enable]>
          broadcast_suppression:
            - dhcp
            - arp
            - dhcp2
            - arp2
            - netbios-ns
            - netbios-ds
            - arp3
            - dhcp-up
            - dhcp-down
            - arp-known
            - arp-unknown
            - arp-reply
            - ipv6
            - dhcp-starvation
            - arp-poison
            - all-other-mc
            - all-other-bc
            - arp-proxy
            - dhcp-ucast
          captive_portal_ac_name: <string>
          captive_portal_macauth_radius_secret: <list or string>
          captive_portal_macauth_radius_server: <string>
          captive_portal_radius_secret: <list or string>
          captive_portal_radius_server: <string>
          captive_portal_session_timeout_interval: <integer>
          dhcp_lease_time: <integer>
          dhcp_option82_circuit_id_insertion: <value in [disable, style-1, style-2, ...]>
          dhcp_option82_insertion: <value in [disable, enable]>
          dhcp_option82_remote_id_insertion: <value in [disable, style-1]>
          dynamic_vlan: <value in [disable, enable]>
          dynamic_mapping:
            -
              _centmgmt: <value in [disable, enable]>
              _dhcp_svr_id: <string>
              _intf_allowaccess:
                - https
                - ping
                - ssh
                - snmp
                - http
                - telnet
                - fgfm
                - auto-ipsec
                - radius-acct
                - probe-response
                - capwap
                - dnp
                - ftm
                - fabric
                - speed-test
              _intf_device_identification: <value in [disable, enable]>
              _intf_device_netscan: <value in [disable, enable]>
              _intf_dhcp_relay_ip: <list or string>
              _intf_dhcp_relay_service: <value in [disable, enable]>
              _intf_dhcp_relay_type: <value in [regular, ipsec]>
              _intf_dhcp6_relay_ip: <string>
              _intf_dhcp6_relay_service: <value in [disable, enable]>
              _intf_dhcp6_relay_type: <value in [regular]>
              _intf_ip: <string>
              _intf_ip6_address: <string>
              _intf_ip6_allowaccess:
                - https
                - ping
                - ssh
                - snmp
                - http
                - telnet
                - any
                - fgfm
                - capwap
              _intf_listen_forticlient_connection: <value in [disable, enable]>
              _scope:
                -
                  name: <string>
                  vdom: <string>
              acct_interim_interval: <integer>
              address_group: <string>
              alias: <string>
              atf_weight: <integer>
              auth: <value in [PSK, psk, RADIUS, ...]>
              broadcast_ssid: <value in [disable, enable]>
              broadcast_suppression:
                - dhcp
                - arp
                - dhcp2
                - arp2
                - netbios-ns
                - netbios-ds
                - arp3
                - dhcp-up
                - dhcp-down
                - arp-known
                - arp-unknown
                - arp-reply
                - ipv6
                - dhcp-starvation
                - arp-poison
                - all-other-mc
                - all-other-bc
                - arp-proxy
                - dhcp-ucast
              captive_portal_ac_name: <string>
              captive_portal_macauth_radius_secret: <list or string>
              captive_portal_macauth_radius_server: <string>
              captive_portal_radius_secret: <list or string>
              captive_portal_radius_server: <string>
              captive_portal_session_timeout_interval: <integer>
              client_count: <integer>
              dhcp_lease_time: <integer>
              dhcp_option82_circuit_id_insertion: <value in [disable, style-1, style-2, ...]>
              dhcp_option82_insertion: <value in [disable, enable]>
              dhcp_option82_remote_id_insertion: <value in [disable, style-1]>
              dynamic_vlan: <value in [disable, enable]>
              eap_reauth: <value in [disable, enable]>
              eap_reauth_intv: <integer>
              eapol_key_retries: <value in [disable, enable]>
              encrypt: <value in [TKIP, AES, TKIP-AES]>
              external_fast_roaming: <value in [disable, enable]>
              external_logout: <string>
              external_web: <string>
              fast_bss_transition: <value in [disable, enable]>
              fast_roaming: <value in [disable, enable]>
              ft_mobility_domain: <integer>
              ft_over_ds: <value in [disable, enable]>
              ft_r0_key_lifetime: <integer>
              gtk_rekey: <value in [disable, enable]>
              gtk_rekey_intv: <integer>
              hotspot20_profile: <string>
              intra_vap_privacy: <value in [disable, enable]>
              ip: <string>
              key: <list or string>
              keyindex: <integer>
              ldpc: <value in [disable, tx, rx, ...]>
              local_authentication: <value in [disable, enable]>
              local_bridging: <value in [disable, enable]>
              local_lan: <value in [deny, allow]>
              local_standalone: <value in [disable, enable]>
              local_standalone_nat: <value in [disable, enable]>
              local_switching: <value in [disable, enable]>
              mac_auth_bypass: <value in [disable, enable]>
              mac_filter: <value in [disable, enable]>
              mac_filter_policy_other: <value in [deny, allow]>
              max_clients: <integer>
              max_clients_ap: <integer>
              me_disable_thresh: <integer>
              mesh_backhaul: <value in [disable, enable]>
              mpsk: <value in [disable, enable]>
              mpsk_concurrent_clients: <integer>
              multicast_enhance: <value in [disable, enable]>
              multicast_rate: <value in [0, 6000, 12000, ...]>
              okc: <value in [disable, enable]>
              owe_groups:
                - 19
                - 20
                - 21
              owe_transition: <value in [disable, enable]>
              owe_transition_ssid: <string>
              passphrase: <list or string>
              pmf: <value in [disable, enable, optional]>
              pmf_assoc_comeback_timeout: <integer>
              pmf_sa_query_retry_timeout: <integer>
              portal_message_override_group: <string>
              portal_type: <value in [auth, auth+disclaimer, disclaimer, ...]>
              probe_resp_suppression: <value in [disable, enable]>
              probe_resp_threshold: <string>
              ptk_rekey: <value in [disable, enable]>
              ptk_rekey_intv: <integer>
              qos_profile: <string>
              quarantine: <value in [disable, enable]>
              radio_2g_threshold: <string>
              radio_5g_threshold: <string>
              radio_sensitivity: <value in [disable, enable]>
              radius_mac_auth: <value in [disable, enable]>
              radius_mac_auth_server: <string>
              radius_mac_auth_usergroups: <list or string>
              radius_server: <string>
              rates_11a:
                - 1
                - 1-basic
                - 2
                - 2-basic
                - 5.5
                - 5.5-basic
                - 6
                - 6-basic
                - 9
                - 9-basic
                - 12
                - 12-basic
                - 18
                - 18-basic
                - 24
                - 24-basic
                - 36
                - 36-basic
                - 48
                - 48-basic
                - 54
                - 54-basic
                - 11
                - 11-basic
              rates_11ac_ss12:
                - mcs0/1
                - mcs1/1
                - mcs2/1
                - mcs3/1
                - mcs4/1
                - mcs5/1
                - mcs6/1
                - mcs7/1
                - mcs8/1
                - mcs9/1
                - mcs0/2
                - mcs1/2
                - mcs2/2
                - mcs3/2
                - mcs4/2
                - mcs5/2
                - mcs6/2
                - mcs7/2
                - mcs8/2
                - mcs9/2
                - mcs10/1
                - mcs11/1
                - mcs10/2
                - mcs11/2
              rates_11ac_ss34:
                - mcs0/3
                - mcs1/3
                - mcs2/3
                - mcs3/3
                - mcs4/3
                - mcs5/3
                - mcs6/3
                - mcs7/3
                - mcs8/3
                - mcs9/3
                - mcs0/4
                - mcs1/4
                - mcs2/4
                - mcs3/4
                - mcs4/4
                - mcs5/4
                - mcs6/4
                - mcs7/4
                - mcs8/4
                - mcs9/4
                - mcs10/3
                - mcs11/3
                - mcs10/4
                - mcs11/4
              rates_11bg:
                - 1
                - 1-basic
                - 2
                - 2-basic
                - 5.5
                - 5.5-basic
                - 6
                - 6-basic
                - 9
                - 9-basic
                - 12
                - 12-basic
                - 18
                - 18-basic
                - 24
                - 24-basic
                - 36
                - 36-basic
                - 48
                - 48-basic
                - 54
                - 54-basic
                - 11
                - 11-basic
              rates_11n_ss12:
                - mcs0/1
                - mcs1/1
                - mcs2/1
                - mcs3/1
                - mcs4/1
                - mcs5/1
                - mcs6/1
                - mcs7/1
                - mcs8/2
                - mcs9/2
                - mcs10/2
                - mcs11/2
                - mcs12/2
                - mcs13/2
                - mcs14/2
                - mcs15/2
              rates_11n_ss34:
                - mcs16/3
                - mcs17/3
                - mcs18/3
                - mcs19/3
                - mcs20/3
                - mcs21/3
                - mcs22/3
                - mcs23/3
                - mcs24/4
                - mcs25/4
                - mcs26/4
                - mcs27/4
                - mcs28/4
                - mcs29/4
                - mcs30/4
                - mcs31/4
              sae_groups:
                - 1
                - 2
                - 5
                - 14
                - 15
                - 16
                - 17
                - 18
                - 19
                - 20
                - 21
                - 27
                - 28
                - 29
                - 30
                - 31
              sae_password: <list or string>
              schedule: <list or string>
              security: <value in [None, WEP64, wep64, ...]>
              security_exempt_list: <string>
              security_obsolete_option: <value in [disable, enable]>
              security_redirect_url: <string>
              selected_usergroups: <list or string>
              split_tunneling: <value in [disable, enable]>
              ssid: <string>
              tkip_counter_measure: <value in [disable, enable]>
              usergroup: <list or string>
              utm_profile: <string>
              vdom: <list or string>
              vlan_auto: <value in [disable, enable]>
              vlan_pooling: <value in [wtp-group, round-robin, hash, ...]>
              vlanid: <integer>
              voice_enterprise: <value in [disable, enable]>
              mu_mimo: <value in [disable, enable]>
              _intf_device_access_list: <string>
              external_web_format: <value in [auto-detect, no-query-string, partial-query-string]>
              high_efficiency: <value in [disable, enable]>
              primary_wag_profile: <string>
              secondary_wag_profile: <string>
              target_wake_time: <value in [disable, enable]>
              tunnel_echo_interval: <integer>
              tunnel_fallback_interval: <integer>
              access_control_list: <string>
              captive_portal_auth_timeout: <integer>
              ipv6_rules:
                - drop-icmp6ra
                - drop-icmp6rs
                - drop-llmnr6
                - drop-icmp6mld2
                - drop-dhcp6s
                - drop-dhcp6c
                - ndp-proxy
                - drop-ns-dad
                - drop-ns-nondad
              sticky_client_remove: <value in [disable, enable]>
              sticky_client_threshold_2g: <string>
              sticky_client_threshold_5g: <string>
              bss_color_partial: <value in [disable, enable]>
              dhcp_option43_insertion: <value in [disable, enable]>
              mpsk_profile: <string>
              igmp_snooping: <value in [disable, enable]>
              port_macauth: <value in [disable, radius, address-group]>
              port_macauth_reauth_timeout: <integer>
              port_macauth_timeout: <integer>
              additional_akms:
                - akm6
              bstm_disassociation_imminent: <value in [disable, enable]>
              bstm_load_balancing_disassoc_timer: <integer>
              bstm_rssi_disassoc_timer: <integer>
              dhcp_address_enforcement: <value in [disable, enable]>
              gas_comeback_delay: <integer>
              gas_fragmentation_limit: <integer>
              mac_called_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
              mac_calling_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
              mac_case: <value in [uppercase, lowercase]>
              mac_password_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
              mac_username_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
              mbo: <value in [disable, enable]>
              mbo_cell_data_conn_pref: <value in [excluded, prefer-not, prefer-use]>
              nac: <value in [disable, enable]>
              nac_profile: <string>
              neighbor_report_dual_band: <value in [disable, enable]>
              address_group_policy: <value in [disable, allow, deny]>
              antivirus_profile: <string>
              application_detection_engine: <value in [disable, enable]>
              application_list: <string>
              application_report_intv: <integer>
              auth_cert: <string>
              auth_portal_addr: <string>
              beacon_advertising:
                - name
                - model
                - serial-number
              ips_sensor: <string>
              l3_roaming: <value in [disable, enable]>
              local_standalone_dns: <value in [disable, enable]>
              local_standalone_dns_ip: <list or string>
              osen: <value in [disable, enable]>
              radius_mac_mpsk_auth: <value in [disable, enable]>
              radius_mac_mpsk_timeout: <integer>
              rates_11ax_ss12:
                - mcs0/1
                - mcs1/1
                - mcs2/1
                - mcs3/1
                - mcs4/1
                - mcs5/1
                - mcs6/1
                - mcs7/1
                - mcs8/1
                - mcs9/1
                - mcs10/1
                - mcs11/1
                - mcs0/2
                - mcs1/2
                - mcs2/2
                - mcs3/2
                - mcs4/2
                - mcs5/2
                - mcs6/2
                - mcs7/2
                - mcs8/2
                - mcs9/2
                - mcs10/2
                - mcs11/2
              rates_11ax_ss34:
                - mcs0/3
                - mcs1/3
                - mcs2/3
                - mcs3/3
                - mcs4/3
                - mcs5/3
                - mcs6/3
                - mcs7/3
                - mcs8/3
                - mcs9/3
                - mcs10/3
                - mcs11/3
                - mcs0/4
                - mcs1/4
                - mcs2/4
                - mcs3/4
                - mcs4/4
                - mcs5/4
                - mcs6/4
                - mcs7/4
                - mcs8/4
                - mcs9/4
                - mcs10/4
                - mcs11/4
              scan_botnet_connections: <value in [disable, block, monitor]>
              utm_log: <value in [disable, enable]>
              utm_status: <value in [disable, enable]>
              webfilter_profile: <string>
              sae_h2e_only: <value in [disable, enable]>
              sae_pk: <value in [disable, enable]>
              sae_private_key: <string>
              sticky_client_threshold_6g: <string>
              application_dscp_marking: <value in [disable, enable]>
              l3_roaming_mode: <value in [direct, indirect]>
              rates_11ac_mcs_map: <string>
              rates_11ax_mcs_map: <string>
              captive_portal_fw_accounting: <value in [disable, enable]>
              radius_mac_auth_block_interval: <integer>
              _is_factory_setting: <value in [disable, enable, ext]>
              d80211k: <value in [disable, enable]>
              d80211v: <value in [disable, enable]>
              roaming_acct_interim_update: <value in [disable, enable]>
              sae_hnp_only: <value in [disable, enable]>
          eap_reauth: <value in [disable, enable]>
          eap_reauth_intv: <integer>
          eapol_key_retries: <value in [disable, enable]>
          encrypt: <value in [TKIP, AES, TKIP-AES]>
          external_fast_roaming: <value in [disable, enable]>
          external_logout: <string>
          external_web: <string>
          fast_bss_transition: <value in [disable, enable]>
          fast_roaming: <value in [disable, enable]>
          ft_mobility_domain: <integer>
          ft_over_ds: <value in [disable, enable]>
          ft_r0_key_lifetime: <integer>
          gtk_rekey: <value in [disable, enable]>
          gtk_rekey_intv: <integer>
          hotspot20_profile: <string>
          intra_vap_privacy: <value in [disable, enable]>
          ip: <string>
          key: <list or string>
          keyindex: <integer>
          ldpc: <value in [disable, tx, rx, ...]>
          local_authentication: <value in [disable, enable]>
          local_bridging: <value in [disable, enable]>
          local_lan: <value in [deny, allow]>
          local_standalone: <value in [disable, enable]>
          local_standalone_nat: <value in [disable, enable]>
          mac_auth_bypass: <value in [disable, enable]>
          mac_filter: <value in [disable, enable]>
          mac_filter_list:
            -
              id: <integer>
              mac: <string>
              mac_filter_policy: <value in [deny, allow]>
          mac_filter_policy_other: <value in [deny, allow]>
          max_clients: <integer>
          max_clients_ap: <integer>
          me_disable_thresh: <integer>
          mesh_backhaul: <value in [disable, enable]>
          mpsk: <value in [disable, enable]>
          mpsk_concurrent_clients: <integer>
          mpsk_key:
            -
              comment: <string>
              concurrent_clients: <string>
              key_name: <string>
              passphrase: <list or string>
              mpsk_schedules: <list or string>
          multicast_enhance: <value in [disable, enable]>
          multicast_rate: <value in [0, 6000, 12000, ...]>
          name: <string>
          okc: <value in [disable, enable]>
          passphrase: <list or string>
          pmf: <value in [disable, enable, optional]>
          pmf_assoc_comeback_timeout: <integer>
          pmf_sa_query_retry_timeout: <integer>
          portal_message_override_group: <string>
          portal_type: <value in [auth, auth+disclaimer, disclaimer, ...]>
          probe_resp_suppression: <value in [disable, enable]>
          probe_resp_threshold: <string>
          ptk_rekey: <value in [disable, enable]>
          ptk_rekey_intv: <integer>
          qos_profile: <string>
          quarantine: <value in [disable, enable]>
          radio_2g_threshold: <string>
          radio_5g_threshold: <string>
          radio_sensitivity: <value in [disable, enable]>
          radius_mac_auth: <value in [disable, enable]>
          radius_mac_auth_server: <string>
          radius_mac_auth_usergroups: <list or string>
          radius_server: <string>
          rates_11a:
            - 1
            - 1-basic
            - 2
            - 2-basic
            - 5.5
            - 5.5-basic
            - 6
            - 6-basic
            - 9
            - 9-basic
            - 12
            - 12-basic
            - 18
            - 18-basic
            - 24
            - 24-basic
            - 36
            - 36-basic
            - 48
            - 48-basic
            - 54
            - 54-basic
            - 11
            - 11-basic
          rates_11ac_ss12:
            - mcs0/1
            - mcs1/1
            - mcs2/1
            - mcs3/1
            - mcs4/1
            - mcs5/1
            - mcs6/1
            - mcs7/1
            - mcs8/1
            - mcs9/1
            - mcs0/2
            - mcs1/2
            - mcs2/2
            - mcs3/2
            - mcs4/2
            - mcs5/2
            - mcs6/2
            - mcs7/2
            - mcs8/2
            - mcs9/2
            - mcs10/1
            - mcs11/1
            - mcs10/2
            - mcs11/2
          rates_11ac_ss34:
            - mcs0/3
            - mcs1/3
            - mcs2/3
            - mcs3/3
            - mcs4/3
            - mcs5/3
            - mcs6/3
            - mcs7/3
            - mcs8/3
            - mcs9/3
            - mcs0/4
            - mcs1/4
            - mcs2/4
            - mcs3/4
            - mcs4/4
            - mcs5/4
            - mcs6/4
            - mcs7/4
            - mcs8/4
            - mcs9/4
            - mcs10/3
            - mcs11/3
            - mcs10/4
            - mcs11/4
          rates_11bg:
            - 1
            - 1-basic
            - 2
            - 2-basic
            - 5.5
            - 5.5-basic
            - 6
            - 6-basic
            - 9
            - 9-basic
            - 12
            - 12-basic
            - 18
            - 18-basic
            - 24
            - 24-basic
            - 36
            - 36-basic
            - 48
            - 48-basic
            - 54
            - 54-basic
            - 11
            - 11-basic
          rates_11n_ss12:
            - mcs0/1
            - mcs1/1
            - mcs2/1
            - mcs3/1
            - mcs4/1
            - mcs5/1
            - mcs6/1
            - mcs7/1
            - mcs8/2
            - mcs9/2
            - mcs10/2
            - mcs11/2
            - mcs12/2
            - mcs13/2
            - mcs14/2
            - mcs15/2
          rates_11n_ss34:
            - mcs16/3
            - mcs17/3
            - mcs18/3
            - mcs19/3
            - mcs20/3
            - mcs21/3
            - mcs22/3
            - mcs23/3
            - mcs24/4
            - mcs25/4
            - mcs26/4
            - mcs27/4
            - mcs28/4
            - mcs29/4
            - mcs30/4
            - mcs31/4
          schedule: <list or string>
          security: <value in [None, WEP64, wep64, ...]>
          security_exempt_list: <string>
          security_obsolete_option: <value in [disable, enable]>
          security_redirect_url: <string>
          selected_usergroups: <list or string>
          split_tunneling: <value in [disable, enable]>
          ssid: <string>
          tkip_counter_measure: <value in [disable, enable]>
          usergroup: <list or string>
          utm_profile: <string>
          vdom: <string>
          vlan_auto: <value in [disable, enable]>
          vlan_pool:
            -
              _wtp_group: <string>
              id: <integer>
              wtp_group: <string>
          vlan_pooling: <value in [wtp-group, round-robin, hash, ...]>
          vlanid: <integer>
          voice_enterprise: <value in [disable, enable]>
          address_group: <string>
          atf_weight: <integer>
          mu_mimo: <value in [disable, enable]>
          owe_groups:
            - 19
            - 20
            - 21
          owe_transition: <value in [disable, enable]>
          owe_transition_ssid: <string>
          sae_groups:
            - 1
            - 2
            - 5
            - 14
            - 15
            - 16
            - 17
            - 18
            - 19
            - 20
            - 21
            - 27
            - 28
            - 29
            - 30
            - 31
          sae_password: <list or string>
          _intf_device_access_list: <string>
          external_web_format: <value in [auto-detect, no-query-string, partial-query-string]>
          high_efficiency: <value in [disable, enable]>
          primary_wag_profile: <string>
          secondary_wag_profile: <string>
          target_wake_time: <value in [disable, enable]>
          tunnel_echo_interval: <integer>
          tunnel_fallback_interval: <integer>
          access_control_list: <string>
          captive_portal_auth_timeout: <integer>
          ipv6_rules:
            - drop-icmp6ra
            - drop-icmp6rs
            - drop-llmnr6
            - drop-icmp6mld2
            - drop-dhcp6s
            - drop-dhcp6c
            - ndp-proxy
            - drop-ns-dad
            - drop-ns-nondad
          sticky_client_remove: <value in [disable, enable]>
          sticky_client_threshold_2g: <string>
          sticky_client_threshold_5g: <string>
          bss_color_partial: <value in [disable, enable]>
          dhcp_option43_insertion: <value in [disable, enable]>
          mpsk_profile: <string>
          igmp_snooping: <value in [disable, enable]>
          port_macauth: <value in [disable, radius, address-group]>
          port_macauth_reauth_timeout: <integer>
          port_macauth_timeout: <integer>
          portal_message_overrides:
            auth_disclaimer_page: <string>
            auth_login_failed_page: <string>
            auth_login_page: <string>
            auth_reject_page: <string>
          additional_akms:
            - akm6
          bstm_disassociation_imminent: <value in [disable, enable]>
          bstm_load_balancing_disassoc_timer: <integer>
          bstm_rssi_disassoc_timer: <integer>
          dhcp_address_enforcement: <value in [disable, enable]>
          gas_comeback_delay: <integer>
          gas_fragmentation_limit: <integer>
          mac_called_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          mac_calling_station_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          mac_case: <value in [uppercase, lowercase]>
          mac_password_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          mac_username_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          mbo: <value in [disable, enable]>
          mbo_cell_data_conn_pref: <value in [excluded, prefer-not, prefer-use]>
          nac: <value in [disable, enable]>
          nac_profile: <string>
          neighbor_report_dual_band: <value in [disable, enable]>
          address_group_policy: <value in [disable, allow, deny]>
          antivirus_profile: <string>
          application_detection_engine: <value in [disable, enable]>
          application_list: <string>
          application_report_intv: <integer>
          auth_cert: <string>
          auth_portal_addr: <string>
          beacon_advertising:
            - name
            - model
            - serial-number
          ips_sensor: <string>
          l3_roaming: <value in [disable, enable]>
          local_standalone_dns: <value in [disable, enable]>
          local_standalone_dns_ip: <list or string>
          osen: <value in [disable, enable]>
          radius_mac_mpsk_auth: <value in [disable, enable]>
          radius_mac_mpsk_timeout: <integer>
          rates_11ax_ss12:
            - mcs0/1
            - mcs1/1
            - mcs2/1
            - mcs3/1
            - mcs4/1
            - mcs5/1
            - mcs6/1
            - mcs7/1
            - mcs8/1
            - mcs9/1
            - mcs10/1
            - mcs11/1
            - mcs0/2
            - mcs1/2
            - mcs2/2
            - mcs3/2
            - mcs4/2
            - mcs5/2
            - mcs6/2
            - mcs7/2
            - mcs8/2
            - mcs9/2
            - mcs10/2
            - mcs11/2
          rates_11ax_ss34:
            - mcs0/3
            - mcs1/3
            - mcs2/3
            - mcs3/3
            - mcs4/3
            - mcs5/3
            - mcs6/3
            - mcs7/3
            - mcs8/3
            - mcs9/3
            - mcs10/3
            - mcs11/3
            - mcs0/4
            - mcs1/4
            - mcs2/4
            - mcs3/4
            - mcs4/4
            - mcs5/4
            - mcs6/4
            - mcs7/4
            - mcs8/4
            - mcs9/4
            - mcs10/4
            - mcs11/4
          scan_botnet_connections: <value in [disable, block, monitor]>
          utm_log: <value in [disable, enable]>
          utm_status: <value in [disable, enable]>
          vlan_name:
            -
              name: <string>
              vlan_id: <integer>
          webfilter_profile: <string>
          sae_h2e_only: <value in [disable, enable]>
          sae_pk: <value in [disable, enable]>
          sae_private_key: <string>
          sticky_client_threshold_6g: <string>
          application_dscp_marking: <value in [disable, enable]>
          l3_roaming_mode: <value in [direct, indirect]>
          rates_11ac_mcs_map: <string>
          rates_11ax_mcs_map: <string>
          captive_portal_fw_accounting: <value in [disable, enable]>
          radius_mac_auth_block_interval: <integer>
          _is_factory_setting: <value in [disable, enable, ext]>
          d80211k: <value in [disable, enable]>
          d80211v: <value in [disable, enable]>
          roaming_acct_interim_update: <value in [disable, enable]>
          sae_hnp_only: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/vap',
        '/pm/config/global/obj/wireless-controller/vap'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}',
        '/pm/config/global/obj/wireless-controller/vap/{vap}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vap': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_centmgmt': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_dhcp_svr_id': {'type': 'str'},
                '_intf_allowaccess': {
                    'type': 'list',
                    'choices': [
                        'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'auto-ipsec', 'radius-acct', 'probe-response', 'capwap', 'dnp', 'ftm',
                        'fabric', 'speed-test'
                    ],
                    'elements': 'str'
                },
                '_intf_device-identification': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_device-netscan': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_dhcp-relay-ip': {'type': 'raw'},
                '_intf_dhcp-relay-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_dhcp-relay-type': {'choices': ['regular', 'ipsec'], 'type': 'str'},
                '_intf_dhcp6-relay-ip': {'type': 'str'},
                '_intf_dhcp6-relay-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_intf_dhcp6-relay-type': {'choices': ['regular'], 'type': 'str'},
                '_intf_ip': {'type': 'str'},
                '_intf_ip6-address': {'type': 'str'},
                '_intf_ip6-allowaccess': {
                    'type': 'list',
                    'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'any', 'fgfm', 'capwap'],
                    'elements': 'str'
                },
                '_intf_listen-forticlient-connection': {'choices': ['disable', 'enable'], 'type': 'str'},
                'acct-interim-interval': {'type': 'int'},
                'alias': {'type': 'str'},
                'auth': {'choices': ['PSK', 'psk', 'RADIUS', 'radius', 'usergroup'], 'type': 'str'},
                'broadcast-ssid': {'choices': ['disable', 'enable'], 'type': 'str'},
                'broadcast-suppression': {
                    'type': 'list',
                    'choices': [
                        'dhcp', 'arp', 'dhcp2', 'arp2', 'netbios-ns', 'netbios-ds', 'arp3', 'dhcp-up', 'dhcp-down', 'arp-known', 'arp-unknown',
                        'arp-reply', 'ipv6', 'dhcp-starvation', 'arp-poison', 'all-other-mc', 'all-other-bc', 'arp-proxy', 'dhcp-ucast'
                    ],
                    'elements': 'str'
                },
                'captive-portal-ac-name': {'type': 'str'},
                'captive-portal-macauth-radius-secret': {'no_log': True, 'type': 'raw'},
                'captive-portal-macauth-radius-server': {'type': 'str'},
                'captive-portal-radius-secret': {'no_log': True, 'type': 'raw'},
                'captive-portal-radius-server': {'type': 'str'},
                'captive-portal-session-timeout-interval': {'type': 'int'},
                'dhcp-lease-time': {'type': 'int'},
                'dhcp-option82-circuit-id-insertion': {'choices': ['disable', 'style-1', 'style-2', 'style-3'], 'type': 'str'},
                'dhcp-option82-insertion': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-option82-remote-id-insertion': {'choices': ['disable', 'style-1'], 'type': 'str'},
                'dynamic-vlan': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dynamic_mapping': {
                    'type': 'list',
                    'options': {
                        '_centmgmt': {'choices': ['disable', 'enable'], 'type': 'str'},
                        '_dhcp_svr_id': {'type': 'str'},
                        '_intf_allowaccess': {
                            'type': 'list',
                            'choices': [
                                'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'auto-ipsec', 'radius-acct', 'probe-response', 'capwap', 'dnp',
                                'ftm', 'fabric', 'speed-test'
                            ],
                            'elements': 'str'
                        },
                        '_intf_device-identification': {'choices': ['disable', 'enable'], 'type': 'str'},
                        '_intf_device-netscan': {'choices': ['disable', 'enable'], 'type': 'str'},
                        '_intf_dhcp-relay-ip': {'type': 'raw'},
                        '_intf_dhcp-relay-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                        '_intf_dhcp-relay-type': {'choices': ['regular', 'ipsec'], 'type': 'str'},
                        '_intf_dhcp6-relay-ip': {'type': 'str'},
                        '_intf_dhcp6-relay-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                        '_intf_dhcp6-relay-type': {'choices': ['regular'], 'type': 'str'},
                        '_intf_ip': {'type': 'str'},
                        '_intf_ip6-address': {'type': 'str'},
                        '_intf_ip6-allowaccess': {
                            'type': 'list',
                            'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'any', 'fgfm', 'capwap'],
                            'elements': 'str'
                        },
                        '_intf_listen-forticlient-connection': {'choices': ['disable', 'enable'], 'type': 'str'},
                        '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                        'acct-interim-interval': {'type': 'int'},
                        'address-group': {'type': 'str'},
                        'alias': {'type': 'str'},
                        'atf-weight': {'type': 'int'},
                        'auth': {'choices': ['PSK', 'psk', 'RADIUS', 'radius', 'usergroup'], 'type': 'str'},
                        'broadcast-ssid': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'broadcast-suppression': {
                            'type': 'list',
                            'choices': [
                                'dhcp', 'arp', 'dhcp2', 'arp2', 'netbios-ns', 'netbios-ds', 'arp3', 'dhcp-up', 'dhcp-down', 'arp-known', 'arp-unknown',
                                'arp-reply', 'ipv6', 'dhcp-starvation', 'arp-poison', 'all-other-mc', 'all-other-bc', 'arp-proxy', 'dhcp-ucast'
                            ],
                            'elements': 'str'
                        },
                        'captive-portal-ac-name': {'type': 'str'},
                        'captive-portal-macauth-radius-secret': {'no_log': True, 'type': 'raw'},
                        'captive-portal-macauth-radius-server': {'type': 'str'},
                        'captive-portal-radius-secret': {'no_log': True, 'type': 'raw'},
                        'captive-portal-radius-server': {'type': 'str'},
                        'captive-portal-session-timeout-interval': {'type': 'int'},
                        'client-count': {'type': 'int'},
                        'dhcp-lease-time': {'type': 'int'},
                        'dhcp-option82-circuit-id-insertion': {'choices': ['disable', 'style-1', 'style-2', 'style-3'], 'type': 'str'},
                        'dhcp-option82-insertion': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-option82-remote-id-insertion': {'choices': ['disable', 'style-1'], 'type': 'str'},
                        'dynamic-vlan': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'eap-reauth': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'eap-reauth-intv': {'type': 'int'},
                        'eapol-key-retries': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'encrypt': {'choices': ['TKIP', 'AES', 'TKIP-AES'], 'type': 'str'},
                        'external-fast-roaming': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'external-logout': {'type': 'str'},
                        'external-web': {'type': 'str'},
                        'fast-bss-transition': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'fast-roaming': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ft-mobility-domain': {'type': 'int'},
                        'ft-over-ds': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ft-r0-key-lifetime': {'no_log': True, 'type': 'int'},
                        'gtk-rekey': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'gtk-rekey-intv': {'no_log': True, 'type': 'int'},
                        'hotspot20-profile': {'type': 'str'},
                        'intra-vap-privacy': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ip': {'type': 'str'},
                        'key': {'no_log': True, 'type': 'raw'},
                        'keyindex': {'no_log': True, 'type': 'int'},
                        'ldpc': {'choices': ['disable', 'tx', 'rx', 'rxtx'], 'type': 'str'},
                        'local-authentication': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-bridging': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-lan': {'choices': ['deny', 'allow'], 'type': 'str'},
                        'local-standalone': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-standalone-nat': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-switching': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'mac-auth-bypass': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'mac-filter': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'mac-filter-policy-other': {'choices': ['deny', 'allow'], 'type': 'str'},
                        'max-clients': {'type': 'int'},
                        'max-clients-ap': {'type': 'int'},
                        'me-disable-thresh': {'type': 'int'},
                        'mesh-backhaul': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'mpsk': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'mpsk-concurrent-clients': {'type': 'int'},
                        'multicast-enhance': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'multicast-rate': {'choices': ['0', '6000', '12000', '24000'], 'type': 'str'},
                        'okc': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'owe-groups': {'type': 'list', 'choices': ['19', '20', '21'], 'elements': 'str'},
                        'owe-transition': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'owe-transition-ssid': {'type': 'str'},
                        'passphrase': {'no_log': True, 'type': 'raw'},
                        'pmf': {'choices': ['disable', 'enable', 'optional'], 'type': 'str'},
                        'pmf-assoc-comeback-timeout': {'type': 'int'},
                        'pmf-sa-query-retry-timeout': {'type': 'int'},
                        'portal-message-override-group': {'type': 'str'},
                        'portal-type': {
                            'choices': [
                                'auth', 'auth+disclaimer', 'disclaimer', 'email-collect', 'cmcc', 'cmcc-macauth', 'auth-mac', 'external-auth',
                                'external-macauth'
                            ],
                            'type': 'str'
                        },
                        'probe-resp-suppression': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'probe-resp-threshold': {'type': 'str'},
                        'ptk-rekey': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ptk-rekey-intv': {'no_log': True, 'type': 'int'},
                        'qos-profile': {'type': 'str'},
                        'quarantine': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'radio-2g-threshold': {'type': 'str'},
                        'radio-5g-threshold': {'type': 'str'},
                        'radio-sensitivity': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'radius-mac-auth': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'radius-mac-auth-server': {'type': 'str'},
                        'radius-mac-auth-usergroups': {'type': 'raw'},
                        'radius-server': {'type': 'str'},
                        'rates-11a': {
                            'type': 'list',
                            'choices': [
                                '1', '1-basic', '2', '2-basic', '5.5', '5.5-basic', '6', '6-basic', '9', '9-basic', '12', '12-basic', '18', '18-basic',
                                '24', '24-basic', '36', '36-basic', '48', '48-basic', '54', '54-basic', '11', '11-basic'
                            ],
                            'elements': 'str'
                        },
                        'rates-11ac-ss12': {
                            'type': 'list',
                            'choices': [
                                'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/1', 'mcs9/1', 'mcs0/2', 'mcs1/2',
                                'mcs2/2', 'mcs3/2', 'mcs4/2', 'mcs5/2', 'mcs6/2', 'mcs7/2', 'mcs8/2', 'mcs9/2', 'mcs10/1', 'mcs11/1', 'mcs10/2',
                                'mcs11/2'
                            ],
                            'elements': 'str'
                        },
                        'rates-11ac-ss34': {
                            'type': 'list',
                            'choices': [
                                'mcs0/3', 'mcs1/3', 'mcs2/3', 'mcs3/3', 'mcs4/3', 'mcs5/3', 'mcs6/3', 'mcs7/3', 'mcs8/3', 'mcs9/3', 'mcs0/4', 'mcs1/4',
                                'mcs2/4', 'mcs3/4', 'mcs4/4', 'mcs5/4', 'mcs6/4', 'mcs7/4', 'mcs8/4', 'mcs9/4', 'mcs10/3', 'mcs11/3', 'mcs10/4',
                                'mcs11/4'
                            ],
                            'elements': 'str'
                        },
                        'rates-11bg': {
                            'type': 'list',
                            'choices': [
                                '1', '1-basic', '2', '2-basic', '5.5', '5.5-basic', '6', '6-basic', '9', '9-basic', '12', '12-basic', '18', '18-basic',
                                '24', '24-basic', '36', '36-basic', '48', '48-basic', '54', '54-basic', '11', '11-basic'
                            ],
                            'elements': 'str'
                        },
                        'rates-11n-ss12': {
                            'type': 'list',
                            'choices': [
                                'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/2', 'mcs9/2', 'mcs10/2', 'mcs11/2',
                                'mcs12/2', 'mcs13/2', 'mcs14/2', 'mcs15/2'
                            ],
                            'elements': 'str'
                        },
                        'rates-11n-ss34': {
                            'type': 'list',
                            'choices': [
                                'mcs16/3', 'mcs17/3', 'mcs18/3', 'mcs19/3', 'mcs20/3', 'mcs21/3', 'mcs22/3', 'mcs23/3', 'mcs24/4', 'mcs25/4', 'mcs26/4',
                                'mcs27/4', 'mcs28/4', 'mcs29/4', 'mcs30/4', 'mcs31/4'
                            ],
                            'elements': 'str'
                        },
                        'sae-groups': {
                            'type': 'list',
                            'choices': ['1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '27', '28', '29', '30', '31'],
                            'elements': 'str'
                        },
                        'sae-password': {'no_log': True, 'type': 'raw'},
                        'schedule': {'type': 'raw'},
                        'security': {
                            'choices': [
                                'None', 'WEP64', 'wep64', 'WEP128', 'wep128', 'WPA_PSK', 'WPA_RADIUS', 'WPA', 'WPA2', 'WPA2_AUTO', 'open',
                                'wpa-personal', 'wpa-enterprise', 'captive-portal', 'wpa-only-personal', 'wpa-only-enterprise', 'wpa2-only-personal',
                                'wpa2-only-enterprise', 'wpa-personal+captive-portal', 'wpa-only-personal+captive-portal',
                                'wpa2-only-personal+captive-portal', 'osen', 'wpa3-enterprise', 'sae', 'sae-transition', 'owe', 'wpa3-sae',
                                'wpa3-sae-transition', 'wpa3-only-enterprise', 'wpa3-enterprise-transition'
                            ],
                            'type': 'str'
                        },
                        'security-exempt-list': {'type': 'str'},
                        'security-obsolete-option': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'security-redirect-url': {'type': 'str'},
                        'selected-usergroups': {'type': 'raw'},
                        'split-tunneling': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssid': {'type': 'str'},
                        'tkip-counter-measure': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'usergroup': {'type': 'raw'},
                        'utm-profile': {'type': 'str'},
                        'vdom': {'type': 'raw'},
                        'vlan-auto': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'vlan-pooling': {'choices': ['wtp-group', 'round-robin', 'hash', 'disable'], 'type': 'str'},
                        'vlanid': {'type': 'int'},
                        'voice-enterprise': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'mu-mimo': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        '_intf_device-access-list': {'v_range': [['6.2.2', '']], 'type': 'str'},
                        'external-web-format': {
                            'v_range': [['6.2.2', '']],
                            'choices': ['auto-detect', 'no-query-string', 'partial-query-string'],
                            'type': 'str'
                        },
                        'high-efficiency': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'primary-wag-profile': {'v_range': [['6.2.2', '']], 'type': 'str'},
                        'secondary-wag-profile': {'v_range': [['6.2.2', '']], 'type': 'str'},
                        'target-wake-time': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tunnel-echo-interval': {'v_range': [['6.2.2', '']], 'type': 'int'},
                        'tunnel-fallback-interval': {'v_range': [['6.2.2', '']], 'type': 'int'},
                        'access-control-list': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'captive-portal-auth-timeout': {'v_range': [['6.4.0', '']], 'type': 'int'},
                        'ipv6-rules': {
                            'v_range': [['6.4.0', '']],
                            'type': 'list',
                            'choices': [
                                'drop-icmp6ra', 'drop-icmp6rs', 'drop-llmnr6', 'drop-icmp6mld2', 'drop-dhcp6s', 'drop-dhcp6c', 'ndp-proxy',
                                'drop-ns-dad', 'drop-ns-nondad'
                            ],
                            'elements': 'str'
                        },
                        'sticky-client-remove': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sticky-client-threshold-2g': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'sticky-client-threshold-5g': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'bss-color-partial': {'v_range': [['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-option43-insertion': {'v_range': [['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mpsk-profile': {'v_range': [['6.4.2', '']], 'type': 'str'},
                        'igmp-snooping': {'v_range': [['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'port-macauth': {
                            'v_range': [['6.2.8', '6.2.12'], ['6.4.3', '']],
                            'choices': ['disable', 'radius', 'address-group'],
                            'type': 'str'
                        },
                        'port-macauth-reauth-timeout': {'v_range': [['6.2.8', '6.2.12'], ['6.4.3', '']], 'type': 'int'},
                        'port-macauth-timeout': {'v_range': [['6.2.8', '6.2.12'], ['6.4.3', '']], 'type': 'int'},
                        'additional-akms': {'v_range': [['7.0.0', '']], 'type': 'list', 'choices': ['akm6'], 'elements': 'str'},
                        'bstm-disassociation-imminent': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bstm-load-balancing-disassoc-timer': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'bstm-rssi-disassoc-timer': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'dhcp-address-enforcement': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'gas-comeback-delay': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'gas-fragmentation-limit': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'mac-called-station-delimiter': {
                            'v_range': [['7.0.0', '']],
                            'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                            'type': 'str'
                        },
                        'mac-calling-station-delimiter': {
                            'v_range': [['7.0.0', '']],
                            'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                            'type': 'str'
                        },
                        'mac-case': {'v_range': [['7.0.0', '']], 'choices': ['uppercase', 'lowercase'], 'type': 'str'},
                        'mac-password-delimiter': {'v_range': [['7.0.0', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                        'mac-username-delimiter': {'v_range': [['7.0.0', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                        'mbo': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mbo-cell-data-conn-pref': {'v_range': [['7.0.0', '']], 'choices': ['excluded', 'prefer-not', 'prefer-use'], 'type': 'str'},
                        'nac': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'nac-profile': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'neighbor-report-dual-band': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'address-group-policy': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'allow', 'deny'], 'type': 'str'},
                        'antivirus-profile': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'application-detection-engine': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'application-list': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'application-report-intv': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'auth-cert': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'auth-portal-addr': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'beacon-advertising': {
                            'v_range': [['7.0.2', '']],
                            'type': 'list',
                            'choices': ['name', 'model', 'serial-number'],
                            'elements': 'str'
                        },
                        'ips-sensor': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'l3-roaming': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-standalone-dns': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'local-standalone-dns-ip': {'v_range': [['7.0.1', '']], 'type': 'raw'},
                        'osen': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'radius-mac-mpsk-auth': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'radius-mac-mpsk-timeout': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'rates-11ax-ss12': {
                            'v_range': [['7.0.2', '']],
                            'type': 'list',
                            'choices': [
                                'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/1', 'mcs9/1', 'mcs10/1', 'mcs11/1',
                                'mcs0/2', 'mcs1/2', 'mcs2/2', 'mcs3/2', 'mcs4/2', 'mcs5/2', 'mcs6/2', 'mcs7/2', 'mcs8/2', 'mcs9/2', 'mcs10/2', 'mcs11/2'
                            ],
                            'elements': 'str'
                        },
                        'rates-11ax-ss34': {
                            'v_range': [['7.0.2', '']],
                            'type': 'list',
                            'choices': [
                                'mcs0/3', 'mcs1/3', 'mcs2/3', 'mcs3/3', 'mcs4/3', 'mcs5/3', 'mcs6/3', 'mcs7/3', 'mcs8/3', 'mcs9/3', 'mcs10/3', 'mcs11/3',
                                'mcs0/4', 'mcs1/4', 'mcs2/4', 'mcs3/4', 'mcs4/4', 'mcs5/4', 'mcs6/4', 'mcs7/4', 'mcs8/4', 'mcs9/4', 'mcs10/4', 'mcs11/4'
                            ],
                            'elements': 'str'
                        },
                        'scan-botnet-connections': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'utm-log': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'utm-status': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'webfilter-profile': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'sae-h2e-only': {'v_range': [['7.0.5', '7.0.12'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sae-pk': {'v_range': [['7.0.5', '7.0.12'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sae-private-key': {'v_range': [['7.0.5', '7.0.12'], ['7.2.1', '']], 'no_log': True, 'type': 'str'},
                        'sticky-client-threshold-6g': {'v_range': [['7.0.5', '7.0.12'], ['7.2.1', '']], 'type': 'str'},
                        'application-dscp-marking': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'l3-roaming-mode': {'v_range': [['7.2.1', '']], 'choices': ['direct', 'indirect'], 'type': 'str'},
                        'rates-11ac-mcs-map': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'rates-11ax-mcs-map': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'captive-portal-fw-accounting': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'radius-mac-auth-block-interval': {'v_range': [['7.2.2', '']], 'type': 'int'},
                        '_is_factory_setting': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable', 'ext'], 'type': 'str'},
                        '80211k': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        '80211v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'roaming-acct-interim-update': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sae-hnp-only': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'eap-reauth': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eap-reauth-intv': {'type': 'int'},
                'eapol-key-retries': {'choices': ['disable', 'enable'], 'type': 'str'},
                'encrypt': {'choices': ['TKIP', 'AES', 'TKIP-AES'], 'type': 'str'},
                'external-fast-roaming': {'choices': ['disable', 'enable'], 'type': 'str'},
                'external-logout': {'type': 'str'},
                'external-web': {'type': 'str'},
                'fast-bss-transition': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fast-roaming': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ft-mobility-domain': {'type': 'int'},
                'ft-over-ds': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ft-r0-key-lifetime': {'no_log': True, 'type': 'int'},
                'gtk-rekey': {'choices': ['disable', 'enable'], 'type': 'str'},
                'gtk-rekey-intv': {'no_log': True, 'type': 'int'},
                'hotspot20-profile': {'type': 'str'},
                'intra-vap-privacy': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ip': {'type': 'str'},
                'key': {'no_log': True, 'type': 'raw'},
                'keyindex': {'no_log': True, 'type': 'int'},
                'ldpc': {'choices': ['disable', 'tx', 'rx', 'rxtx'], 'type': 'str'},
                'local-authentication': {'choices': ['disable', 'enable'], 'type': 'str'},
                'local-bridging': {'choices': ['disable', 'enable'], 'type': 'str'},
                'local-lan': {'choices': ['deny', 'allow'], 'type': 'str'},
                'local-standalone': {'choices': ['disable', 'enable'], 'type': 'str'},
                'local-standalone-nat': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-auth-bypass': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-filter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-filter-list': {
                    'type': 'list',
                    'options': {'id': {'type': 'int'}, 'mac': {'type': 'str'}, 'mac-filter-policy': {'choices': ['deny', 'allow'], 'type': 'str'}},
                    'elements': 'dict'
                },
                'mac-filter-policy-other': {'choices': ['deny', 'allow'], 'type': 'str'},
                'max-clients': {'type': 'int'},
                'max-clients-ap': {'type': 'int'},
                'me-disable-thresh': {'type': 'int'},
                'mesh-backhaul': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mpsk': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mpsk-concurrent-clients': {'type': 'int'},
                'mpsk-key': {
                    'no_log': True,
                    'type': 'list',
                    'options': {
                        'comment': {'type': 'str'},
                        'concurrent-clients': {'type': 'str'},
                        'key-name': {'no_log': True, 'type': 'str'},
                        'passphrase': {'no_log': True, 'type': 'raw'},
                        'mpsk-schedules': {'v_range': [['6.2.2', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'multicast-enhance': {'choices': ['disable', 'enable'], 'type': 'str'},
                'multicast-rate': {'choices': ['0', '6000', '12000', '24000'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'okc': {'choices': ['disable', 'enable'], 'type': 'str'},
                'passphrase': {'no_log': True, 'type': 'raw'},
                'pmf': {'choices': ['disable', 'enable', 'optional'], 'type': 'str'},
                'pmf-assoc-comeback-timeout': {'type': 'int'},
                'pmf-sa-query-retry-timeout': {'type': 'int'},
                'portal-message-override-group': {'type': 'str'},
                'portal-type': {
                    'choices': [
                        'auth', 'auth+disclaimer', 'disclaimer', 'email-collect', 'cmcc', 'cmcc-macauth', 'auth-mac', 'external-auth',
                        'external-macauth'
                    ],
                    'type': 'str'
                },
                'probe-resp-suppression': {'choices': ['disable', 'enable'], 'type': 'str'},
                'probe-resp-threshold': {'type': 'str'},
                'ptk-rekey': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ptk-rekey-intv': {'no_log': True, 'type': 'int'},
                'qos-profile': {'type': 'str'},
                'quarantine': {'choices': ['disable', 'enable'], 'type': 'str'},
                'radio-2g-threshold': {'type': 'str'},
                'radio-5g-threshold': {'type': 'str'},
                'radio-sensitivity': {'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-auth': {'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-auth-server': {'type': 'str'},
                'radius-mac-auth-usergroups': {'type': 'raw'},
                'radius-server': {'type': 'str'},
                'rates-11a': {
                    'type': 'list',
                    'choices': [
                        '1', '1-basic', '2', '2-basic', '5.5', '5.5-basic', '6', '6-basic', '9', '9-basic', '12', '12-basic', '18', '18-basic', '24',
                        '24-basic', '36', '36-basic', '48', '48-basic', '54', '54-basic', '11', '11-basic'
                    ],
                    'elements': 'str'
                },
                'rates-11ac-ss12': {
                    'type': 'list',
                    'choices': [
                        'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/1', 'mcs9/1', 'mcs0/2', 'mcs1/2', 'mcs2/2',
                        'mcs3/2', 'mcs4/2', 'mcs5/2', 'mcs6/2', 'mcs7/2', 'mcs8/2', 'mcs9/2', 'mcs10/1', 'mcs11/1', 'mcs10/2', 'mcs11/2'
                    ],
                    'elements': 'str'
                },
                'rates-11ac-ss34': {
                    'type': 'list',
                    'choices': [
                        'mcs0/3', 'mcs1/3', 'mcs2/3', 'mcs3/3', 'mcs4/3', 'mcs5/3', 'mcs6/3', 'mcs7/3', 'mcs8/3', 'mcs9/3', 'mcs0/4', 'mcs1/4', 'mcs2/4',
                        'mcs3/4', 'mcs4/4', 'mcs5/4', 'mcs6/4', 'mcs7/4', 'mcs8/4', 'mcs9/4', 'mcs10/3', 'mcs11/3', 'mcs10/4', 'mcs11/4'
                    ],
                    'elements': 'str'
                },
                'rates-11bg': {
                    'type': 'list',
                    'choices': [
                        '1', '1-basic', '2', '2-basic', '5.5', '5.5-basic', '6', '6-basic', '9', '9-basic', '12', '12-basic', '18', '18-basic', '24',
                        '24-basic', '36', '36-basic', '48', '48-basic', '54', '54-basic', '11', '11-basic'
                    ],
                    'elements': 'str'
                },
                'rates-11n-ss12': {
                    'type': 'list',
                    'choices': [
                        'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/2', 'mcs9/2', 'mcs10/2', 'mcs11/2',
                        'mcs12/2', 'mcs13/2', 'mcs14/2', 'mcs15/2'
                    ],
                    'elements': 'str'
                },
                'rates-11n-ss34': {
                    'type': 'list',
                    'choices': [
                        'mcs16/3', 'mcs17/3', 'mcs18/3', 'mcs19/3', 'mcs20/3', 'mcs21/3', 'mcs22/3', 'mcs23/3', 'mcs24/4', 'mcs25/4', 'mcs26/4',
                        'mcs27/4', 'mcs28/4', 'mcs29/4', 'mcs30/4', 'mcs31/4'
                    ],
                    'elements': 'str'
                },
                'schedule': {'type': 'raw'},
                'security': {
                    'choices': [
                        'None', 'WEP64', 'wep64', 'WEP128', 'wep128', 'WPA_PSK', 'WPA_RADIUS', 'WPA', 'WPA2', 'WPA2_AUTO', 'open', 'wpa-personal',
                        'wpa-enterprise', 'captive-portal', 'wpa-only-personal', 'wpa-only-enterprise', 'wpa2-only-personal', 'wpa2-only-enterprise',
                        'wpa-personal+captive-portal', 'wpa-only-personal+captive-portal', 'wpa2-only-personal+captive-portal', 'osen',
                        'wpa3-enterprise', 'sae', 'sae-transition', 'owe', 'wpa3-sae', 'wpa3-sae-transition', 'wpa3-only-enterprise',
                        'wpa3-enterprise-transition'
                    ],
                    'type': 'str'
                },
                'security-exempt-list': {'type': 'str'},
                'security-obsolete-option': {'choices': ['disable', 'enable'], 'type': 'str'},
                'security-redirect-url': {'type': 'str'},
                'selected-usergroups': {'type': 'raw'},
                'split-tunneling': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssid': {'type': 'str'},
                'tkip-counter-measure': {'choices': ['disable', 'enable'], 'type': 'str'},
                'usergroup': {'type': 'raw'},
                'utm-profile': {'type': 'str'},
                'vdom': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'vlan-auto': {'choices': ['disable', 'enable'], 'type': 'str'},
                'vlan-pool': {
                    'type': 'list',
                    'options': {'_wtp-group': {'type': 'str'}, 'id': {'type': 'int'}, 'wtp-group': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'vlan-pooling': {'choices': ['wtp-group', 'round-robin', 'hash', 'disable'], 'type': 'str'},
                'vlanid': {'type': 'int'},
                'voice-enterprise': {'choices': ['disable', 'enable'], 'type': 'str'},
                'address-group': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'atf-weight': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'mu-mimo': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'owe-groups': {'v_range': [['6.2.0', '']], 'type': 'list', 'choices': ['19', '20', '21'], 'elements': 'str'},
                'owe-transition': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'owe-transition-ssid': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'sae-groups': {
                    'v_range': [['6.2.0', '']],
                    'type': 'list',
                    'choices': ['1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '27', '28', '29', '30', '31'],
                    'elements': 'str'
                },
                'sae-password': {'v_range': [['6.2.0', '']], 'no_log': True, 'type': 'raw'},
                '_intf_device-access-list': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'external-web-format': {'v_range': [['6.2.2', '']], 'choices': ['auto-detect', 'no-query-string', 'partial-query-string'], 'type': 'str'},
                'high-efficiency': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'primary-wag-profile': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'secondary-wag-profile': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'target-wake-time': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-echo-interval': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'tunnel-fallback-interval': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'access-control-list': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'captive-portal-auth-timeout': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'ipv6-rules': {
                    'v_range': [['6.4.0', '']],
                    'type': 'list',
                    'choices': [
                        'drop-icmp6ra', 'drop-icmp6rs', 'drop-llmnr6', 'drop-icmp6mld2', 'drop-dhcp6s', 'drop-dhcp6c', 'ndp-proxy', 'drop-ns-dad',
                        'drop-ns-nondad'
                    ],
                    'elements': 'str'
                },
                'sticky-client-remove': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sticky-client-threshold-2g': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'sticky-client-threshold-5g': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'bss-color-partial': {'v_range': [['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-option43-insertion': {'v_range': [['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mpsk-profile': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'igmp-snooping': {'v_range': [['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'port-macauth': {'v_range': [['6.2.8', '6.2.12'], ['6.4.3', '']], 'choices': ['disable', 'radius', 'address-group'], 'type': 'str'},
                'port-macauth-reauth-timeout': {'v_range': [['6.2.8', '6.2.12'], ['6.4.3', '']], 'type': 'int'},
                'port-macauth-timeout': {'v_range': [['6.2.8', '6.2.12'], ['6.4.3', '']], 'type': 'int'},
                'portal-message-overrides': {
                    'type': 'dict',
                    'options': {
                        'auth-disclaimer-page': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                        'auth-login-failed-page': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                        'auth-login-page': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                        'auth-reject-page': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'}
                    }
                },
                'additional-akms': {'v_range': [['7.0.0', '']], 'type': 'list', 'choices': ['akm6'], 'elements': 'str'},
                'bstm-disassociation-imminent': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bstm-load-balancing-disassoc-timer': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'bstm-rssi-disassoc-timer': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'dhcp-address-enforcement': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gas-comeback-delay': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'gas-fragmentation-limit': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'mac-called-station-delimiter': {'v_range': [['7.0.0', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mac-calling-station-delimiter': {'v_range': [['7.0.0', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mac-case': {'v_range': [['7.0.0', '']], 'choices': ['uppercase', 'lowercase'], 'type': 'str'},
                'mac-password-delimiter': {'v_range': [['7.0.0', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mac-username-delimiter': {'v_range': [['7.0.0', '']], 'choices': ['hyphen', 'single-hyphen', 'colon', 'none'], 'type': 'str'},
                'mbo': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mbo-cell-data-conn-pref': {'v_range': [['7.0.0', '']], 'choices': ['excluded', 'prefer-not', 'prefer-use'], 'type': 'str'},
                'nac': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nac-profile': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'neighbor-report-dual-band': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'address-group-policy': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'allow', 'deny'], 'type': 'str'},
                'antivirus-profile': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'application-detection-engine': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'application-list': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'application-report-intv': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'auth-cert': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'auth-portal-addr': {'v_range': [['7.0.3', '']], 'type': 'str'},
                'beacon-advertising': {'v_range': [['7.0.2', '']], 'type': 'list', 'choices': ['name', 'model', 'serial-number'], 'elements': 'str'},
                'ips-sensor': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'l3-roaming': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-standalone-dns': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-standalone-dns-ip': {'v_range': [['7.0.1', '']], 'type': 'raw'},
                'osen': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-mpsk-auth': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-mpsk-timeout': {'v_range': [['7.0.2', '']], 'type': 'int'},
                'rates-11ax-ss12': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'choices': [
                        'mcs0/1', 'mcs1/1', 'mcs2/1', 'mcs3/1', 'mcs4/1', 'mcs5/1', 'mcs6/1', 'mcs7/1', 'mcs8/1', 'mcs9/1', 'mcs10/1', 'mcs11/1',
                        'mcs0/2', 'mcs1/2', 'mcs2/2', 'mcs3/2', 'mcs4/2', 'mcs5/2', 'mcs6/2', 'mcs7/2', 'mcs8/2', 'mcs9/2', 'mcs10/2', 'mcs11/2'
                    ],
                    'elements': 'str'
                },
                'rates-11ax-ss34': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'choices': [
                        'mcs0/3', 'mcs1/3', 'mcs2/3', 'mcs3/3', 'mcs4/3', 'mcs5/3', 'mcs6/3', 'mcs7/3', 'mcs8/3', 'mcs9/3', 'mcs10/3', 'mcs11/3',
                        'mcs0/4', 'mcs1/4', 'mcs2/4', 'mcs3/4', 'mcs4/4', 'mcs5/4', 'mcs6/4', 'mcs7/4', 'mcs8/4', 'mcs9/4', 'mcs10/4', 'mcs11/4'
                    ],
                    'elements': 'str'
                },
                'scan-botnet-connections': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'utm-log': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'utm-status': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vlan-name': {
                    'v_range': [['7.0.3', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['7.0.3', '']], 'type': 'str'}, 'vlan-id': {'v_range': [['7.0.3', '']], 'type': 'int'}},
                    'elements': 'dict'
                },
                'webfilter-profile': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'sae-h2e-only': {'v_range': [['7.0.5', '7.0.12'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sae-pk': {'v_range': [['7.0.5', '7.0.12'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sae-private-key': {'v_range': [['7.0.5', '7.0.12'], ['7.2.1', '']], 'no_log': True, 'type': 'str'},
                'sticky-client-threshold-6g': {'v_range': [['7.0.5', '7.0.12'], ['7.2.1', '']], 'type': 'str'},
                'application-dscp-marking': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'l3-roaming-mode': {'v_range': [['7.2.1', '']], 'choices': ['direct', 'indirect'], 'type': 'str'},
                'rates-11ac-mcs-map': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'rates-11ax-mcs-map': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'captive-portal-fw-accounting': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-mac-auth-block-interval': {'v_range': [['7.2.2', '']], 'type': 'int'},
                '_is_factory_setting': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable', 'ext'], 'type': 'str'},
                '80211k': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '80211v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'roaming-acct-interim-update': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sae-hnp-only': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vap'),
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
