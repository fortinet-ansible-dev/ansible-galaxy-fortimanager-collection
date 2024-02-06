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
module: fmgr_vpnsslweb_portal
short_description: Portal.
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
    vpnsslweb_portal:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allow-user-access:
                type: list
                elements: str
                description: Deprecated, please rename it to allow_user_access. Allow user access to SSL-VPN applications.
                choices:
                    - 'web'
                    - 'ftp'
                    - 'telnet'
                    - 'smb'
                    - 'vnc'
                    - 'rdp'
                    - 'ssh'
                    - 'ping'
                    - 'citrix'
                    - 'portforward'
                    - 'sftp'
            auto-connect:
                type: str
                description: Deprecated, please rename it to auto_connect. Enable/disable automatic connect by client when system is up.
                choices:
                    - 'disable'
                    - 'enable'
            bookmark-group:
                type: list
                elements: dict
                description: Deprecated, please rename it to bookmark_group. Bookmark-Group.
                suboptions:
                    bookmarks:
                        type: list
                        elements: dict
                        description: Bookmarks.
                        suboptions:
                            additional-params:
                                type: str
                                description: Deprecated, please rename it to additional_params. Additional parameters.
                            apptype:
                                type: str
                                description: Application type.
                                choices:
                                    - 'web'
                                    - 'telnet'
                                    - 'ssh'
                                    - 'ftp'
                                    - 'smb'
                                    - 'vnc'
                                    - 'rdp'
                                    - 'citrix'
                                    - 'rdpnative'
                                    - 'portforward'
                                    - 'sftp'
                            description:
                                type: str
                                description: Description.
                            folder:
                                type: str
                                description: Network shared file folder parameter.
                            form-data:
                                type: list
                                elements: dict
                                description: Deprecated, please rename it to form_data. Form-Data.
                                suboptions:
                                    name:
                                        type: str
                                        description: Name.
                                    value:
                                        type: str
                                        description: Value.
                            host:
                                type: str
                                description: Host name/IP parameter.
                            listening-port:
                                type: int
                                description: Deprecated, please rename it to listening_port. Listening port
                            load-balancing-info:
                                type: str
                                description: Deprecated, please rename it to load_balancing_info. The load balancing information or cookie which should...
                            logon-password:
                                type: raw
                                description: (list) Deprecated, please rename it to logon_password. Logon password.
                            logon-user:
                                type: str
                                description: Deprecated, please rename it to logon_user. Logon user.
                            name:
                                type: str
                                description: Bookmark name.
                            port:
                                type: int
                                description: Remote port.
                            preconnection-blob:
                                type: str
                                description: Deprecated, please rename it to preconnection_blob. An arbitrary string which identifies the RDP source.
                            preconnection-id:
                                type: int
                                description: Deprecated, please rename it to preconnection_id. The numeric ID of the RDP source
                            remote-port:
                                type: int
                                description: Deprecated, please rename it to remote_port. Remote port
                            security:
                                type: str
                                description: Security mode for RDP connection.
                                choices:
                                    - 'rdp'
                                    - 'nla'
                                    - 'tls'
                                    - 'any'
                            server-layout:
                                type: str
                                description: Deprecated, please rename it to server_layout. Server side keyboard layout.
                                choices:
                                    - 'en-us-qwerty'
                                    - 'de-de-qwertz'
                                    - 'fr-fr-azerty'
                                    - 'it-it-qwerty'
                                    - 'sv-se-qwerty'
                                    - 'failsafe'
                                    - 'en-gb-qwerty'
                                    - 'es-es-qwerty'
                                    - 'fr-ch-qwertz'
                                    - 'ja-jp-qwerty'
                                    - 'pt-br-qwerty'
                                    - 'tr-tr-qwerty'
                                    - 'fr-ca-qwerty'
                            show-status-window:
                                type: str
                                description: Deprecated, please rename it to show_status_window. Enable/disable showing of status window.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sso:
                                type: str
                                description: Single Sign-On.
                                choices:
                                    - 'disable'
                                    - 'static'
                                    - 'auto'
                            sso-credential:
                                type: str
                                description: Deprecated, please rename it to sso_credential. Single sign-on credentials.
                                choices:
                                    - 'sslvpn-login'
                                    - 'alternative'
                            sso-credential-sent-once:
                                type: str
                                description: Deprecated, please rename it to sso_credential_sent_once. Single sign-on credentials are only sent once to...
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sso-password:
                                type: raw
                                description: (list) Deprecated, please rename it to sso_password. SSO password.
                            sso-username:
                                type: str
                                description: Deprecated, please rename it to sso_username. SSO user name.
                            url:
                                type: str
                                description: URL parameter.
                            domain:
                                type: str
                                description: Login domain.
                            color-depth:
                                type: str
                                description: Deprecated, please rename it to color_depth. Color depth per pixel.
                                choices:
                                    - '8'
                                    - '16'
                                    - '32'
                            height:
                                type: int
                                description: Screen height
                            keyboard-layout:
                                type: str
                                description: Deprecated, please rename it to keyboard_layout. Keyboard layout.
                                choices:
                                    - 'ar'
                                    - 'da'
                                    - 'de'
                                    - 'de-ch'
                                    - 'en-gb'
                                    - 'en-uk'
                                    - 'en-us'
                                    - 'es'
                                    - 'fi'
                                    - 'fr'
                                    - 'fr-be'
                                    - 'fr-ca'
                                    - 'fr-ch'
                                    - 'hr'
                                    - 'hu'
                                    - 'it'
                                    - 'ja'
                                    - 'lt'
                                    - 'lv'
                                    - 'mk'
                                    - 'no'
                                    - 'pl'
                                    - 'pt'
                                    - 'pt-br'
                                    - 'ru'
                                    - 'sl'
                                    - 'sv'
                                    - 'tk'
                                    - 'tr'
                                    - 'fr-ca-m'
                                    - 'wg'
                                    - 'ar-101'
                                    - 'ar-102'
                                    - 'ar-102-azerty'
                                    - 'can-mul'
                                    - 'cz'
                                    - 'cz-qwerty'
                                    - 'cz-pr'
                                    - 'nl'
                                    - 'de-ibm'
                                    - 'en-uk-ext'
                                    - 'en-us-dvorak'
                                    - 'es-var'
                                    - 'fi-sami'
                                    - 'hu-101'
                                    - 'it-142'
                                    - 'ko'
                                    - 'lt-ibm'
                                    - 'lt-std'
                                    - 'lav-std'
                                    - 'lav-leg'
                                    - 'mk-std'
                                    - 'no-sami'
                                    - 'pol-214'
                                    - 'pol-pr'
                                    - 'pt-br-abnt2'
                                    - 'ru-mne'
                                    - 'ru-t'
                                    - 'sv-sami'
                                    - 'tuk'
                                    - 'tur-f'
                                    - 'tur-q'
                                    - 'zh-sym-sg-us'
                                    - 'zh-sym-us'
                                    - 'zh-tr-hk'
                                    - 'zh-tr-mo'
                                    - 'zh-tr-us'
                                    - 'fr-apple'
                                    - 'la-am'
                                    - 'ja-106'
                            restricted-admin:
                                type: str
                                description: Deprecated, please rename it to restricted_admin. Enable/disable restricted admin mode for RDP.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            send-preconnection-id:
                                type: str
                                description: Deprecated, please rename it to send_preconnection_id. Enable/disable sending of preconnection ID.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            width:
                                type: int
                                description: Screen width
                            vnc-keyboard-layout:
                                type: str
                                description: Deprecated, please rename it to vnc_keyboard_layout. Keyboard layout.
                                choices:
                                    - 'da'
                                    - 'de'
                                    - 'de-ch'
                                    - 'en-uk'
                                    - 'es'
                                    - 'fi'
                                    - 'fr'
                                    - 'fr-be'
                                    - 'it'
                                    - 'no'
                                    - 'pt'
                                    - 'sv'
                                    - 'nl'
                                    - 'en-uk-ext'
                                    - 'it-142'
                                    - 'pt-br-abnt2'
                                    - 'default'
                                    - 'fr-ca-mul'
                                    - 'gd'
                                    - 'us-intl'
                    name:
                        type: str
                        description: Bookmark group name.
            custom-lang:
                type: str
                description: Deprecated, please rename it to custom_lang. Change the web portal display language.
            customize-forticlient-download-url:
                type: str
                description: Deprecated, please rename it to customize_forticlient_download_url. Enable support of customized download URL for FortiClient.
                choices:
                    - 'disable'
                    - 'enable'
            display-bookmark:
                type: str
                description: Deprecated, please rename it to display_bookmark. Enable to display the web portal bookmark widget.
                choices:
                    - 'disable'
                    - 'enable'
            display-connection-tools:
                type: str
                description: Deprecated, please rename it to display_connection_tools. Enable to display the web portal connection tools widget.
                choices:
                    - 'disable'
                    - 'enable'
            display-history:
                type: str
                description: Deprecated, please rename it to display_history. Enable to display the web portal user login history widget.
                choices:
                    - 'disable'
                    - 'enable'
            display-status:
                type: str
                description: Deprecated, please rename it to display_status. Enable to display the web portal status widget.
                choices:
                    - 'disable'
                    - 'enable'
            dns-server1:
                type: str
                description: Deprecated, please rename it to dns_server1. IPv4 DNS server 1.
            dns-server2:
                type: str
                description: Deprecated, please rename it to dns_server2. IPv4 DNS server 2.
            dns-suffix:
                type: str
                description: Deprecated, please rename it to dns_suffix. DNS suffix.
            exclusive-routing:
                type: str
                description: Deprecated, please rename it to exclusive_routing. Enable/disable all traffic go through tunnel only.
                choices:
                    - 'disable'
                    - 'enable'
            forticlient-download:
                type: str
                description: Deprecated, please rename it to forticlient_download. Enable/disable download option for FortiClient.
                choices:
                    - 'disable'
                    - 'enable'
            forticlient-download-method:
                type: str
                description: Deprecated, please rename it to forticlient_download_method. FortiClient download method.
                choices:
                    - 'direct'
                    - 'ssl-vpn'
            heading:
                type: str
                description: Web portal heading message.
            hide-sso-credential:
                type: str
                description: Deprecated, please rename it to hide_sso_credential. Enable to prevent SSO credential being sent to client.
                choices:
                    - 'disable'
                    - 'enable'
            host-check:
                type: str
                description: Deprecated, please rename it to host_check. Type of host checking performed on endpoints.
                choices:
                    - 'none'
                    - 'av'
                    - 'fw'
                    - 'av-fw'
                    - 'custom'
            host-check-interval:
                type: int
                description: Deprecated, please rename it to host_check_interval. Periodic host check interval.
            host-check-policy:
                type: raw
                description: (list or str) Deprecated, please rename it to host_check_policy. One or more policies to require the endpoint to have spec...
            ip-mode:
                type: str
                description: Deprecated, please rename it to ip_mode. Method by which users of this SSL-VPN tunnel obtain IP addresses.
                choices:
                    - 'range'
                    - 'user-group'
                    - 'dhcp'
                    - 'no-ip'
            ip-pools:
                type: raw
                description: (list or str) Deprecated, please rename it to ip_pools. IPv4 firewall source address objects reserved for SSL-VPN tunnel m...
            ipv6-dns-server1:
                type: str
                description: Deprecated, please rename it to ipv6_dns_server1. IPv6 DNS server 1.
            ipv6-dns-server2:
                type: str
                description: Deprecated, please rename it to ipv6_dns_server2. IPv6 DNS server 2.
            ipv6-exclusive-routing:
                type: str
                description: Deprecated, please rename it to ipv6_exclusive_routing. Enable/disable all IPv6 traffic go through tunnel only.
                choices:
                    - 'disable'
                    - 'enable'
            ipv6-pools:
                type: raw
                description: (list or str) Deprecated, please rename it to ipv6_pools. IPv4 firewall source address objects reserved for SSL-VPN tunnel...
            ipv6-service-restriction:
                type: str
                description: Deprecated, please rename it to ipv6_service_restriction. Enable/disable IPv6 tunnel service restriction.
                choices:
                    - 'disable'
                    - 'enable'
            ipv6-split-tunneling:
                type: str
                description: Deprecated, please rename it to ipv6_split_tunneling. Enable/disable IPv6 split tunneling.
                choices:
                    - 'disable'
                    - 'enable'
            ipv6-split-tunneling-routing-address:
                type: raw
                description: (list or str) Deprecated, please rename it to ipv6_split_tunneling_routing_address. IPv6 SSL-VPN tunnel mode firewall addr...
            ipv6-tunnel-mode:
                type: str
                description: Deprecated, please rename it to ipv6_tunnel_mode. Enable/disable IPv6 SSL-VPN tunnel mode.
                choices:
                    - 'disable'
                    - 'enable'
            ipv6-wins-server1:
                type: str
                description: Deprecated, please rename it to ipv6_wins_server1. IPv6 WINS server 1.
            ipv6-wins-server2:
                type: str
                description: Deprecated, please rename it to ipv6_wins_server2. IPv6 WINS server 2.
            keep-alive:
                type: str
                description: Deprecated, please rename it to keep_alive. Enable/disable automatic reconnect for FortiClient connections.
                choices:
                    - 'disable'
                    - 'enable'
            limit-user-logins:
                type: str
                description: Deprecated, please rename it to limit_user_logins. Enable to limit each user to one SSL-VPN session at a time.
                choices:
                    - 'disable'
                    - 'enable'
            mac-addr-action:
                type: str
                description: Deprecated, please rename it to mac_addr_action. Client MAC address action.
                choices:
                    - 'deny'
                    - 'allow'
            mac-addr-check:
                type: str
                description: Deprecated, please rename it to mac_addr_check. Enable/disable MAC address host checking.
                choices:
                    - 'disable'
                    - 'enable'
            mac-addr-check-rule:
                type: list
                elements: dict
                description: Deprecated, please rename it to mac_addr_check_rule. Mac-Addr-Check-Rule.
                suboptions:
                    mac-addr-list:
                        type: raw
                        description: (list) Deprecated, please rename it to mac_addr_list. Client MAC address list.
                    mac-addr-mask:
                        type: int
                        description: Deprecated, please rename it to mac_addr_mask. Client MAC address mask.
                    name:
                        type: str
                        description: Client MAC address check rule name.
            macos-forticlient-download-url:
                type: str
                description: Deprecated, please rename it to macos_forticlient_download_url. Download URL for Mac FortiClient.
            name:
                type: str
                description: Portal name.
                required: true
            os-check:
                type: str
                description: Deprecated, please rename it to os_check. Enable to let the FortiGate decide action based on client OS.
                choices:
                    - 'disable'
                    - 'enable'
            redir-url:
                type: str
                description: Deprecated, please rename it to redir_url. Client login redirect URL.
            save-password:
                type: str
                description: Deprecated, please rename it to save_password. Enable/disable FortiClient saving the users password.
                choices:
                    - 'disable'
                    - 'enable'
            service-restriction:
                type: str
                description: Deprecated, please rename it to service_restriction. Enable/disable tunnel service restriction.
                choices:
                    - 'disable'
                    - 'enable'
            skip-check-for-unsupported-browser:
                type: str
                description: Deprecated, please rename it to skip_check_for_unsupported_browser. Enable to skip host check if browser does not support it.
                choices:
                    - 'disable'
                    - 'enable'
            skip-check-for-unsupported-os:
                type: str
                description: Deprecated, please rename it to skip_check_for_unsupported_os. Enable to skip host check if client OS does not support it.
                choices:
                    - 'disable'
                    - 'enable'
            smb-ntlmv1-auth:
                type: str
                description: Deprecated, please rename it to smb_ntlmv1_auth. Enable support of NTLMv1 for Samba authentication.
                choices:
                    - 'disable'
                    - 'enable'
            smbv1:
                type: str
                description: Enable/disable support of SMBv1 for Samba.
                choices:
                    - 'disable'
                    - 'enable'
            split-dns:
                type: list
                elements: dict
                description: Deprecated, please rename it to split_dns. Split-Dns.
                suboptions:
                    dns-server1:
                        type: str
                        description: Deprecated, please rename it to dns_server1. DNS server 1.
                    dns-server2:
                        type: str
                        description: Deprecated, please rename it to dns_server2. DNS server 2.
                    domains:
                        type: str
                        description: Split DNS domains used for SSL-VPN clients separated by comma
                    id:
                        type: int
                        description: ID.
                    ipv6-dns-server1:
                        type: str
                        description: Deprecated, please rename it to ipv6_dns_server1. IPv6 DNS server 1.
                    ipv6-dns-server2:
                        type: str
                        description: Deprecated, please rename it to ipv6_dns_server2. IPv6 DNS server 2.
            split-tunneling:
                type: str
                description: Deprecated, please rename it to split_tunneling. Enable/disable IPv4 split tunneling.
                choices:
                    - 'disable'
                    - 'enable'
            split-tunneling-routing-address:
                type: raw
                description: (list or str) Deprecated, please rename it to split_tunneling_routing_address. IPv4 SSL-VPN tunnel mode firewall address o...
            theme:
                type: str
                description: Web portal color scheme.
                choices:
                    - 'gray'
                    - 'blue'
                    - 'orange'
                    - 'crimson'
                    - 'steelblue'
                    - 'darkgrey'
                    - 'green'
                    - 'melongene'
                    - 'red'
                    - 'mariner'
                    - 'neutrino'
                    - 'jade'
                    - 'graphite'
                    - 'dark-matter'
                    - 'onyx'
                    - 'eclipse'
                    - 'jet-stream'
                    - 'security-fabric'
            tunnel-mode:
                type: str
                description: Deprecated, please rename it to tunnel_mode. Enable/disable IPv4 SSL-VPN tunnel mode.
                choices:
                    - 'disable'
                    - 'enable'
            user-bookmark:
                type: str
                description: Deprecated, please rename it to user_bookmark. Enable to allow web portal users to create their own bookmarks.
                choices:
                    - 'disable'
                    - 'enable'
            user-group-bookmark:
                type: str
                description: Deprecated, please rename it to user_group_bookmark. Enable to allow web portal users to create bookmarks for all users in...
                choices:
                    - 'disable'
                    - 'enable'
            web-mode:
                type: str
                description: Deprecated, please rename it to web_mode. Enable/disable SSL VPN web mode.
                choices:
                    - 'disable'
                    - 'enable'
            windows-forticlient-download-url:
                type: str
                description: Deprecated, please rename it to windows_forticlient_download_url. Download URL for Windows FortiClient.
            wins-server1:
                type: str
                description: Deprecated, please rename it to wins_server1. IPv4 WINS server 1.
            wins-server2:
                type: str
                description: Deprecated, please rename it to wins_server2. IPv4 WINS server 1.
            skip-check-for-browser:
                type: str
                description: Deprecated, please rename it to skip_check_for_browser. Enable to skip host check for browser support.
                choices:
                    - 'disable'
                    - 'enable'
            smb-max-version:
                type: str
                description: Deprecated, please rename it to smb_max_version. SMB maximum client protocol version.
                choices:
                    - 'smbv1'
                    - 'smbv2'
                    - 'smbv3'
            smb-min-version:
                type: str
                description: Deprecated, please rename it to smb_min_version. SMB minimum client protocol version.
                choices:
                    - 'smbv1'
                    - 'smbv2'
                    - 'smbv3'
            virtual-desktop-logout-when-browser-close:
                type: str
                description: Deprecated, please rename it to virtual_desktop_logout_when_browser_close. Enable/disable logout when browser is close in ...
                choices:
                    - 'disable'
                    - 'enable'
            virtual-desktop-clipboard-share:
                type: str
                description: Deprecated, please rename it to virtual_desktop_clipboard_share. Enable/disable sharing of clipboard in virtual desktop.
                choices:
                    - 'disable'
                    - 'enable'
            virtual-desktop-desktop-switch:
                type: str
                description: Deprecated, please rename it to virtual_desktop_desktop_switch. Enable/disable switch to virtual desktop.
                choices:
                    - 'disable'
                    - 'enable'
            virtual-desktop:
                type: str
                description: Deprecated, please rename it to virtual_desktop. Enable/disable SSL VPN virtual desktop.
                choices:
                    - 'disable'
                    - 'enable'
            virtual-desktop-network-share-access:
                type: str
                description: Deprecated, please rename it to virtual_desktop_network_share_access. Enable/disable network share access in virtual desktop.
                choices:
                    - 'disable'
                    - 'enable'
            virtual-desktop-printing:
                type: str
                description: Deprecated, please rename it to virtual_desktop_printing. Enable/disable printing in virtual desktop.
                choices:
                    - 'disable'
                    - 'enable'
            virtual-desktop-app-list:
                type: str
                description: Deprecated, please rename it to virtual_desktop_app_list. Virtual desktop application list.
            virtual-desktop-removable-media-access:
                type: str
                description: Deprecated, please rename it to virtual_desktop_removable_media_access. Enable/disable access to removable media in virtua...
                choices:
                    - 'disable'
                    - 'enable'
            transform-backward-slashes:
                type: str
                description: Deprecated, please rename it to transform_backward_slashes. Transform backward slashes to forward slashes in URLs.
                choices:
                    - 'disable'
                    - 'enable'
            ipv6-split-tunneling-routing-negate:
                type: str
                description: Deprecated, please rename it to ipv6_split_tunneling_routing_negate. Enable to negate IPv6 split tunneling routing address.
                choices:
                    - 'disable'
                    - 'enable'
            split-tunneling-routing-negate:
                type: str
                description: Deprecated, please rename it to split_tunneling_routing_negate. Enable to negate split tunneling routing address.
                choices:
                    - 'disable'
                    - 'enable'
            os-check-list:
                type: dict
                description: Deprecated, please rename it to os_check_list.
                suboptions:
                    action:
                        type: str
                        description: OS check options.
                        choices:
                            - 'allow'
                            - 'check-up-to-date'
                            - 'deny'
                    latest-patch-level:
                        type: str
                        description: Deprecated, please rename it to latest_patch_level. Latest OS patch level.
                    name:
                        type: str
                        description: Name.
                    tolerance:
                        type: int
                        description: OS patch level tolerance.
            use-sdwan:
                type: str
                description: Deprecated, please rename it to use_sdwan. Use SD-WAN rules to get output interface.
                choices:
                    - 'disable'
                    - 'enable'
            prefer-ipv6-dns:
                type: str
                description: Deprecated, please rename it to prefer_ipv6_dns. Prefer to query IPv6 dns first if enabled.
                choices:
                    - 'disable'
                    - 'enable'
            rewrite-ip-uri-ui:
                type: str
                description: Deprecated, please rename it to rewrite_ip_uri_ui. Rewrite contents for URI contains IP and /ui/.
                choices:
                    - 'disable'
                    - 'enable'
            clipboard:
                type: str
                description: Enable to support RDP/VPC clipboard functionality.
                choices:
                    - 'disable'
                    - 'enable'
            default-window-height:
                type: int
                description: Deprecated, please rename it to default_window_height. Screen height
            default-window-width:
                type: int
                description: Deprecated, please rename it to default_window_width. Screen width
            dhcp-ip-overlap:
                type: str
                description: Deprecated, please rename it to dhcp_ip_overlap. Configure overlapping DHCP IP allocation assignment.
                choices:
                    - 'use-old'
                    - 'use-new'
            client-src-range:
                type: str
                description: Deprecated, please rename it to client_src_range. Allow client to add source range for the tunnel traffic.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp-ra-giaddr:
                type: str
                description: Deprecated, please rename it to dhcp_ra_giaddr. Relay agent gateway IP address to use in the giaddr field of DHCP requests.
            dhcp6-ra-linkaddr:
                type: str
                description: Deprecated, please rename it to dhcp6_ra_linkaddr. Relay agent IPv6 link address to use in DHCP6 requests.
            landing-page:
                type: dict
                description: Deprecated, please rename it to landing_page.
                suboptions:
                    form-data:
                        type: list
                        elements: dict
                        description: Deprecated, please rename it to form_data.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            value:
                                type: str
                                description: Value.
                    logout-url:
                        type: str
                        description: Deprecated, please rename it to logout_url. Landing page log out URL.
                    sso:
                        type: str
                        description: Single sign-on.
                        choices:
                            - 'disable'
                            - 'static'
                            - 'auto'
                    sso-credential:
                        type: str
                        description: Deprecated, please rename it to sso_credential. Single sign-on credentials.
                        choices:
                            - 'sslvpn-login'
                            - 'alternative'
                    sso-password:
                        type: raw
                        description: (list) Deprecated, please rename it to sso_password.
                    sso-username:
                        type: str
                        description: Deprecated, please rename it to sso_username. SSO user name.
                    url:
                        type: str
                        description: Landing page URL.
            landing-page-mode:
                type: str
                description: Deprecated, please rename it to landing_page_mode. Enable/disable SSL-VPN landing page mode.
                choices:
                    - 'disable'
                    - 'enable'
            default-protocol:
                type: str
                description: Deprecated, please rename it to default_protocol. Application type that is set by default.
                choices:
                    - 'web'
                    - 'ftp'
                    - 'telnet'
                    - 'smb'
                    - 'vnc'
                    - 'rdp'
                    - 'ssh'
                    - 'sftp'
            focus-bookmark:
                type: str
                description: Deprecated, please rename it to focus_bookmark. Enable to prioritize the placement of the bookmark section over the quick-...
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
    - name: Portal.
      fortinet.fortimanager.fmgr_vpnsslweb_portal:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        vpnsslweb_portal:
          allow_user_access:
            - web
            - ftp
            - telnet
            - smb
            - vnc
            - rdp
            - ssh
            - ping
            - citrix
            - portforward
            - sftp
          auto_connect: <value in [disable, enable]>
          bookmark_group:
            -
              bookmarks:
                -
                  additional_params: <string>
                  apptype: <value in [web, telnet, ssh, ...]>
                  description: <string>
                  folder: <string>
                  form_data:
                    -
                      name: <string>
                      value: <string>
                  host: <string>
                  listening_port: <integer>
                  load_balancing_info: <string>
                  logon_password: <list or string>
                  logon_user: <string>
                  name: <string>
                  port: <integer>
                  preconnection_blob: <string>
                  preconnection_id: <integer>
                  remote_port: <integer>
                  security: <value in [rdp, nla, tls, ...]>
                  server_layout: <value in [en-us-qwerty, de-de-qwertz, fr-fr-azerty, ...]>
                  show_status_window: <value in [disable, enable]>
                  sso: <value in [disable, static, auto]>
                  sso_credential: <value in [sslvpn-login, alternative]>
                  sso_credential_sent_once: <value in [disable, enable]>
                  sso_password: <list or string>
                  sso_username: <string>
                  url: <string>
                  domain: <string>
                  color_depth: <value in [8, 16, 32]>
                  height: <integer>
                  keyboard_layout: <value in [ar, da, de, ...]>
                  restricted_admin: <value in [disable, enable]>
                  send_preconnection_id: <value in [disable, enable]>
                  width: <integer>
                  vnc_keyboard_layout: <value in [da, de, de-ch, ...]>
              name: <string>
          custom_lang: <string>
          customize_forticlient_download_url: <value in [disable, enable]>
          display_bookmark: <value in [disable, enable]>
          display_connection_tools: <value in [disable, enable]>
          display_history: <value in [disable, enable]>
          display_status: <value in [disable, enable]>
          dns_server1: <string>
          dns_server2: <string>
          dns_suffix: <string>
          exclusive_routing: <value in [disable, enable]>
          forticlient_download: <value in [disable, enable]>
          forticlient_download_method: <value in [direct, ssl-vpn]>
          heading: <string>
          hide_sso_credential: <value in [disable, enable]>
          host_check: <value in [none, av, fw, ...]>
          host_check_interval: <integer>
          host_check_policy: <list or string>
          ip_mode: <value in [range, user-group, dhcp, ...]>
          ip_pools: <list or string>
          ipv6_dns_server1: <string>
          ipv6_dns_server2: <string>
          ipv6_exclusive_routing: <value in [disable, enable]>
          ipv6_pools: <list or string>
          ipv6_service_restriction: <value in [disable, enable]>
          ipv6_split_tunneling: <value in [disable, enable]>
          ipv6_split_tunneling_routing_address: <list or string>
          ipv6_tunnel_mode: <value in [disable, enable]>
          ipv6_wins_server1: <string>
          ipv6_wins_server2: <string>
          keep_alive: <value in [disable, enable]>
          limit_user_logins: <value in [disable, enable]>
          mac_addr_action: <value in [deny, allow]>
          mac_addr_check: <value in [disable, enable]>
          mac_addr_check_rule:
            -
              mac_addr_list: <list or string>
              mac_addr_mask: <integer>
              name: <string>
          macos_forticlient_download_url: <string>
          name: <string>
          os_check: <value in [disable, enable]>
          redir_url: <string>
          save_password: <value in [disable, enable]>
          service_restriction: <value in [disable, enable]>
          skip_check_for_unsupported_browser: <value in [disable, enable]>
          skip_check_for_unsupported_os: <value in [disable, enable]>
          smb_ntlmv1_auth: <value in [disable, enable]>
          smbv1: <value in [disable, enable]>
          split_dns:
            -
              dns_server1: <string>
              dns_server2: <string>
              domains: <string>
              id: <integer>
              ipv6_dns_server1: <string>
              ipv6_dns_server2: <string>
          split_tunneling: <value in [disable, enable]>
          split_tunneling_routing_address: <list or string>
          theme: <value in [gray, blue, orange, ...]>
          tunnel_mode: <value in [disable, enable]>
          user_bookmark: <value in [disable, enable]>
          user_group_bookmark: <value in [disable, enable]>
          web_mode: <value in [disable, enable]>
          windows_forticlient_download_url: <string>
          wins_server1: <string>
          wins_server2: <string>
          skip_check_for_browser: <value in [disable, enable]>
          smb_max_version: <value in [smbv1, smbv2, smbv3]>
          smb_min_version: <value in [smbv1, smbv2, smbv3]>
          virtual_desktop_logout_when_browser_close: <value in [disable, enable]>
          virtual_desktop_clipboard_share: <value in [disable, enable]>
          virtual_desktop_desktop_switch: <value in [disable, enable]>
          virtual_desktop: <value in [disable, enable]>
          virtual_desktop_network_share_access: <value in [disable, enable]>
          virtual_desktop_printing: <value in [disable, enable]>
          virtual_desktop_app_list: <string>
          virtual_desktop_removable_media_access: <value in [disable, enable]>
          transform_backward_slashes: <value in [disable, enable]>
          ipv6_split_tunneling_routing_negate: <value in [disable, enable]>
          split_tunneling_routing_negate: <value in [disable, enable]>
          os_check_list:
            action: <value in [allow, check-up-to-date, deny]>
            latest_patch_level: <string>
            name: <string>
            tolerance: <integer>
          use_sdwan: <value in [disable, enable]>
          prefer_ipv6_dns: <value in [disable, enable]>
          rewrite_ip_uri_ui: <value in [disable, enable]>
          clipboard: <value in [disable, enable]>
          default_window_height: <integer>
          default_window_width: <integer>
          dhcp_ip_overlap: <value in [use-old, use-new]>
          client_src_range: <value in [disable, enable]>
          dhcp_ra_giaddr: <string>
          dhcp6_ra_linkaddr: <string>
          landing_page:
            form_data:
              -
                name: <string>
                value: <string>
            logout_url: <string>
            sso: <value in [disable, static, auto]>
            sso_credential: <value in [sslvpn-login, alternative]>
            sso_password: <list or string>
            sso_username: <string>
            url: <string>
          landing_page_mode: <value in [disable, enable]>
          default_protocol: <value in [web, ftp, telnet, ...]>
          focus_bookmark: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal',
        '/pm/config/global/obj/vpn/ssl/web/portal'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}',
        '/pm/config/global/obj/vpn/ssl/web/portal/{portal}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vpnsslweb_portal': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'allow-user-access': {
                    'type': 'list',
                    'choices': ['web', 'ftp', 'telnet', 'smb', 'vnc', 'rdp', 'ssh', 'ping', 'citrix', 'portforward', 'sftp'],
                    'elements': 'str'
                },
                'auto-connect': {'choices': ['disable', 'enable'], 'type': 'str'},
                'bookmark-group': {
                    'type': 'list',
                    'options': {
                        'bookmarks': {
                            'type': 'list',
                            'options': {
                                'additional-params': {'type': 'str'},
                                'apptype': {
                                    'choices': ['web', 'telnet', 'ssh', 'ftp', 'smb', 'vnc', 'rdp', 'citrix', 'rdpnative', 'portforward', 'sftp'],
                                    'type': 'str'
                                },
                                'description': {'type': 'str'},
                                'folder': {'type': 'str'},
                                'form-data': {'type': 'list', 'options': {'name': {'type': 'str'}, 'value': {'type': 'str'}}, 'elements': 'dict'},
                                'host': {'type': 'str'},
                                'listening-port': {'type': 'int'},
                                'load-balancing-info': {'type': 'str'},
                                'logon-password': {'no_log': True, 'type': 'raw'},
                                'logon-user': {'type': 'str'},
                                'name': {'type': 'str'},
                                'port': {'type': 'int'},
                                'preconnection-blob': {'type': 'str'},
                                'preconnection-id': {'type': 'int'},
                                'remote-port': {'type': 'int'},
                                'security': {'choices': ['rdp', 'nla', 'tls', 'any'], 'type': 'str'},
                                'server-layout': {
                                    'choices': [
                                        'en-us-qwerty', 'de-de-qwertz', 'fr-fr-azerty', 'it-it-qwerty', 'sv-se-qwerty', 'failsafe', 'en-gb-qwerty',
                                        'es-es-qwerty', 'fr-ch-qwertz', 'ja-jp-qwerty', 'pt-br-qwerty', 'tr-tr-qwerty', 'fr-ca-qwerty'
                                    ],
                                    'type': 'str'
                                },
                                'show-status-window': {'choices': ['disable', 'enable'], 'type': 'str'},
                                'sso': {'choices': ['disable', 'static', 'auto'], 'type': 'str'},
                                'sso-credential': {'choices': ['sslvpn-login', 'alternative'], 'type': 'str'},
                                'sso-credential-sent-once': {'choices': ['disable', 'enable'], 'type': 'str'},
                                'sso-password': {'no_log': True, 'type': 'raw'},
                                'sso-username': {'type': 'str'},
                                'url': {'type': 'str'},
                                'domain': {'v_range': [['6.4.2', '']], 'type': 'str'},
                                'color-depth': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['8', '16', '32'], 'type': 'str'},
                                'height': {'v_range': [['7.0.3', '']], 'type': 'int'},
                                'keyboard-layout': {
                                    'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']],
                                    'choices': [
                                        'ar', 'da', 'de', 'de-ch', 'en-gb', 'en-uk', 'en-us', 'es', 'fi', 'fr', 'fr-be', 'fr-ca', 'fr-ch', 'hr', 'hu',
                                        'it', 'ja', 'lt', 'lv', 'mk', 'no', 'pl', 'pt', 'pt-br', 'ru', 'sl', 'sv', 'tk', 'tr', 'fr-ca-m', 'wg', 'ar-101',
                                        'ar-102', 'ar-102-azerty', 'can-mul', 'cz', 'cz-qwerty', 'cz-pr', 'nl', 'de-ibm', 'en-uk-ext', 'en-us-dvorak',
                                        'es-var', 'fi-sami', 'hu-101', 'it-142', 'ko', 'lt-ibm', 'lt-std', 'lav-std', 'lav-leg', 'mk-std', 'no-sami',
                                        'pol-214', 'pol-pr', 'pt-br-abnt2', 'ru-mne', 'ru-t', 'sv-sami', 'tuk', 'tur-f', 'tur-q', 'zh-sym-sg-us',
                                        'zh-sym-us', 'zh-tr-hk', 'zh-tr-mo', 'zh-tr-us', 'fr-apple', 'la-am', 'ja-106'
                                    ],
                                    'type': 'str'
                                },
                                'restricted-admin': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'send-preconnection-id': {
                                    'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']],
                                    'choices': ['disable', 'enable'],
                                    'type': 'str'
                                },
                                'width': {'v_range': [['7.0.3', '']], 'type': 'int'},
                                'vnc-keyboard-layout': {
                                    'v_range': [['7.2.2', '']],
                                    'choices': [
                                        'da', 'de', 'de-ch', 'en-uk', 'es', 'fi', 'fr', 'fr-be', 'it', 'no', 'pt', 'sv', 'nl', 'en-uk-ext', 'it-142',
                                        'pt-br-abnt2', 'default', 'fr-ca-mul', 'gd', 'us-intl'
                                    ],
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'name': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'custom-lang': {'type': 'str'},
                'customize-forticlient-download-url': {'choices': ['disable', 'enable'], 'type': 'str'},
                'display-bookmark': {'choices': ['disable', 'enable'], 'type': 'str'},
                'display-connection-tools': {'choices': ['disable', 'enable'], 'type': 'str'},
                'display-history': {'choices': ['disable', 'enable'], 'type': 'str'},
                'display-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dns-server1': {'type': 'str'},
                'dns-server2': {'type': 'str'},
                'dns-suffix': {'type': 'str'},
                'exclusive-routing': {'choices': ['disable', 'enable'], 'type': 'str'},
                'forticlient-download': {'choices': ['disable', 'enable'], 'type': 'str'},
                'forticlient-download-method': {'choices': ['direct', 'ssl-vpn'], 'type': 'str'},
                'heading': {'type': 'str'},
                'hide-sso-credential': {'choices': ['disable', 'enable'], 'type': 'str'},
                'host-check': {'choices': ['none', 'av', 'fw', 'av-fw', 'custom'], 'type': 'str'},
                'host-check-interval': {'type': 'int'},
                'host-check-policy': {'type': 'raw'},
                'ip-mode': {'choices': ['range', 'user-group', 'dhcp', 'no-ip'], 'type': 'str'},
                'ip-pools': {'type': 'raw'},
                'ipv6-dns-server1': {'type': 'str'},
                'ipv6-dns-server2': {'type': 'str'},
                'ipv6-exclusive-routing': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv6-pools': {'type': 'raw'},
                'ipv6-service-restriction': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv6-split-tunneling': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv6-split-tunneling-routing-address': {'type': 'raw'},
                'ipv6-tunnel-mode': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv6-wins-server1': {'type': 'str'},
                'ipv6-wins-server2': {'type': 'str'},
                'keep-alive': {'choices': ['disable', 'enable'], 'type': 'str'},
                'limit-user-logins': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-addr-action': {'choices': ['deny', 'allow'], 'type': 'str'},
                'mac-addr-check': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-addr-check-rule': {
                    'type': 'list',
                    'options': {'mac-addr-list': {'type': 'raw'}, 'mac-addr-mask': {'type': 'int'}, 'name': {'type': 'str'}},
                    'elements': 'dict'
                },
                'macos-forticlient-download-url': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'os-check': {'choices': ['disable', 'enable'], 'type': 'str'},
                'redir-url': {'type': 'str'},
                'save-password': {'choices': ['disable', 'enable'], 'type': 'str'},
                'service-restriction': {'choices': ['disable', 'enable'], 'type': 'str'},
                'skip-check-for-unsupported-browser': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'skip-check-for-unsupported-os': {'choices': ['disable', 'enable'], 'type': 'str'},
                'smb-ntlmv1-auth': {'choices': ['disable', 'enable'], 'type': 'str'},
                'smbv1': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'split-dns': {
                    'type': 'list',
                    'options': {
                        'dns-server1': {'type': 'str'},
                        'dns-server2': {'type': 'str'},
                        'domains': {'type': 'str'},
                        'id': {'type': 'int'},
                        'ipv6-dns-server1': {'type': 'str'},
                        'ipv6-dns-server2': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'split-tunneling': {'choices': ['disable', 'enable'], 'type': 'str'},
                'split-tunneling-routing-address': {'type': 'raw'},
                'theme': {
                    'choices': [
                        'gray', 'blue', 'orange', 'crimson', 'steelblue', 'darkgrey', 'green', 'melongene', 'red', 'mariner', 'neutrino', 'jade',
                        'graphite', 'dark-matter', 'onyx', 'eclipse', 'jet-stream', 'security-fabric'
                    ],
                    'type': 'str'
                },
                'tunnel-mode': {'choices': ['disable', 'enable'], 'type': 'str'},
                'user-bookmark': {'choices': ['disable', 'enable'], 'type': 'str'},
                'user-group-bookmark': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-mode': {'choices': ['disable', 'enable'], 'type': 'str'},
                'windows-forticlient-download-url': {'type': 'str'},
                'wins-server1': {'type': 'str'},
                'wins-server2': {'type': 'str'},
                'skip-check-for-browser': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'smb-max-version': {'v_range': [['6.2.0', '']], 'choices': ['smbv1', 'smbv2', 'smbv3'], 'type': 'str'},
                'smb-min-version': {'v_range': [['6.2.0', '']], 'choices': ['smbv1', 'smbv2', 'smbv3'], 'type': 'str'},
                'virtual-desktop-logout-when-browser-close': {'v_range': [['6.2.0', '6.2.12']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-desktop-clipboard-share': {'v_range': [['6.2.0', '6.2.12']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-desktop-desktop-switch': {'v_range': [['6.2.0', '6.2.12']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-desktop': {'v_range': [['6.2.0', '6.2.12']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-desktop-network-share-access': {'v_range': [['6.2.0', '6.2.12']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-desktop-printing': {'v_range': [['6.2.0', '6.2.12']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-desktop-app-list': {'v_range': [['6.2.0', '6.2.12']], 'type': 'str'},
                'virtual-desktop-removable-media-access': {'v_range': [['6.2.0', '6.2.12']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'transform-backward-slashes': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv6-split-tunneling-routing-negate': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'split-tunneling-routing-negate': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'os-check-list': {
                    'type': 'dict',
                    'options': {
                        'action': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'choices': ['allow', 'check-up-to-date', 'deny'], 'type': 'str'},
                        'latest-patch-level': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                        'name': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'str'},
                        'tolerance': {'v_range': [['6.2.8', '6.2.12'], ['6.4.5', '']], 'type': 'int'}
                    }
                },
                'use-sdwan': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'prefer-ipv6-dns': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rewrite-ip-uri-ui': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'clipboard': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'default-window-height': {'v_range': [['7.0.4', '']], 'type': 'int'},
                'default-window-width': {'v_range': [['7.0.4', '']], 'type': 'int'},
                'dhcp-ip-overlap': {'v_range': [['7.0.4', '7.0.10'], ['7.2.1', '']], 'choices': ['use-old', 'use-new'], 'type': 'str'},
                'client-src-range': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-ra-giaddr': {'v_range': [['7.2.2', '']], 'type': 'str'},
                'dhcp6-ra-linkaddr': {'v_range': [['7.2.2', '']], 'type': 'str'},
                'landing-page': {
                    'type': 'dict',
                    'options': {
                        'form-data': {
                            'v_range': [['7.4.0', '']],
                            'type': 'list',
                            'options': {'name': {'v_range': [['7.4.0', '']], 'type': 'str'}, 'value': {'v_range': [['7.4.0', '']], 'type': 'str'}},
                            'elements': 'dict'
                        },
                        'logout-url': {'v_range': [['7.4.0', '7.4.1']], 'type': 'str'},
                        'sso': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'static', 'auto'], 'type': 'str'},
                        'sso-credential': {'v_range': [['7.4.0', '']], 'choices': ['sslvpn-login', 'alternative'], 'type': 'str'},
                        'sso-password': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'raw'},
                        'sso-username': {'v_range': [['7.4.0', '']], 'type': 'str'},
                        'url': {'v_range': [['7.4.0', '']], 'type': 'str'}
                    }
                },
                'landing-page-mode': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'default-protocol': {'v_range': [['7.4.1', '']], 'choices': ['web', 'ftp', 'telnet', 'smb', 'vnc', 'rdp', 'ssh', 'sftp'], 'type': 'str'},
                'focus-bookmark': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_portal'),
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
