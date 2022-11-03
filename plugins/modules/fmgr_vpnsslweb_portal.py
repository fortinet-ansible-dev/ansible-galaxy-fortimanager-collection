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
module: fmgr_vpnsslweb_portal
short_description: no description
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
        description: |
          only set to True when module schema diffs with FortiManager API structure,
           module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: |
          the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
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
    vpnsslweb_portal:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            allow-user-access:
                description: no description
                type: list
                choices:
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
            auto-connect:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            bookmark-group:
                description: no description
                type: list
                suboptions:
                    bookmarks:
                        description: no description
                        type: list
                        suboptions:
                            additional-params:
                                type: str
                                description: no description
                            apptype:
                                type: str
                                description: no description
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
                                description: no description
                            folder:
                                type: str
                                description: no description
                            form-data:
                                description: no description
                                type: list
                                suboptions:
                                    name:
                                        type: str
                                        description: no description
                                    value:
                                        type: str
                                        description: no description
                            host:
                                type: str
                                description: no description
                            listening-port:
                                type: int
                                description: no description
                            load-balancing-info:
                                type: str
                                description: no description
                            logon-password:
                                description: no description
                                type: str
                            logon-user:
                                type: str
                                description: no description
                            name:
                                type: str
                                description: no description
                            port:
                                type: int
                                description: no description
                            preconnection-blob:
                                type: str
                                description: no description
                            preconnection-id:
                                type: int
                                description: no description
                            remote-port:
                                type: int
                                description: no description
                            security:
                                type: str
                                description: no description
                                choices:
                                    - 'rdp'
                                    - 'nla'
                                    - 'tls'
                                    - 'any'
                            server-layout:
                                type: str
                                description: no description
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
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sso:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'static'
                                    - 'auto'
                            sso-credential:
                                type: str
                                description: no description
                                choices:
                                    - 'sslvpn-login'
                                    - 'alternative'
                            sso-credential-sent-once:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sso-password:
                                description: no description
                                type: str
                            sso-username:
                                type: str
                                description: no description
                            url:
                                type: str
                                description: no description
                            domain:
                                type: str
                                description: no description
                            color-depth:
                                type: str
                                description: no description
                                choices:
                                    - '8'
                                    - '16'
                                    - '32'
                            height:
                                type: int
                                description: no description
                            keyboard-layout:
                                type: str
                                description: no description
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
                            restricted-admin:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            send-preconnection-id:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            width:
                                type: int
                                description: no description
                    name:
                        type: str
                        description: no description
            custom-lang:
                type: str
                description: no description
            customize-forticlient-download-url:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            display-bookmark:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            display-connection-tools:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            display-history:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            display-status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dns-server1:
                type: str
                description: no description
            dns-server2:
                type: str
                description: no description
            dns-suffix:
                type: str
                description: no description
            exclusive-routing:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            forticlient-download:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            forticlient-download-method:
                type: str
                description: no description
                choices:
                    - 'direct'
                    - 'ssl-vpn'
            heading:
                type: str
                description: no description
            hide-sso-credential:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            host-check:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'av'
                    - 'fw'
                    - 'av-fw'
                    - 'custom'
            host-check-interval:
                type: int
                description: no description
            host-check-policy:
                type: str
                description: no description
            ip-mode:
                type: str
                description: no description
                choices:
                    - 'range'
                    - 'user-group'
            ip-pools:
                type: str
                description: no description
            ipv6-dns-server1:
                type: str
                description: no description
            ipv6-dns-server2:
                type: str
                description: no description
            ipv6-exclusive-routing:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ipv6-pools:
                type: str
                description: no description
            ipv6-service-restriction:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ipv6-split-tunneling:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ipv6-split-tunneling-routing-address:
                type: str
                description: no description
            ipv6-tunnel-mode:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ipv6-wins-server1:
                type: str
                description: no description
            ipv6-wins-server2:
                type: str
                description: no description
            keep-alive:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            limit-user-logins:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            mac-addr-action:
                type: str
                description: no description
                choices:
                    - 'deny'
                    - 'allow'
            mac-addr-check:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            mac-addr-check-rule:
                description: no description
                type: list
                suboptions:
                    mac-addr-list:
                        description: no description
                        type: str
                    mac-addr-mask:
                        type: int
                        description: no description
                    name:
                        type: str
                        description: no description
            macos-forticlient-download-url:
                type: str
                description: no description
            name:
                type: str
                description: no description
            os-check:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            redir-url:
                type: str
                description: no description
            save-password:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            service-restriction:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            skip-check-for-unsupported-browser:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            skip-check-for-unsupported-os:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            smb-ntlmv1-auth:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            smbv1:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            split-dns:
                description: no description
                type: list
                suboptions:
                    dns-server1:
                        type: str
                        description: no description
                    dns-server2:
                        type: str
                        description: no description
                    domains:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    ipv6-dns-server1:
                        type: str
                        description: no description
                    ipv6-dns-server2:
                        type: str
                        description: no description
            split-tunneling:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            split-tunneling-routing-address:
                type: str
                description: no description
            theme:
                type: str
                description: no description
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
            tunnel-mode:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            user-bookmark:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            user-group-bookmark:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-mode:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            windows-forticlient-download-url:
                type: str
                description: no description
            wins-server1:
                type: str
                description: no description
            wins-server2:
                type: str
                description: no description
            skip-check-for-browser:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            smb-max-version:
                type: str
                description: no description
                choices:
                    - 'smbv1'
                    - 'smbv2'
                    - 'smbv3'
            smb-min-version:
                type: str
                description: no description
                choices:
                    - 'smbv1'
                    - 'smbv2'
                    - 'smbv3'
            transform-backward-slashes:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ipv6-split-tunneling-routing-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            split-tunneling-routing-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            os-check-list:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'check-up-to-date'
                            - 'deny'
                    latest-patch-level:
                        type: str
                        description: no description
                    name:
                        type: str
                        description: no description
                    tolerance:
                        type: int
                        description: no description
            use-sdwan:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            prefer-ipv6-dns:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            rewrite-ip-uri-ui:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            clipboard:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            default-window-height:
                type: int
                description: no description
            default-window-width:
                type: int
                description: no description

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
    - name: no description
      fmgr_vpnsslweb_portal:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         vpnsslweb_portal:
            allow-user-access:
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
            auto-connect: <value in [disable, enable]>
            bookmark-group:
              -
                  bookmarks:
                    -
                        additional-params: <value of string>
                        apptype: <value in [web, telnet, ssh, ...]>
                        description: <value of string>
                        folder: <value of string>
                        form-data:
                          -
                              name: <value of string>
                              value: <value of string>
                        host: <value of string>
                        listening-port: <value of integer>
                        load-balancing-info: <value of string>
                        logon-password: <value of string>
                        logon-user: <value of string>
                        name: <value of string>
                        port: <value of integer>
                        preconnection-blob: <value of string>
                        preconnection-id: <value of integer>
                        remote-port: <value of integer>
                        security: <value in [rdp, nla, tls, ...]>
                        server-layout: <value in [en-us-qwerty, de-de-qwertz, fr-fr-azerty, ...]>
                        show-status-window: <value in [disable, enable]>
                        sso: <value in [disable, static, auto]>
                        sso-credential: <value in [sslvpn-login, alternative]>
                        sso-credential-sent-once: <value in [disable, enable]>
                        sso-password: <value of string>
                        sso-username: <value of string>
                        url: <value of string>
                        domain: <value of string>
                        color-depth: <value in [8, 16, 32]>
                        height: <value of integer>
                        keyboard-layout: <value in [ar, da, de, ...]>
                        restricted-admin: <value in [disable, enable]>
                        send-preconnection-id: <value in [disable, enable]>
                        width: <value of integer>
                  name: <value of string>
            custom-lang: <value of string>
            customize-forticlient-download-url: <value in [disable, enable]>
            display-bookmark: <value in [disable, enable]>
            display-connection-tools: <value in [disable, enable]>
            display-history: <value in [disable, enable]>
            display-status: <value in [disable, enable]>
            dns-server1: <value of string>
            dns-server2: <value of string>
            dns-suffix: <value of string>
            exclusive-routing: <value in [disable, enable]>
            forticlient-download: <value in [disable, enable]>
            forticlient-download-method: <value in [direct, ssl-vpn]>
            heading: <value of string>
            hide-sso-credential: <value in [disable, enable]>
            host-check: <value in [none, av, fw, ...]>
            host-check-interval: <value of integer>
            host-check-policy: <value of string>
            ip-mode: <value in [range, user-group]>
            ip-pools: <value of string>
            ipv6-dns-server1: <value of string>
            ipv6-dns-server2: <value of string>
            ipv6-exclusive-routing: <value in [disable, enable]>
            ipv6-pools: <value of string>
            ipv6-service-restriction: <value in [disable, enable]>
            ipv6-split-tunneling: <value in [disable, enable]>
            ipv6-split-tunneling-routing-address: <value of string>
            ipv6-tunnel-mode: <value in [disable, enable]>
            ipv6-wins-server1: <value of string>
            ipv6-wins-server2: <value of string>
            keep-alive: <value in [disable, enable]>
            limit-user-logins: <value in [disable, enable]>
            mac-addr-action: <value in [deny, allow]>
            mac-addr-check: <value in [disable, enable]>
            mac-addr-check-rule:
              -
                  mac-addr-list: <value of string>
                  mac-addr-mask: <value of integer>
                  name: <value of string>
            macos-forticlient-download-url: <value of string>
            name: <value of string>
            os-check: <value in [disable, enable]>
            redir-url: <value of string>
            save-password: <value in [disable, enable]>
            service-restriction: <value in [disable, enable]>
            skip-check-for-unsupported-browser: <value in [disable, enable]>
            skip-check-for-unsupported-os: <value in [disable, enable]>
            smb-ntlmv1-auth: <value in [disable, enable]>
            smbv1: <value in [disable, enable]>
            split-dns:
              -
                  dns-server1: <value of string>
                  dns-server2: <value of string>
                  domains: <value of string>
                  id: <value of integer>
                  ipv6-dns-server1: <value of string>
                  ipv6-dns-server2: <value of string>
            split-tunneling: <value in [disable, enable]>
            split-tunneling-routing-address: <value of string>
            theme: <value in [gray, blue, orange, ...]>
            tunnel-mode: <value in [disable, enable]>
            user-bookmark: <value in [disable, enable]>
            user-group-bookmark: <value in [disable, enable]>
            web-mode: <value in [disable, enable]>
            windows-forticlient-download-url: <value of string>
            wins-server1: <value of string>
            wins-server2: <value of string>
            skip-check-for-browser: <value in [disable, enable]>
            smb-max-version: <value in [smbv1, smbv2, smbv3]>
            smb-min-version: <value in [smbv1, smbv2, smbv3]>
            transform-backward-slashes: <value in [disable, enable]>
            ipv6-split-tunneling-routing-negate: <value in [disable, enable]>
            split-tunneling-routing-negate: <value in [disable, enable]>
            os-check-list:
               action: <value in [allow, check-up-to-date, deny]>
               latest-patch-level: <value of string>
               name: <value of string>
               tolerance: <value of integer>
            use-sdwan: <value in [disable, enable]>
            prefer-ipv6-dns: <value in [disable, enable]>
            rewrite-ip-uri-ui: <value in [disable, enable]>
            clipboard: <value in [disable, enable]>
            default-window-height: <value of integer>
            default-window-width: <value of integer>

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
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
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
        'vpnsslweb_portal': {
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
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'allow-user-access': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'web',
                        'ftp',
                        'telnet',
                        'smb',
                        'vnc',
                        'rdp',
                        'ssh',
                        'ping',
                        'citrix',
                        'portforward',
                        'sftp'
                    ]
                },
                'auto-connect': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'bookmark-group': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'bookmarks': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'additional-params': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'apptype': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'web',
                                        'telnet',
                                        'ssh',
                                        'ftp',
                                        'smb',
                                        'vnc',
                                        'rdp',
                                        'citrix',
                                        'rdpnative',
                                        'portforward',
                                        'sftp'
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
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'folder': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'form-data': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'name': {
                                            'required': False,
                                            'revision': {
                                                '6.0.0': True,
                                                '6.2.1': True,
                                                '6.2.3': True,
                                                '6.2.5': True,
                                                '6.4.0': True,
                                                '6.4.2': True,
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'value': {
                                            'required': False,
                                            'revision': {
                                                '6.0.0': True,
                                                '6.2.1': True,
                                                '6.2.3': True,
                                                '6.2.5': True,
                                                '6.4.0': True,
                                                '6.4.2': True,
                                                '6.4.5': True,
                                                '7.0.0': True,
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        }
                                    }
                                },
                                'host': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'listening-port': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': False
                                    },
                                    'type': 'int'
                                },
                                'load-balancing-info': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'logon-password': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'logon-user': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'name': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'port': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'preconnection-blob': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'preconnection-id': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'remote-port': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': False
                                    },
                                    'type': 'int'
                                },
                                'security': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'rdp',
                                        'nla',
                                        'tls',
                                        'any'
                                    ],
                                    'type': 'str'
                                },
                                'server-layout': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': False
                                    },
                                    'choices': [
                                        'en-us-qwerty',
                                        'de-de-qwertz',
                                        'fr-fr-azerty',
                                        'it-it-qwerty',
                                        'sv-se-qwerty',
                                        'failsafe',
                                        'en-gb-qwerty',
                                        'es-es-qwerty',
                                        'fr-ch-qwertz',
                                        'ja-jp-qwerty',
                                        'pt-br-qwerty',
                                        'tr-tr-qwerty',
                                        'fr-ca-qwerty'
                                    ],
                                    'type': 'str'
                                },
                                'show-status-window': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': False
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'sso': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'static',
                                        'auto'
                                    ],
                                    'type': 'str'
                                },
                                'sso-credential': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'sslvpn-login',
                                        'alternative'
                                    ],
                                    'type': 'str'
                                },
                                'sso-credential-sent-once': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'sso-password': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'sso-username': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'url': {
                                    'required': False,
                                    'revision': {
                                        '6.0.0': True,
                                        '6.2.1': True,
                                        '6.2.3': True,
                                        '6.2.5': True,
                                        '6.4.0': True,
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'domain': {
                                    'required': False,
                                    'revision': {
                                        '6.4.2': True,
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'color-depth': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        '8',
                                        '16',
                                        '32'
                                    ],
                                    'type': 'str'
                                },
                                'height': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'keyboard-layout': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'ar',
                                        'da',
                                        'de',
                                        'de-ch',
                                        'en-gb',
                                        'en-uk',
                                        'en-us',
                                        'es',
                                        'fi',
                                        'fr',
                                        'fr-be',
                                        'fr-ca',
                                        'fr-ch',
                                        'hr',
                                        'hu',
                                        'it',
                                        'ja',
                                        'lt',
                                        'lv',
                                        'mk',
                                        'no',
                                        'pl',
                                        'pt',
                                        'pt-br',
                                        'ru',
                                        'sl',
                                        'sv',
                                        'tk',
                                        'tr',
                                        'fr-ca-m',
                                        'wg',
                                        'ar-101',
                                        'ar-102',
                                        'ar-102-azerty',
                                        'can-mul',
                                        'cz',
                                        'cz-qwerty',
                                        'cz-pr',
                                        'nl',
                                        'de-ibm',
                                        'en-uk-ext',
                                        'en-us-dvorak',
                                        'es-var',
                                        'fi-sami',
                                        'hu-101',
                                        'it-142',
                                        'ko',
                                        'lt-ibm',
                                        'lt-std',
                                        'lav-std',
                                        'lav-leg',
                                        'mk-std',
                                        'no-sami',
                                        'pol-214',
                                        'pol-pr',
                                        'pt-br-abnt2',
                                        'ru-mne',
                                        'ru-t',
                                        'sv-sami',
                                        'tuk',
                                        'tur-f',
                                        'tur-q',
                                        'zh-sym-sg-us',
                                        'zh-sym-us',
                                        'zh-tr-hk',
                                        'zh-tr-mo',
                                        'zh-tr-us',
                                        'fr-apple'
                                    ],
                                    'type': 'str'
                                },
                                'restricted-admin': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'send-preconnection-id': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'width': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                }
                            }
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'custom-lang': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'customize-forticlient-download-url': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'display-bookmark': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'display-connection-tools': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'display-history': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'display-status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dns-server1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dns-server2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dns-suffix': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'exclusive-routing': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'forticlient-download': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'forticlient-download-method': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'direct',
                        'ssl-vpn'
                    ],
                    'type': 'str'
                },
                'heading': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'hide-sso-credential': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'host-check': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'av',
                        'fw',
                        'av-fw',
                        'custom'
                    ],
                    'type': 'str'
                },
                'host-check-interval': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'host-check-policy': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ip-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'range',
                        'user-group'
                    ],
                    'type': 'str'
                },
                'ip-pools': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6-dns-server1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6-dns-server2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6-exclusive-routing': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ipv6-pools': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6-service-restriction': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ipv6-split-tunneling': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ipv6-split-tunneling-routing-address': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6-tunnel-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ipv6-wins-server1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ipv6-wins-server2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'keep-alive': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'limit-user-logins': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mac-addr-action': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'deny',
                        'allow'
                    ],
                    'type': 'str'
                },
                'mac-addr-check': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mac-addr-check-rule': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'mac-addr-list': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'mac-addr-mask': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'macos-forticlient-download-url': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'os-check': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'redir-url': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'save-password': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'service-restriction': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'skip-check-for-unsupported-browser': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'skip-check-for-unsupported-os': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'smb-ntlmv1-auth': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'smbv1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'split-dns': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'dns-server1': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'dns-server2': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'domains': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'ipv6-dns-server1': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ipv6-dns-server2': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'split-tunneling': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'split-tunneling-routing-address': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'theme': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'gray',
                        'blue',
                        'orange',
                        'crimson',
                        'steelblue',
                        'darkgrey',
                        'green',
                        'melongene',
                        'red',
                        'mariner',
                        'neutrino',
                        'jade',
                        'graphite',
                        'dark-matter',
                        'onyx',
                        'eclipse'
                    ],
                    'type': 'str'
                },
                'tunnel-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'user-bookmark': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'user-group-bookmark': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'windows-forticlient-download-url': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'wins-server1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'wins-server2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'skip-check-for-browser': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'smb-max-version': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'smbv1',
                        'smbv2',
                        'smbv3'
                    ],
                    'type': 'str'
                },
                'smb-min-version': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'smbv1',
                        'smbv2',
                        'smbv3'
                    ],
                    'type': 'str'
                },
                'transform-backward-slashes': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ipv6-split-tunneling-routing-negate': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'split-tunneling-routing-negate': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'os-check-list': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'allow',
                                'check-up-to-date',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'latest-patch-level': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'tolerance': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'use-sdwan': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'prefer-ipv6-dns': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rewrite-ip-uri-ui': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'clipboard': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'default-window-height': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'default-window-width': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_portal'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
