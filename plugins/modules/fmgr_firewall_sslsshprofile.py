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
module: fmgr_firewall_sslsshprofile
short_description: Configure SSL/SSH protocol options.
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
    firewall_sslsshprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            caname:
                type: str
                description: 'CA certificate used by SSL Inspection.'
            comment:
                type: str
                description: 'Optional comments.'
            mapi-over-https:
                type: str
                description: 'Enable/disable inspection of MAPI over HTTPS.'
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: 'Name.'
            rpc-over-https:
                type: str
                description: 'Enable/disable inspection of RPC over HTTPS.'
                choices:
                    - 'disable'
                    - 'enable'
            server-cert:
                type: str
                description: 'Certificate used by SSL Inspection to replace server certificate.'
            server-cert-mode:
                type: str
                description: 'Re-sign or replace the servers certificate.'
                choices:
                    - 're-sign'
                    - 'replace'
            ssl-anomalies-log:
                type: str
                description: 'Enable/disable logging SSL anomalies.'
                choices:
                    - 'disable'
                    - 'enable'
            ssl-exempt:
                description: no description
                type: list
                suboptions:
                    address:
                        type: str
                        description: 'IPv4 address object.'
                    address6:
                        type: str
                        description: 'IPv6 address object.'
                    fortiguard-category:
                        type: str
                        description: 'FortiGuard category ID.'
                    id:
                        type: int
                        description: 'ID number.'
                    regex:
                        type: str
                        description: 'Exempt servers by regular expression.'
                    type:
                        type: str
                        description: 'Type of address object (IPv4 or IPv6) or FortiGuard category.'
                        choices:
                            - 'fortiguard-category'
                            - 'address'
                            - 'address6'
                            - 'wildcard-fqdn'
                            - 'regex'
                    wildcard-fqdn:
                        type: str
                        description: 'Exempt servers by wildcard FQDN.'
            ssl-exemptions-log:
                type: str
                description: 'Enable/disable logging SSL exemptions.'
                choices:
                    - 'disable'
                    - 'enable'
            ssl-server:
                description: no description
                type: list
                suboptions:
                    ftps-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during the FTPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    https-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during the HTTPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    id:
                        type: int
                        description: 'SSL server ID.'
                    imaps-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during the IMAPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ip:
                        type: str
                        description: 'IPv4 address of the SSL server.'
                    pop3s-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during the POP3S handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    smtps-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during the SMTPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ssl-other-client-cert-request:
                        type: str
                        description: 'Action based on client certificate request during an SSL protocol handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ftps-client-certificate:
                        type: str
                        description: 'Action based on received client certificate during the FTPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    https-client-certificate:
                        type: str
                        description: 'Action based on received client certificate during the HTTPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    imaps-client-certificate:
                        type: str
                        description: 'Action based on received client certificate during the IMAPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    pop3s-client-certificate:
                        type: str
                        description: 'Action based on received client certificate during the POP3S handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    smtps-client-certificate:
                        type: str
                        description: 'Action based on received client certificate during the SMTPS handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ssl-other-client-certificate:
                        type: str
                        description: 'Action based on received client certificate during an SSL protocol handshake.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
            untrusted-caname:
                type: str
                description: 'Untrusted CA certificate used by SSL Inspection.'
            use-ssl-server:
                type: str
                description: 'Enable/disable the use of SSL server table for SSL offloading.'
                choices:
                    - 'disable'
                    - 'enable'
            whitelist:
                type: str
                description: 'Enable/disable exempting servers by FortiGuard whitelist.'
                choices:
                    - 'disable'
                    - 'enable'
            block-blacklisted-certificates:
                type: str
                description: 'Enable/disable blocking SSL-based botnet communication by FortiGuard certificate blacklist.'
                choices:
                    - 'disable'
                    - 'enable'
            ssl-negotiation-log:
                type: str
                description: 'Enable/disable logging SSL negotiation.'
                choices:
                    - 'disable'
                    - 'enable'
            ftps:
                description: no description
                type: dict
                required: false
                suboptions:
                    cert-validation-failure:
                        type: str
                        description: 'Action based on certificate validation failure.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: 'Action based on certificate validation timeout.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: 'Action based on received client certificate.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: 'Action based on server certificate is expired.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        description: no description
                        type: int
                    revoked-server-cert:
                        type: str
                        description: 'Action based on server certificate is revoked.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: 'Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.'
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: 'Configure protocol inspection status.'
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: 'Action based on the SSL cipher used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: 'Action based on the SSL negotiation used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: 'Action based on server certificate is not issued by a trusted CA.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            https:
                description: no description
                type: dict
                required: false
                suboptions:
                    cert-validation-failure:
                        type: str
                        description: 'Action based on certificate validation failure.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: 'Action based on certificate validation timeout.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: 'Action based on received client certificate.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: 'Action based on server certificate is expired.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked-server-cert:
                        type: str
                        description: 'Action based on server certificate is revoked.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: 'Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.'
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: 'Configure protocol inspection status.'
                        choices:
                            - 'disable'
                            - 'certificate-inspection'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: 'Action based on the SSL cipher used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: 'Action based on the SSL negotiation used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: 'Action based on server certificate is not issued by a trusted CA.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-probe-failure:
                        type: str
                        description: 'Action based on certificate probe failure.'
                        choices:
                            - 'block'
                            - 'allow'
            imaps:
                description: no description
                type: dict
                required: false
                suboptions:
                    cert-validation-failure:
                        type: str
                        description: 'Action based on certificate validation failure.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: 'Action based on certificate validation timeout.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: 'Action based on received client certificate.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: 'Action based on server certificate is expired.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked-server-cert:
                        type: str
                        description: 'Action based on server certificate is revoked.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: 'Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.'
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: 'Configure protocol inspection status.'
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: 'Action based on the SSL cipher used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: 'Action based on the SSL negotiation used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: 'Action based on server certificate is not issued by a trusted CA.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            pop3s:
                description: no description
                type: dict
                required: false
                suboptions:
                    cert-validation-failure:
                        type: str
                        description: 'Action based on certificate validation failure.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: 'Action based on certificate validation timeout.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: 'Action based on received client certificate.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: 'Action based on server certificate is expired.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked-server-cert:
                        type: str
                        description: 'Action based on server certificate is revoked.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: 'Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.'
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: 'Configure protocol inspection status.'
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: 'Action based on the SSL cipher used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: 'Action based on the SSL negotiation used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: 'Action based on server certificate is not issued by a trusted CA.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            smtps:
                description: no description
                type: dict
                required: false
                suboptions:
                    cert-validation-failure:
                        type: str
                        description: 'Action based on certificate validation failure.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: 'Action based on certificate validation timeout.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: 'Action based on received client certificate.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: 'Action based on server certificate is expired.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked-server-cert:
                        type: str
                        description: 'Action based on server certificate is revoked.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: 'Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.'
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: 'Configure protocol inspection status.'
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: 'Action based on the SSL cipher used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: 'Action based on the SSL negotiation used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: 'Action based on server certificate is not issued by a trusted CA.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            ssh:
                description: no description
                type: dict
                required: false
                suboptions:
                    inspect-all:
                        type: str
                        description: 'Level of SSL inspection.'
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssh-algorithm:
                        type: str
                        description: 'Relative strength of encryption algorithms accepted during negotiation.'
                        choices:
                            - 'compatible'
                            - 'high-encryption'
                    ssh-tun-policy-check:
                        type: str
                        description: 'Enable/disable SSH tunnel policy check.'
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: 'Configure protocol inspection status.'
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-version:
                        type: str
                        description: 'Action based on SSH version being unsupported.'
                        choices:
                            - 'block'
                            - 'bypass'
            ssl:
                description: no description
                type: dict
                required: false
                suboptions:
                    cert-validation-failure:
                        type: str
                        description: 'Action based on certificate validation failure.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: 'Action based on certificate validation timeout.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: 'Action based on received client certificate.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: 'Action based on server certificate is expired.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    inspect-all:
                        type: str
                        description: 'Level of SSL inspection.'
                        choices:
                            - 'disable'
                            - 'certificate-inspection'
                            - 'deep-inspection'
                    revoked-server-cert:
                        type: str
                        description: 'Action based on server certificate is revoked.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: 'Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.'
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    unsupported-ssl-cipher:
                        type: str
                        description: 'Action based on the SSL cipher used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: 'Action based on the SSL negotiation used being unsupported.'
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: 'Action based on server certificate is not issued by a trusted CA.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            allowlist:
                type: str
                description: 'Enable/disable exempting servers by FortiGuard allowlist.'
                choices:
                    - 'disable'
                    - 'enable'
            block-blocklisted-certificates:
                type: str
                description: 'Enable/disable blocking SSL-based botnet communication by FortiGuard certificate blocklist.'
                choices:
                    - 'disable'
                    - 'enable'
            dot:
                description: no description
                type: dict
                required: false
                suboptions:
                    cert-validation-failure:
                        type: str
                        description: 'Action based on certificate validation failure.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: 'Action based on certificate validation timeout.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: 'Action based on received client certificate.'
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: 'Action based on server certificate is expired.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    proxy-after-tcp-handshake:
                        type: str
                        description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked-server-cert:
                        type: str
                        description: 'Action based on server certificate is revoked.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: 'Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.'
                        choices:
                            - 'enable'
                            - 'strict'
                            - 'disable'
                    status:
                        type: str
                        description: 'Configure protocol inspection status.'
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: 'Action based on the SSL cipher used being unsupported.'
                        choices:
                            - 'block'
                            - 'allow'
                    unsupported-ssl-negotiation:
                        type: str
                        description: 'Action based on the SSL negotiation used being unsupported.'
                        choices:
                            - 'block'
                            - 'allow'
                    untrusted-server-cert:
                        type: str
                        description: 'Action based on server certificate is not issued by a trusted CA.'
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            supported-alpn:
                type: str
                description: 'Configure ALPN option.'
                choices:
                    - 'none'
                    - 'http1-1'
                    - 'http2'
                    - 'all'

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
    - name: Configure SSL/SSH protocol options.
      fmgr_firewall_sslsshprofile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         firewall_sslsshprofile:
            caname: <value of string>
            comment: <value of string>
            mapi-over-https: <value in [disable, enable]>
            name: <value of string>
            rpc-over-https: <value in [disable, enable]>
            server-cert: <value of string>
            server-cert-mode: <value in [re-sign, replace]>
            ssl-anomalies-log: <value in [disable, enable]>
            ssl-exempt:
              -
                  address: <value of string>
                  address6: <value of string>
                  fortiguard-category: <value of string>
                  id: <value of integer>
                  regex: <value of string>
                  type: <value in [fortiguard-category, address, address6, ...]>
                  wildcard-fqdn: <value of string>
            ssl-exemptions-log: <value in [disable, enable]>
            ssl-server:
              -
                  ftps-client-cert-request: <value in [bypass, inspect, block]>
                  https-client-cert-request: <value in [bypass, inspect, block]>
                  id: <value of integer>
                  imaps-client-cert-request: <value in [bypass, inspect, block]>
                  ip: <value of string>
                  pop3s-client-cert-request: <value in [bypass, inspect, block]>
                  smtps-client-cert-request: <value in [bypass, inspect, block]>
                  ssl-other-client-cert-request: <value in [bypass, inspect, block]>
                  ftps-client-certificate: <value in [bypass, inspect, block]>
                  https-client-certificate: <value in [bypass, inspect, block]>
                  imaps-client-certificate: <value in [bypass, inspect, block]>
                  pop3s-client-certificate: <value in [bypass, inspect, block]>
                  smtps-client-certificate: <value in [bypass, inspect, block]>
                  ssl-other-client-certificate: <value in [bypass, inspect, block]>
            untrusted-caname: <value of string>
            use-ssl-server: <value in [disable, enable]>
            whitelist: <value in [disable, enable]>
            block-blacklisted-certificates: <value in [disable, enable]>
            ssl-negotiation-log: <value in [disable, enable]>
            ftps:
               cert-validation-failure: <value in [allow, block, ignore]>
               cert-validation-timeout: <value in [allow, block, ignore]>
               client-certificate: <value in [bypass, inspect, block]>
               expired-server-cert: <value in [allow, block, ignore]>
               ports: <value of integer>
               revoked-server-cert: <value in [allow, block, ignore]>
               sni-server-cert-check: <value in [disable, enable, strict]>
               status: <value in [disable, deep-inspection]>
               unsupported-ssl-cipher: <value in [allow, block]>
               unsupported-ssl-negotiation: <value in [allow, block]>
               untrusted-server-cert: <value in [allow, block, ignore]>
            https:
               cert-validation-failure: <value in [allow, block, ignore]>
               cert-validation-timeout: <value in [allow, block, ignore]>
               client-certificate: <value in [bypass, inspect, block]>
               expired-server-cert: <value in [allow, block, ignore]>
               ports: <value of integer>
               proxy-after-tcp-handshake: <value in [disable, enable]>
               revoked-server-cert: <value in [allow, block, ignore]>
               sni-server-cert-check: <value in [disable, enable, strict]>
               status: <value in [disable, certificate-inspection, deep-inspection]>
               unsupported-ssl-cipher: <value in [allow, block]>
               unsupported-ssl-negotiation: <value in [allow, block]>
               untrusted-server-cert: <value in [allow, block, ignore]>
               cert-probe-failure: <value in [block, allow]>
            imaps:
               cert-validation-failure: <value in [allow, block, ignore]>
               cert-validation-timeout: <value in [allow, block, ignore]>
               client-certificate: <value in [bypass, inspect, block]>
               expired-server-cert: <value in [allow, block, ignore]>
               ports: <value of integer>
               proxy-after-tcp-handshake: <value in [disable, enable]>
               revoked-server-cert: <value in [allow, block, ignore]>
               sni-server-cert-check: <value in [disable, enable, strict]>
               status: <value in [disable, deep-inspection]>
               unsupported-ssl-cipher: <value in [allow, block]>
               unsupported-ssl-negotiation: <value in [allow, block]>
               untrusted-server-cert: <value in [allow, block, ignore]>
            pop3s:
               cert-validation-failure: <value in [allow, block, ignore]>
               cert-validation-timeout: <value in [allow, block, ignore]>
               client-certificate: <value in [bypass, inspect, block]>
               expired-server-cert: <value in [allow, block, ignore]>
               ports: <value of integer>
               proxy-after-tcp-handshake: <value in [disable, enable]>
               revoked-server-cert: <value in [allow, block, ignore]>
               sni-server-cert-check: <value in [disable, enable, strict]>
               status: <value in [disable, deep-inspection]>
               unsupported-ssl-cipher: <value in [allow, block]>
               unsupported-ssl-negotiation: <value in [allow, block]>
               untrusted-server-cert: <value in [allow, block, ignore]>
            smtps:
               cert-validation-failure: <value in [allow, block, ignore]>
               cert-validation-timeout: <value in [allow, block, ignore]>
               client-certificate: <value in [bypass, inspect, block]>
               expired-server-cert: <value in [allow, block, ignore]>
               ports: <value of integer>
               proxy-after-tcp-handshake: <value in [disable, enable]>
               revoked-server-cert: <value in [allow, block, ignore]>
               sni-server-cert-check: <value in [disable, enable, strict]>
               status: <value in [disable, deep-inspection]>
               unsupported-ssl-cipher: <value in [allow, block]>
               unsupported-ssl-negotiation: <value in [allow, block]>
               untrusted-server-cert: <value in [allow, block, ignore]>
            ssh:
               inspect-all: <value in [disable, deep-inspection]>
               ports: <value of integer>
               proxy-after-tcp-handshake: <value in [disable, enable]>
               ssh-algorithm: <value in [compatible, high-encryption]>
               ssh-tun-policy-check: <value in [disable, enable]>
               status: <value in [disable, deep-inspection]>
               unsupported-version: <value in [block, bypass]>
            ssl:
               cert-validation-failure: <value in [allow, block, ignore]>
               cert-validation-timeout: <value in [allow, block, ignore]>
               client-certificate: <value in [bypass, inspect, block]>
               expired-server-cert: <value in [allow, block, ignore]>
               inspect-all: <value in [disable, certificate-inspection, deep-inspection]>
               revoked-server-cert: <value in [allow, block, ignore]>
               sni-server-cert-check: <value in [disable, enable, strict]>
               unsupported-ssl-cipher: <value in [allow, block]>
               unsupported-ssl-negotiation: <value in [allow, block]>
               untrusted-server-cert: <value in [allow, block, ignore]>
            allowlist: <value in [disable, enable]>
            block-blocklisted-certificates: <value in [disable, enable]>
            dot:
               cert-validation-failure: <value in [allow, block, ignore]>
               cert-validation-timeout: <value in [allow, block, ignore]>
               client-certificate: <value in [bypass, inspect, block]>
               expired-server-cert: <value in [allow, block, ignore]>
               proxy-after-tcp-handshake: <value in [disable, enable]>
               revoked-server-cert: <value in [allow, block, ignore]>
               sni-server-cert-check: <value in [enable, strict, disable]>
               status: <value in [disable, deep-inspection]>
               unsupported-ssl-cipher: <value in [block, allow]>
               unsupported-ssl-negotiation: <value in [block, allow]>
               untrusted-server-cert: <value in [allow, block, ignore]>
            supported-alpn: <value in [none, http1-1, http2, ...]>

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
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile',
        '/pm/config/global/obj/firewall/ssl-ssh-profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}',
        '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
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
        'firewall_sslsshprofile': {
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
                '7.0.0': True
            },
            'options': {
                'caname': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'comment': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'mapi-over-https': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
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
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'rpc-over-https': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'server-cert': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'server-cert-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        're-sign',
                        'replace'
                    ],
                    'type': 'str'
                },
                'ssl-anomalies-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-exempt': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'address': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'address6': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'fortiguard-category': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
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
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'regex': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'fortiguard-category',
                                'address',
                                'address6',
                                'wildcard-fqdn',
                                'regex'
                            ],
                            'type': 'str'
                        },
                        'wildcard-fqdn': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'ssl-exemptions-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-server': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'ftps-client-cert-request': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'https-client-cert-request': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
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
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'imaps-client-cert-request': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'ip': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'pop3s-client-cert-request': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'smtps-client-cert-request': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'ssl-other-client-cert-request': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': False,
                                '6.4.2': False,
                                '6.4.5': False,
                                '7.0.0': False
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'ftps-client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'https-client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'imaps-client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'pop3s-client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'smtps-client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'ssl-other-client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'untrusted-caname': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'use-ssl-server': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'whitelist': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'block-blacklisted-certificates': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-negotiation-log': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ftps': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'expired-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'sni-server-cert-check': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'strict'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'deep-inspection'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-cipher': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-negotiation': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'https': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'expired-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'sni-server-cert-check': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'strict'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'certificate-inspection',
                                'deep-inspection'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-cipher': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-negotiation': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'cert-probe-failure': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'block',
                                'allow'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'imaps': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'expired-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'sni-server-cert-check': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'strict'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'deep-inspection'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-cipher': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-negotiation': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'pop3s': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'expired-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'sni-server-cert-check': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'strict'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'deep-inspection'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-cipher': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-negotiation': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'smtps': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'expired-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'sni-server-cert-check': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'strict'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'deep-inspection'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-cipher': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-negotiation': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'ssh': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'inspect-all': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'deep-inspection'
                            ],
                            'type': 'str'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'ssh-algorithm': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'compatible',
                                'high-encryption'
                            ],
                            'type': 'str'
                        },
                        'ssh-tun-policy-check': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'deep-inspection'
                            ],
                            'type': 'str'
                        },
                        'unsupported-version': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'block',
                                'bypass'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'ssl': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'expired-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'inspect-all': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'certificate-inspection',
                                'deep-inspection'
                            ],
                            'type': 'str'
                        },
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'sni-server-cert-check': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'strict'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-cipher': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-negotiation': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'allowlist': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'block-blocklisted-certificates': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dot': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'inspect',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'expired-server-cert': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'proxy-after-tcp-handshake': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'sni-server-cert-check': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'enable',
                                'strict',
                                'disable'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'deep-inspection'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-cipher': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'block',
                                'allow'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-negotiation': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'block',
                                'allow'
                            ],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'supported-alpn': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'none',
                        'http1-1',
                        'http2',
                        'all'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslsshprofile'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
