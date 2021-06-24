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
module: fmgr_firewall_profileprotocoloptions
short_description: Configure protocol options.
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
    firewall_profileprotocoloptions:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: 'Optional comments.'
            name:
                type: str
                description: 'Name.'
            oversize-log:
                type: str
                description: 'Enable/disable logging for antivirus oversize file blocking.'
                choices:
                    - 'disable'
                    - 'enable'
            replacemsg-group:
                type: str
                description: 'Name of the replacement message group to be used'
            rpc-over-http:
                type: str
                description: 'Enable/disable inspection of RPC over HTTP.'
                choices:
                    - 'disable'
                    - 'enable'
            switching-protocols-log:
                type: str
                description: 'Enable/disable logging for HTTP/HTTPS switching protocols.'
                choices:
                    - 'disable'
                    - 'enable'
            feature-set:
                type: str
                description: 'Flow/proxy feature set.'
                choices:
                    - 'proxy'
                    - 'flow'
            cifs:
                description: no description
                type: dict
                required: false
                suboptions:
                    domain-controller:
                        type: str
                        description: 'Domain for which to decrypt CIFS traffic.'
                    file-filter:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            entries:
                                description: no description
                                type: list
                                suboptions:
                                    action:
                                        type: str
                                        description: 'Action taken for matched file.'
                                        choices:
                                            - 'log'
                                            - 'block'
                                    comment:
                                        type: str
                                        description: 'Comment.'
                                    direction:
                                        type: str
                                        description: 'Match files transmitted in the sessions originating or reply direction.'
                                        choices:
                                            - 'any'
                                            - 'incoming'
                                            - 'outgoing'
                                    file-type:
                                        description: no description
                                        type: str
                                    filter:
                                        type: str
                                        description: 'Add a file filter.'
                                    protocol:
                                        description: no description
                                        type: list
                                        choices:
                                         - cifs
                            log:
                                type: str
                                description: 'Enable/disable file filter logging.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                            status:
                                type: str
                                description: 'Enable/disable file filter.'
                                choices:
                                    - 'disable'
                                    - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                    oversize-limit:
                        type: int
                        description: 'Maximum in-memory file size that can be scanned (1 - 383 MB, default = 10).'
                    ports:
                        description: no description
                        type: int
                    scan-bzip2:
                        type: str
                        description: 'Enable/disable scanning of BZip2 compressed files.'
                        choices:
                            - 'disable'
                            - 'enable'
                    server-credential-type:
                        type: str
                        description: 'CIFS server credential type.'
                        choices:
                            - 'none'
                            - 'credential-replication'
                            - 'credential-keytab'
                    server-keytab:
                        description: no description
                        type: list
                        suboptions:
                            keytab:
                                type: str
                                description: 'Base64 encoded keytab file containing credential of the server.'
                            password:
                                description: no description
                                type: str
                            principal:
                                type: str
                                description: 'Service principal.  For example, "host/cifsserver.example.com@example.com".'
                    status:
                        type: str
                        description: 'Enable/disable the active status of scanning for this protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp-window-maximum:
                        type: int
                        description: 'Maximum dynamic TCP window size (default = 8MB).'
                    tcp-window-minimum:
                        type: int
                        description: 'Minimum dynamic TCP window size (default = 128KB).'
                    tcp-window-size:
                        type: int
                        description: 'Set TCP static window size (default = 256KB).'
                    tcp-window-type:
                        type: str
                        description: 'Specify type of TCP window to use for this protocol.'
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'
                    uncompressed-nest-limit:
                        type: int
                        description: 'Maximum nested levels of compression that can be uncompressed and scanned (2 - 100, default = 12).'
                    uncompressed-oversize-limit:
                        type: int
                        description: 'Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited, default = 10).'
            dns:
                description: no description
                type: dict
                required: false
                suboptions:
                    ports:
                        description: no description
                        type: int
                    status:
                        type: str
                        description: 'Enable/disable the active status of scanning for this protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
            ftp:
                description: no description
                type: dict
                required: false
                suboptions:
                    comfort-amount:
                        type: int
                        description: 'Amount of data to send in a transmission for client comforting (1 - 65535 bytes, default = 1).'
                    comfort-interval:
                        type: int
                        description: 'Period of time between start, or last transmission, and the next client comfort transmission of data (1 - 900 sec, def...'
                    inspect-all:
                        type: str
                        description: 'Enable/disable the inspection of all ports for the protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - clientcomfort
                         - no-content-summary
                         - oversize
                         - splice
                         - bypass-rest-command
                         - bypass-mode-command
                    oversize-limit:
                        type: int
                        description: 'Maximum in-memory file size that can be scanned (1 - 383 MB, default = 10).'
                    ports:
                        description: no description
                        type: int
                    scan-bzip2:
                        type: str
                        description: 'Enable/disable scanning of BZip2 compressed files.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-offloaded:
                        type: str
                        description: 'SSL decryption and encryption performed by an external device.'
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: 'Enable/disable the active status of scanning for this protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: 'Maximum nested levels of compression that can be uncompressed and scanned (2 - 100, default = 12).'
                    uncompressed-oversize-limit:
                        type: int
                        description: 'Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited, default = 10).'
                    stream-based-uncompressed-limit:
                        type: int
                        description: 'Maximum stream-based uncompressed data size that will be scanned (MB, 0 = unlimited (default).  Stream-based uncompres...'
                    tcp-window-maximum:
                        type: int
                        description: 'Maximum dynamic TCP window size.'
                    tcp-window-minimum:
                        type: int
                        description: 'Minimum dynamic TCP window size.'
                    tcp-window-size:
                        type: int
                        description: 'Set TCP static window size.'
                    tcp-window-type:
                        type: str
                        description: 'TCP window type to use for this protocol.'
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'
            http:
                description: no description
                type: dict
                required: false
                suboptions:
                    block-page-status-code:
                        type: int
                        description: 'Code number returned for blocked HTTP pages (non-FortiGuard only) (100 - 599, default = 403).'
                    comfort-amount:
                        type: int
                        description: 'Amount of data to send in a transmission for client comforting (1 - 65535 bytes, default = 1).'
                    comfort-interval:
                        type: int
                        description: 'Period of time between start, or last transmission, and the next client comfort transmission of data (1 - 900 sec, def...'
                    fortinet-bar:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    fortinet-bar-port:
                        type: int
                        description: no description
                    inspect-all:
                        type: str
                        description: 'Enable/disable the inspection of all ports for the protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - chunkedbypass
                         - clientcomfort
                         - no-content-summary
                         - servercomfort
                    oversize-limit:
                        type: int
                        description: 'Maximum in-memory file size that can be scanned (1 - 383 MB, default = 10).'
                    ports:
                        description: no description
                        type: int
                    post-lang:
                        description: no description
                        type: list
                        choices:
                         - jisx0201
                         - jisx0208
                         - jisx0212
                         - gb2312
                         - ksc5601-ex
                         - euc-jp
                         - sjis
                         - iso2022-jp
                         - iso2022-jp-1
                         - iso2022-jp-2
                         - euc-cn
                         - ces-gbk
                         - hz
                         - ces-big5
                         - euc-kr
                         - iso2022-jp-3
                         - iso8859-1
                         - tis620
                         - cp874
                         - cp1252
                         - cp1251
                    proxy-after-tcp-handshake:
                        type: str
                        description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                        choices:
                            - 'disable'
                            - 'enable'
                    range-block:
                        type: str
                        description: 'Enable/disable blocking of partial downloads.'
                        choices:
                            - 'disable'
                            - 'enable'
                    retry-count:
                        type: int
                        description: 'Number of attempts to retry HTTP connection (0 - 100, default = 0).'
                    scan-bzip2:
                        type: str
                        description: 'Enable/disable scanning of BZip2 compressed files.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-offloaded:
                        type: str
                        description: 'SSL decryption and encryption performed by an external device.'
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: 'Enable/disable the active status of scanning for this protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    stream-based-uncompressed-limit:
                        type: int
                        description: 'Maximum stream-based uncompressed data size that will be scanned (MB, 0 = unlimited (default).  Stream-based uncompres...'
                    streaming-content-bypass:
                        type: str
                        description: 'Enable/disable bypassing of streaming content from buffering.'
                        choices:
                            - 'disable'
                            - 'enable'
                    strip-x-forwarded-for:
                        type: str
                        description: 'Enable/disable stripping of HTTP X-Forwarded-For header.'
                        choices:
                            - 'disable'
                            - 'enable'
                    switching-protocols:
                        type: str
                        description: 'Bypass from scanning, or block a connection that attempts to switch protocol.'
                        choices:
                            - 'bypass'
                            - 'block'
                    tcp-window-maximum:
                        type: int
                        description: 'Maximum dynamic TCP window size (default = 8MB).'
                    tcp-window-minimum:
                        type: int
                        description: 'Minimum dynamic TCP window size (default = 128KB).'
                    tcp-window-size:
                        type: int
                        description: 'Set TCP static window size (default = 256KB).'
                    tcp-window-type:
                        type: str
                        description: 'Specify type of TCP window to use for this protocol.'
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'
                    tunnel-non-http:
                        type: str
                        description: 'Configure how to process non-HTTP traffic when a profile configured for HTTP traffic accepts a non-HTTP session. Can o...'
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: 'Maximum nested levels of compression that can be uncompressed and scanned (2 - 100, default = 12).'
                    uncompressed-oversize-limit:
                        type: int
                        description: 'Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited, default = 10).'
                    unknown-http-version:
                        type: str
                        description: 'How to handle HTTP sessions that do not comply with HTTP 0.9, 1.0, or 1.1.'
                        choices:
                            - 'best-effort'
                            - 'reject'
                            - 'tunnel'
            imap:
                description: no description
                type: dict
                required: false
                suboptions:
                    inspect-all:
                        type: str
                        description: 'Enable/disable the inspection of all ports for the protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - fragmail
                         - no-content-summary
                    oversize-limit:
                        type: int
                        description: 'Maximum in-memory file size that can be scanned (1 - 383 MB, default = 10).'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                        choices:
                            - 'disable'
                            - 'enable'
                    scan-bzip2:
                        type: str
                        description: 'Enable/disable scanning of BZip2 compressed files.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-offloaded:
                        type: str
                        description: 'SSL decryption and encryption performed by an external device.'
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: 'Enable/disable the active status of scanning for this protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: 'Maximum nested levels of compression that can be uncompressed and scanned (2 - 100, default = 12).'
                    uncompressed-oversize-limit:
                        type: int
                        description: 'Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited, default = 10).'
            mail-signature:
                description: no description
                type: dict
                required: false
                suboptions:
                    signature:
                        type: str
                        description: 'Email signature to be added to outgoing email (if the signature contains spaces, enclose with quotation marks).'
                    status:
                        type: str
                        description: 'Enable/disable adding an email signature to SMTP email messages as they pass through the FortiGate.'
                        choices:
                            - 'disable'
                            - 'enable'
            mapi:
                description: no description
                type: dict
                required: false
                suboptions:
                    options:
                        description: no description
                        type: list
                        choices:
                         - fragmail
                         - oversize
                         - no-content-summary
                    oversize-limit:
                        type: int
                        description: 'Maximum in-memory file size that can be scanned (1 - 383 MB, default = 10).'
                    ports:
                        description: no description
                        type: int
                    scan-bzip2:
                        type: str
                        description: 'Enable/disable scanning of BZip2 compressed files.'
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: 'Enable/disable the active status of scanning for this protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: 'Maximum nested levels of compression that can be uncompressed and scanned (2 - 100, default = 12).'
                    uncompressed-oversize-limit:
                        type: int
                        description: 'Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited, default = 10).'
            nntp:
                description: no description
                type: dict
                required: false
                suboptions:
                    inspect-all:
                        type: str
                        description: 'Enable/disable the inspection of all ports for the protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - no-content-summary
                         - splice
                    oversize-limit:
                        type: int
                        description: 'Maximum in-memory file size that can be scanned (1 - 383 MB, default = 10).'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                        choices:
                            - 'disable'
                            - 'enable'
                    scan-bzip2:
                        type: str
                        description: 'Enable/disable scanning of BZip2 compressed files.'
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: 'Enable/disable the active status of scanning for this protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: 'Maximum nested levels of compression that can be uncompressed and scanned (2 - 100, default = 12).'
                    uncompressed-oversize-limit:
                        type: int
                        description: 'Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited, default = 10).'
            pop3:
                description: no description
                type: dict
                required: false
                suboptions:
                    inspect-all:
                        type: str
                        description: 'Enable/disable the inspection of all ports for the protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - fragmail
                         - no-content-summary
                    oversize-limit:
                        type: int
                        description: 'Maximum in-memory file size that can be scanned (1 - 383 MB, default = 10).'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                        choices:
                            - 'disable'
                            - 'enable'
                    scan-bzip2:
                        type: str
                        description: 'Enable/disable scanning of BZip2 compressed files.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-offloaded:
                        type: str
                        description: 'SSL decryption and encryption performed by an external device.'
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: 'Enable/disable the active status of scanning for this protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: 'Maximum nested levels of compression that can be uncompressed and scanned (2 - 100, default = 12).'
                    uncompressed-oversize-limit:
                        type: int
                        description: 'Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited, default = 10).'
            smtp:
                description: no description
                type: dict
                required: false
                suboptions:
                    inspect-all:
                        type: str
                        description: 'Enable/disable the inspection of all ports for the protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - fragmail
                         - no-content-summary
                         - splice
                    oversize-limit:
                        type: int
                        description: 'Maximum in-memory file size that can be scanned (1 - 383 MB, default = 10).'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: 'Proxy traffic after the TCP 3-way handshake has been established (not before).'
                        choices:
                            - 'disable'
                            - 'enable'
                    scan-bzip2:
                        type: str
                        description: 'Enable/disable scanning of BZip2 compressed files.'
                        choices:
                            - 'disable'
                            - 'enable'
                    server-busy:
                        type: str
                        description: 'Enable/disable SMTP server busy when server not available.'
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl-offloaded:
                        type: str
                        description: 'SSL decryption and encryption performed by an external device.'
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: 'Enable/disable the active status of scanning for this protocol.'
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: 'Maximum nested levels of compression that can be uncompressed and scanned (2 - 100, default = 12).'
                    uncompressed-oversize-limit:
                        type: int
                        description: 'Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited, default = 10).'
            ssh:
                description: no description
                type: dict
                required: false
                suboptions:
                    comfort-amount:
                        type: int
                        description: 'Amount of data to send in a transmission for client comforting (1 - 65535 bytes, default = 1).'
                    comfort-interval:
                        type: int
                        description: 'Period of time between start, or last transmission, and the next client comfort transmission of data (1 - 900 sec, def...'
                    options:
                        description: no description
                        type: list
                        choices:
                         - oversize
                         - clientcomfort
                         - servercomfort
                    oversize-limit:
                        type: int
                        description: 'Maximum in-memory file size that can be scanned (1 - 383 MB, default = 10).'
                    scan-bzip2:
                        type: str
                        description: 'Enable/disable scanning of BZip2 compressed files.'
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed-nest-limit:
                        type: int
                        description: 'Maximum nested levels of compression that can be uncompressed and scanned (2 - 100, default = 12).'
                    uncompressed-oversize-limit:
                        type: int
                        description: 'Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited, default = 10).'
                    ssl-offloaded:
                        type: str
                        description: 'SSL decryption and encryption performed by an external device.'
                        choices:
                            - 'no'
                            - 'yes'
                    stream-based-uncompressed-limit:
                        type: int
                        description: 'Maximum stream-based uncompressed data size that will be scanned (MB, 0 = unlimited (default).  Stream-based uncompres...'
                    tcp-window-maximum:
                        type: int
                        description: 'Maximum dynamic TCP window size.'
                    tcp-window-minimum:
                        type: int
                        description: 'Minimum dynamic TCP window size.'
                    tcp-window-size:
                        type: int
                        description: 'Set TCP static window size.'
                    tcp-window-type:
                        type: str
                        description: 'TCP window type to use for this protocol.'
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'

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
    - name: Configure protocol options.
      fmgr_firewall_profileprotocoloptions:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         firewall_profileprotocoloptions:
            comment: <value of string>
            name: <value of string>
            oversize-log: <value in [disable, enable]>
            replacemsg-group: <value of string>
            rpc-over-http: <value in [disable, enable]>
            switching-protocols-log: <value in [disable, enable]>
            feature-set: <value in [proxy, flow]>
            cifs:
               domain-controller: <value of string>
               file-filter:
                  entries:
                    -
                        action: <value in [log, block]>
                        comment: <value of string>
                        direction: <value in [any, incoming, outgoing]>
                        file-type: <value of string>
                        filter: <value of string>
                        protocol:
                          - cifs
                  log: <value in [disable, enable]>
                  status: <value in [disable, enable]>
               options:
                 - oversize
               oversize-limit: <value of integer>
               ports: <value of integer>
               scan-bzip2: <value in [disable, enable]>
               server-credential-type: <value in [none, credential-replication, credential-keytab]>
               server-keytab:
                 -
                     keytab: <value of string>
                     password: <value of string>
                     principal: <value of string>
               status: <value in [disable, enable]>
               tcp-window-maximum: <value of integer>
               tcp-window-minimum: <value of integer>
               tcp-window-size: <value of integer>
               tcp-window-type: <value in [system, static, dynamic]>
               uncompressed-nest-limit: <value of integer>
               uncompressed-oversize-limit: <value of integer>
            dns:
               ports: <value of integer>
               status: <value in [disable, enable]>
            ftp:
               comfort-amount: <value of integer>
               comfort-interval: <value of integer>
               inspect-all: <value in [disable, enable]>
               options:
                 - clientcomfort
                 - no-content-summary
                 - oversize
                 - splice
                 - bypass-rest-command
                 - bypass-mode-command
               oversize-limit: <value of integer>
               ports: <value of integer>
               scan-bzip2: <value in [disable, enable]>
               ssl-offloaded: <value in [no, yes]>
               status: <value in [disable, enable]>
               uncompressed-nest-limit: <value of integer>
               uncompressed-oversize-limit: <value of integer>
               stream-based-uncompressed-limit: <value of integer>
               tcp-window-maximum: <value of integer>
               tcp-window-minimum: <value of integer>
               tcp-window-size: <value of integer>
               tcp-window-type: <value in [system, static, dynamic]>
            http:
               block-page-status-code: <value of integer>
               comfort-amount: <value of integer>
               comfort-interval: <value of integer>
               fortinet-bar: <value in [disable, enable]>
               fortinet-bar-port: <value of integer>
               inspect-all: <value in [disable, enable]>
               options:
                 - oversize
                 - chunkedbypass
                 - clientcomfort
                 - no-content-summary
                 - servercomfort
               oversize-limit: <value of integer>
               ports: <value of integer>
               post-lang:
                 - jisx0201
                 - jisx0208
                 - jisx0212
                 - gb2312
                 - ksc5601-ex
                 - euc-jp
                 - sjis
                 - iso2022-jp
                 - iso2022-jp-1
                 - iso2022-jp-2
                 - euc-cn
                 - ces-gbk
                 - hz
                 - ces-big5
                 - euc-kr
                 - iso2022-jp-3
                 - iso8859-1
                 - tis620
                 - cp874
                 - cp1252
                 - cp1251
               proxy-after-tcp-handshake: <value in [disable, enable]>
               range-block: <value in [disable, enable]>
               retry-count: <value of integer>
               scan-bzip2: <value in [disable, enable]>
               ssl-offloaded: <value in [no, yes]>
               status: <value in [disable, enable]>
               stream-based-uncompressed-limit: <value of integer>
               streaming-content-bypass: <value in [disable, enable]>
               strip-x-forwarded-for: <value in [disable, enable]>
               switching-protocols: <value in [bypass, block]>
               tcp-window-maximum: <value of integer>
               tcp-window-minimum: <value of integer>
               tcp-window-size: <value of integer>
               tcp-window-type: <value in [system, static, dynamic]>
               tunnel-non-http: <value in [disable, enable]>
               uncompressed-nest-limit: <value of integer>
               uncompressed-oversize-limit: <value of integer>
               unknown-http-version: <value in [best-effort, reject, tunnel]>
            imap:
               inspect-all: <value in [disable, enable]>
               options:
                 - oversize
                 - fragmail
                 - no-content-summary
               oversize-limit: <value of integer>
               ports: <value of integer>
               proxy-after-tcp-handshake: <value in [disable, enable]>
               scan-bzip2: <value in [disable, enable]>
               ssl-offloaded: <value in [no, yes]>
               status: <value in [disable, enable]>
               uncompressed-nest-limit: <value of integer>
               uncompressed-oversize-limit: <value of integer>
            mail-signature:
               signature: <value of string>
               status: <value in [disable, enable]>
            mapi:
               options:
                 - fragmail
                 - oversize
                 - no-content-summary
               oversize-limit: <value of integer>
               ports: <value of integer>
               scan-bzip2: <value in [disable, enable]>
               status: <value in [disable, enable]>
               uncompressed-nest-limit: <value of integer>
               uncompressed-oversize-limit: <value of integer>
            nntp:
               inspect-all: <value in [disable, enable]>
               options:
                 - oversize
                 - no-content-summary
                 - splice
               oversize-limit: <value of integer>
               ports: <value of integer>
               proxy-after-tcp-handshake: <value in [disable, enable]>
               scan-bzip2: <value in [disable, enable]>
               status: <value in [disable, enable]>
               uncompressed-nest-limit: <value of integer>
               uncompressed-oversize-limit: <value of integer>
            pop3:
               inspect-all: <value in [disable, enable]>
               options:
                 - oversize
                 - fragmail
                 - no-content-summary
               oversize-limit: <value of integer>
               ports: <value of integer>
               proxy-after-tcp-handshake: <value in [disable, enable]>
               scan-bzip2: <value in [disable, enable]>
               ssl-offloaded: <value in [no, yes]>
               status: <value in [disable, enable]>
               uncompressed-nest-limit: <value of integer>
               uncompressed-oversize-limit: <value of integer>
            smtp:
               inspect-all: <value in [disable, enable]>
               options:
                 - oversize
                 - fragmail
                 - no-content-summary
                 - splice
               oversize-limit: <value of integer>
               ports: <value of integer>
               proxy-after-tcp-handshake: <value in [disable, enable]>
               scan-bzip2: <value in [disable, enable]>
               server-busy: <value in [disable, enable]>
               ssl-offloaded: <value in [no, yes]>
               status: <value in [disable, enable]>
               uncompressed-nest-limit: <value of integer>
               uncompressed-oversize-limit: <value of integer>
            ssh:
               comfort-amount: <value of integer>
               comfort-interval: <value of integer>
               options:
                 - oversize
                 - clientcomfort
                 - servercomfort
               oversize-limit: <value of integer>
               scan-bzip2: <value in [disable, enable]>
               uncompressed-nest-limit: <value of integer>
               uncompressed-oversize-limit: <value of integer>
               ssl-offloaded: <value in [no, yes]>
               stream-based-uncompressed-limit: <value of integer>
               tcp-window-maximum: <value of integer>
               tcp-window-minimum: <value of integer>
               tcp-window-size: <value of integer>
               tcp-window-type: <value in [system, static, dynamic]>

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
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options',
        '/pm/config/global/obj/firewall/profile-protocol-options'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}',
        '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}'
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
        'firewall_profileprotocoloptions': {
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
                'oversize-log': {
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
                'replacemsg-group': {
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
                'rpc-over-http': {
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
                'switching-protocols-log': {
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
                'feature-set': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False
                    },
                    'choices': [
                        'proxy',
                        'flow'
                    ],
                    'type': 'str'
                },
                'cifs': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'domain-controller': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'file-filter': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'entries': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': False
                                    },
                                    'type': 'list',
                                    'options': {
                                        'action': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False
                                            },
                                            'choices': [
                                                'log',
                                                'block'
                                            ],
                                            'type': 'str'
                                        },
                                        'comment': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False
                                            },
                                            'type': 'str'
                                        },
                                        'direction': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False
                                            },
                                            'choices': [
                                                'any',
                                                'incoming',
                                                'outgoing'
                                            ],
                                            'type': 'str'
                                        },
                                        'file-type': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False
                                            },
                                            'type': 'str'
                                        },
                                        'filter': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False
                                            },
                                            'type': 'str'
                                        },
                                        'protocol': {
                                            'required': False,
                                            'revision': {
                                                '6.4.5': True,
                                                '7.0.0': False
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'cifs'
                                            ]
                                        }
                                    }
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': False
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
                                        '7.0.0': False
                                    },
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'scan-bzip2': {
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
                        'server-credential-type': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'credential-replication',
                                'credential-keytab'
                            ],
                            'type': 'str'
                        },
                        'server-keytab': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'options': {
                                'keytab': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True
                                    },
                                    'type': 'str'
                                },
                                'password': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True
                                    },
                                    'type': 'str'
                                },
                                'principal': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True
                                    },
                                    'type': 'str'
                                }
                            }
                        },
                        'status': {
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
                        'tcp-window-maximum': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-minimum': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-size': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-type': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'system',
                                'static',
                                'dynamic'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'dns': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'status': {
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
                        }
                    }
                },
                'ftp': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'comfort-amount': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'comfort-interval': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'inspect-all': {
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
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'clientcomfort',
                                'no-content-summary',
                                'oversize',
                                'splice',
                                'bypass-rest-command',
                                'bypass-mode-command'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'scan-bzip2': {
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
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
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
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'stream-based-uncompressed-limit': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-maximum': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-minimum': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-size': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-type': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'system',
                                'static',
                                'dynamic'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'http': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'block-page-status-code': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'comfort-amount': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'comfort-interval': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'fortinet-bar': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'fortinet-bar-port': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': False
                            },
                            'type': 'int'
                        },
                        'inspect-all': {
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
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'chunkedbypass',
                                'clientcomfort',
                                'no-content-summary',
                                'servercomfort'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'post-lang': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'jisx0201',
                                'jisx0208',
                                'jisx0212',
                                'gb2312',
                                'ksc5601-ex',
                                'euc-jp',
                                'sjis',
                                'iso2022-jp',
                                'iso2022-jp-1',
                                'iso2022-jp-2',
                                'euc-cn',
                                'ces-gbk',
                                'hz',
                                'ces-big5',
                                'euc-kr',
                                'iso2022-jp-3',
                                'iso8859-1',
                                'tis620',
                                'cp874',
                                'cp1252',
                                'cp1251'
                            ]
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
                        'range-block': {
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
                        'retry-count': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'scan-bzip2': {
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
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
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
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'stream-based-uncompressed-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'streaming-content-bypass': {
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
                        'strip-x-forwarded-for': {
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
                        'switching-protocols': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'bypass',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'tcp-window-maximum': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-minimum': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-size': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-type': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'system',
                                'static',
                                'dynamic'
                            ],
                            'type': 'str'
                        },
                        'tunnel-non-http': {
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
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'unknown-http-version': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'best-effort',
                                'reject',
                                'tunnel'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'imap': {
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
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'fragmail',
                                'no-content-summary'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
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
                        'scan-bzip2': {
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
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
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
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'mail-signature': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'signature': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
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
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'mapi': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'fragmail',
                                'oversize',
                                'no-content-summary'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'ports': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'scan-bzip2': {
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
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'nntp': {
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
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'no-content-summary',
                                'splice'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
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
                        'scan-bzip2': {
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
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'pop3': {
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
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'fragmail',
                                'no-content-summary'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
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
                        'scan-bzip2': {
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
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
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
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'smtp': {
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
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'fragmail',
                                'no-content-summary',
                                'splice'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
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
                        'scan-bzip2': {
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
                        'server-busy': {
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
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
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
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'ssh': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'comfort-amount': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'comfort-interval': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'oversize',
                                'clientcomfort',
                                'servercomfort'
                            ]
                        },
                        'oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'scan-bzip2': {
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
                        'uncompressed-nest-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'uncompressed-oversize-limit': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'ssl-offloaded': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'no',
                                'yes'
                            ],
                            'type': 'str'
                        },
                        'stream-based-uncompressed-limit': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-maximum': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-minimum': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-size': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'tcp-window-type': {
                            'required': False,
                            'revision': {
                                '7.0.0': True
                            },
                            'choices': [
                                'system',
                                'static',
                                'dynamic'
                            ],
                            'type': 'str'
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profileprotocoloptions'),
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
