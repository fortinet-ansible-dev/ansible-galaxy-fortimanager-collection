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
module: fmgr_webfilter_profile
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
    webfilter_profile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: no description
            extended-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            https-replacemsg:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            inspection-mode:
                type: str
                description: no description
                choices:
                    - 'proxy'
                    - 'flow-based'
                    - 'dns'
            log-all-url:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: no description
            options:
                description: no description
                type: list
                choices:
                 - block-invalid-url
                 - jscript
                 - js
                 - vbs
                 - unknown
                 - wf-referer
                 - https-scan
                 - intrinsic
                 - wf-cookie
                 - per-user-bwl
                 - activexfilter
                 - cookiefilter
                 - https-url-scan
                 - javafilter
                 - rangeblock
                 - contenttype-check
                 - per-user-bal
            ovrd-perm:
                description: no description
                type: list
                choices:
                 - bannedword-override
                 - urlfilter-override
                 - fortiguard-wf-override
                 - contenttype-check-override
            post-action:
                type: str
                description: no description
                choices:
                    - 'normal'
                    - 'comfort'
                    - 'block'
            replacemsg-group:
                type: str
                description: no description
            web-content-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-extended-all-action-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-filter-activex-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-filter-applet-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-filter-command-block-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-filter-cookie-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-filter-cookie-removal-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-filter-js-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-filter-jscript-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-filter-referer-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-filter-unknown-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-filter-vbs-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-ftgd-err-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-ftgd-quota-usage:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-invalid-domain-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            web-url-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            wisp:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            wisp-algorithm:
                type: str
                description: no description
                choices:
                    - 'auto-learning'
                    - 'primary-secondary'
                    - 'round-robin'
            wisp-servers:
                type: str
                description: no description
            youtube-channel-filter:
                description: no description
                type: list
                suboptions:
                    channel-id:
                        type: str
                        description: no description
                    comment:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
            youtube-channel-status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'blacklist'
                    - 'whitelist'
            feature-set:
                type: str
                description: no description
                choices:
                    - 'proxy'
                    - 'flow'
            web-antiphishing-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            antiphish:
                description: no description
                type: dict
                required: false
                suboptions:
                    check-basic-auth:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    check-uri:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    check-username-only:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    custom-patterns:
                        description: no description
                        type: list
                        suboptions:
                            category:
                                type: str
                                description: no description
                                choices:
                                    - 'username'
                                    - 'password'
                            pattern:
                                type: str
                                description: no description
                            type:
                                type: str
                                description: no description
                                choices:
                                    - 'regex'
                                    - 'literal'
                    default-action:
                        type: str
                        description: no description
                        choices:
                            - 'log'
                            - 'block'
                            - 'exempt'
                    domain-controller:
                        type: str
                        description: no description
                    inspection-entries:
                        description: no description
                        type: list
                        suboptions:
                            action:
                                type: str
                                description: no description
                                choices:
                                    - 'log'
                                    - 'block'
                                    - 'exempt'
                            fortiguard-category:
                                description: no description
                                type: str
                            name:
                                type: str
                                description: no description
                    max-body-len:
                        type: int
                        description: no description
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    authentication:
                        type: str
                        description: no description
                        choices:
                            - 'domain-controller'
                            - 'ldap'
                    ldap:
                        type: str
                        description: no description
            ftgd-wf:
                description: no description
                type: dict
                required: false
                suboptions:
                    exempt-quota:
                        type: str
                        description: no description
                    filters:
                        description: no description
                        type: list
                        suboptions:
                            action:
                                type: str
                                description: no description
                                choices:
                                    - 'block'
                                    - 'monitor'
                                    - 'warning'
                                    - 'authenticate'
                            auth-usr-grp:
                                type: str
                                description: no description
                            category:
                                type: str
                                description: no description
                            id:
                                type: int
                                description: no description
                            log:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            override-replacemsg:
                                type: str
                                description: no description
                            warn-duration:
                                type: str
                                description: no description
                            warning-duration-type:
                                type: str
                                description: no description
                                choices:
                                    - 'session'
                                    - 'timeout'
                            warning-prompt:
                                type: str
                                description: no description
                                choices:
                                    - 'per-domain'
                                    - 'per-category'
                    max-quota-timeout:
                        type: int
                        description: no description
                    options:
                        description: no description
                        type: list
                        choices:
                         - error-allow
                         - http-err-detail
                         - rate-image-urls
                         - strict-blocking
                         - rate-server-ip
                         - redir-block
                         - connect-request-bypass
                         - log-all-url
                         - ftgd-disable
                    ovrd:
                        type: str
                        description: no description
                    quota:
                        description: no description
                        type: list
                        suboptions:
                            category:
                                type: str
                                description: no description
                            duration:
                                type: str
                                description: no description
                            id:
                                type: int
                                description: no description
                            override-replacemsg:
                                type: str
                                description: no description
                            type:
                                type: str
                                description: no description
                                choices:
                                    - 'time'
                                    - 'traffic'
                            unit:
                                type: str
                                description: no description
                                choices:
                                    - 'B'
                                    - 'KB'
                                    - 'MB'
                                    - 'GB'
                            value:
                                type: int
                                description: no description
                    rate-crl-urls:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    rate-css-urls:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    rate-image-urls:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    rate-javascript-urls:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            override:
                description: no description
                type: dict
                required: false
                suboptions:
                    ovrd-cookie:
                        type: str
                        description: no description
                        choices:
                            - 'deny'
                            - 'allow'
                    ovrd-dur:
                        type: str
                        description: no description
                    ovrd-dur-mode:
                        type: str
                        description: no description
                        choices:
                            - 'constant'
                            - 'ask'
                    ovrd-scope:
                        type: str
                        description: no description
                        choices:
                            - 'user'
                            - 'user-group'
                            - 'ip'
                            - 'ask'
                            - 'browser'
                    ovrd-user-group:
                        type: str
                        description: no description
                    profile:
                        type: str
                        description: no description
                    profile-attribute:
                        type: str
                        description: no description
                        choices:
                            - 'User-Name'
                            - 'User-Password'
                            - 'CHAP-Password'
                            - 'NAS-IP-Address'
                            - 'NAS-Port'
                            - 'Service-Type'
                            - 'Framed-Protocol'
                            - 'Framed-IP-Address'
                            - 'Framed-IP-Netmask'
                            - 'Framed-Routing'
                            - 'Filter-Id'
                            - 'Framed-MTU'
                            - 'Framed-Compression'
                            - 'Login-IP-Host'
                            - 'Login-Service'
                            - 'Login-TCP-Port'
                            - 'Reply-Message'
                            - 'Callback-Number'
                            - 'Callback-Id'
                            - 'Framed-Route'
                            - 'Framed-IPX-Network'
                            - 'State'
                            - 'Class'
                            - 'Vendor-Specific'
                            - 'Session-Timeout'
                            - 'Idle-Timeout'
                            - 'Termination-Action'
                            - 'Called-Station-Id'
                            - 'Calling-Station-Id'
                            - 'NAS-Identifier'
                            - 'Proxy-State'
                            - 'Login-LAT-Service'
                            - 'Login-LAT-Node'
                            - 'Login-LAT-Group'
                            - 'Framed-AppleTalk-Link'
                            - 'Framed-AppleTalk-Network'
                            - 'Framed-AppleTalk-Zone'
                            - 'Acct-Status-Type'
                            - 'Acct-Delay-Time'
                            - 'Acct-Input-Octets'
                            - 'Acct-Output-Octets'
                            - 'Acct-Session-Id'
                            - 'Acct-Authentic'
                            - 'Acct-Session-Time'
                            - 'Acct-Input-Packets'
                            - 'Acct-Output-Packets'
                            - 'Acct-Terminate-Cause'
                            - 'Acct-Multi-Session-Id'
                            - 'Acct-Link-Count'
                            - 'CHAP-Challenge'
                            - 'NAS-Port-Type'
                            - 'Port-Limit'
                            - 'Login-LAT-Port'
                    profile-type:
                        type: str
                        description: no description
                        choices:
                            - 'list'
                            - 'radius'
            url-extraction:
                description: no description
                type: dict
                required: false
                suboptions:
                    redirect-header:
                        type: str
                        description: no description
                    redirect-no-content:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    redirect-url:
                        type: str
                        description: no description
                    server-fqdn:
                        type: str
                        description: no description
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
            web:
                description: no description
                type: dict
                required: false
                suboptions:
                    blacklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    bword-table:
                        type: str
                        description: no description
                    bword-threshold:
                        type: int
                        description: no description
                    content-header-list:
                        type: str
                        description: no description
                    keyword-match:
                        description: no description
                        type: str
                    log-search:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    safe-search:
                        description: no description
                        type: list
                        choices:
                         - google
                         - yahoo
                         - bing
                         - url
                         - header
                    urlfilter-table:
                        type: str
                        description: no description
                    whitelist:
                        description: no description
                        type: list
                        choices:
                         - exempt-av
                         - exempt-webcontent
                         - exempt-activex-java-cookie
                         - exempt-dlp
                         - exempt-rangeblock
                         - extended-log-others
                    youtube-restrict:
                        type: str
                        description: no description
                        choices:
                            - 'strict'
                            - 'none'
                            - 'moderate'
                    allowlist:
                        description: no description
                        type: list
                        choices:
                         - exempt-av
                         - exempt-webcontent
                         - exempt-activex-java-cookie
                         - exempt-dlp
                         - exempt-rangeblock
                         - extended-log-others
                    blocklist:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    vimeo-restrict:
                        type: str
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
      fmgr_webfilter_profile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         webfilter_profile:
            comment: <value of string>
            extended-log: <value in [disable, enable]>
            https-replacemsg: <value in [disable, enable]>
            inspection-mode: <value in [proxy, flow-based, dns]>
            log-all-url: <value in [disable, enable]>
            name: <value of string>
            options:
              - block-invalid-url
              - jscript
              - js
              - vbs
              - unknown
              - wf-referer
              - https-scan
              - intrinsic
              - wf-cookie
              - per-user-bwl
              - activexfilter
              - cookiefilter
              - https-url-scan
              - javafilter
              - rangeblock
              - contenttype-check
              - per-user-bal
            ovrd-perm:
              - bannedword-override
              - urlfilter-override
              - fortiguard-wf-override
              - contenttype-check-override
            post-action: <value in [normal, comfort, block]>
            replacemsg-group: <value of string>
            web-content-log: <value in [disable, enable]>
            web-extended-all-action-log: <value in [disable, enable]>
            web-filter-activex-log: <value in [disable, enable]>
            web-filter-applet-log: <value in [disable, enable]>
            web-filter-command-block-log: <value in [disable, enable]>
            web-filter-cookie-log: <value in [disable, enable]>
            web-filter-cookie-removal-log: <value in [disable, enable]>
            web-filter-js-log: <value in [disable, enable]>
            web-filter-jscript-log: <value in [disable, enable]>
            web-filter-referer-log: <value in [disable, enable]>
            web-filter-unknown-log: <value in [disable, enable]>
            web-filter-vbs-log: <value in [disable, enable]>
            web-ftgd-err-log: <value in [disable, enable]>
            web-ftgd-quota-usage: <value in [disable, enable]>
            web-invalid-domain-log: <value in [disable, enable]>
            web-url-log: <value in [disable, enable]>
            wisp: <value in [disable, enable]>
            wisp-algorithm: <value in [auto-learning, primary-secondary, round-robin]>
            wisp-servers: <value of string>
            youtube-channel-filter:
              -
                  channel-id: <value of string>
                  comment: <value of string>
                  id: <value of integer>
            youtube-channel-status: <value in [disable, blacklist, whitelist]>
            feature-set: <value in [proxy, flow]>
            web-antiphishing-log: <value in [disable, enable]>
            antiphish:
               check-basic-auth: <value in [disable, enable]>
               check-uri: <value in [disable, enable]>
               check-username-only: <value in [disable, enable]>
               custom-patterns:
                 -
                     category: <value in [username, password]>
                     pattern: <value of string>
                     type: <value in [regex, literal]>
               default-action: <value in [log, block, exempt]>
               domain-controller: <value of string>
               inspection-entries:
                 -
                     action: <value in [log, block, exempt]>
                     fortiguard-category: <value of string>
                     name: <value of string>
               max-body-len: <value of integer>
               status: <value in [disable, enable]>
               authentication: <value in [domain-controller, ldap]>
               ldap: <value of string>
            ftgd-wf:
               exempt-quota: <value of string>
               filters:
                 -
                     action: <value in [block, monitor, warning, ...]>
                     auth-usr-grp: <value of string>
                     category: <value of string>
                     id: <value of integer>
                     log: <value in [disable, enable]>
                     override-replacemsg: <value of string>
                     warn-duration: <value of string>
                     warning-duration-type: <value in [session, timeout]>
                     warning-prompt: <value in [per-domain, per-category]>
               max-quota-timeout: <value of integer>
               options:
                 - error-allow
                 - http-err-detail
                 - rate-image-urls
                 - strict-blocking
                 - rate-server-ip
                 - redir-block
                 - connect-request-bypass
                 - log-all-url
                 - ftgd-disable
               ovrd: <value of string>
               quota:
                 -
                     category: <value of string>
                     duration: <value of string>
                     id: <value of integer>
                     override-replacemsg: <value of string>
                     type: <value in [time, traffic]>
                     unit: <value in [B, KB, MB, ...]>
                     value: <value of integer>
               rate-crl-urls: <value in [disable, enable]>
               rate-css-urls: <value in [disable, enable]>
               rate-image-urls: <value in [disable, enable]>
               rate-javascript-urls: <value in [disable, enable]>
            override:
               ovrd-cookie: <value in [deny, allow]>
               ovrd-dur: <value of string>
               ovrd-dur-mode: <value in [constant, ask]>
               ovrd-scope: <value in [user, user-group, ip, ...]>
               ovrd-user-group: <value of string>
               profile: <value of string>
               profile-attribute: <value in [User-Name, User-Password, CHAP-Password, ...]>
               profile-type: <value in [list, radius]>
            url-extraction:
               redirect-header: <value of string>
               redirect-no-content: <value in [disable, enable]>
               redirect-url: <value of string>
               server-fqdn: <value of string>
               status: <value in [disable, enable]>
            web:
               blacklist: <value in [disable, enable]>
               bword-table: <value of string>
               bword-threshold: <value of integer>
               content-header-list: <value of string>
               keyword-match: <value of string>
               log-search: <value in [disable, enable]>
               safe-search:
                 - google
                 - yahoo
                 - bing
                 - url
                 - header
               urlfilter-table: <value of string>
               whitelist:
                 - exempt-av
                 - exempt-webcontent
                 - exempt-activex-java-cookie
                 - exempt-dlp
                 - exempt-rangeblock
                 - extended-log-others
               youtube-restrict: <value in [strict, none, moderate]>
               allowlist:
                 - exempt-av
                 - exempt-webcontent
                 - exempt-activex-java-cookie
                 - exempt-dlp
                 - exempt-rangeblock
                 - extended-log-others
               blocklist: <value in [disable, enable]>
               vimeo-restrict: <value of string>

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
        '/pm/config/adom/{adom}/obj/webfilter/profile',
        '/pm/config/global/obj/webfilter/profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}',
        '/pm/config/global/obj/webfilter/profile/{profile}'
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
        'webfilter_profile': {
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
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'extended-log': {
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
                'https-replacemsg': {
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
                'inspection-mode': {
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
                        'proxy',
                        'flow-based',
                        'dns'
                    ],
                    'type': 'str'
                },
                'log-all-url': {
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
                'options': {
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
                        'block-invalid-url',
                        'jscript',
                        'js',
                        'vbs',
                        'unknown',
                        'wf-referer',
                        'https-scan',
                        'intrinsic',
                        'wf-cookie',
                        'per-user-bwl',
                        'activexfilter',
                        'cookiefilter',
                        'https-url-scan',
                        'javafilter',
                        'rangeblock',
                        'contenttype-check',
                        'per-user-bal'
                    ]
                },
                'ovrd-perm': {
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
                        'bannedword-override',
                        'urlfilter-override',
                        'fortiguard-wf-override',
                        'contenttype-check-override'
                    ]
                },
                'post-action': {
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
                        'normal',
                        'comfort',
                        'block'
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
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'web-content-log': {
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
                'web-extended-all-action-log': {
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
                'web-filter-activex-log': {
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
                'web-filter-applet-log': {
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
                'web-filter-command-block-log': {
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
                'web-filter-cookie-log': {
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
                'web-filter-cookie-removal-log': {
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
                'web-filter-js-log': {
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
                'web-filter-jscript-log': {
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
                'web-filter-referer-log': {
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
                'web-filter-unknown-log': {
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
                'web-filter-vbs-log': {
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
                'web-ftgd-err-log': {
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
                'web-ftgd-quota-usage': {
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
                'web-invalid-domain-log': {
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
                'web-url-log': {
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
                'wisp': {
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
                'wisp-algorithm': {
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
                        'auto-learning',
                        'primary-secondary',
                        'round-robin'
                    ],
                    'type': 'str'
                },
                'wisp-servers': {
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
                'youtube-channel-filter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'type': 'list',
                    'options': {
                        'channel-id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': False,
                                '7.2.0': False
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
                                '7.0.0': False,
                                '7.2.0': False
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
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'int'
                        }
                    }
                },
                'youtube-channel-status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': False,
                        '7.2.0': False
                    },
                    'choices': [
                        'disable',
                        'blacklist',
                        'whitelist'
                    ],
                    'type': 'str'
                },
                'feature-set': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'proxy',
                        'flow'
                    ],
                    'type': 'str'
                },
                'web-antiphishing-log': {
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
                'antiphish': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'check-basic-auth': {
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
                        'check-uri': {
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
                        'check-username-only': {
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
                        'custom-patterns': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'category': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'username',
                                        'password'
                                    ],
                                    'type': 'str'
                                },
                                'pattern': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'type': {
                                    'required': False,
                                    'revision': {
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'regex',
                                        'literal'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'default-action': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'log',
                                'block',
                                'exempt'
                            ],
                            'type': 'str'
                        },
                        'domain-controller': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'inspection-entries': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'log',
                                        'block',
                                        'exempt'
                                    ],
                                    'type': 'str'
                                },
                                'fortiguard-category': {
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
                                }
                            }
                        },
                        'max-body-len': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'status': {
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
                        'authentication': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'domain-controller',
                                'ldap'
                            ],
                            'type': 'str'
                        },
                        'ldap': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'ftgd-wf': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'exempt-quota': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'filters': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'block',
                                        'monitor',
                                        'warning',
                                        'authenticate'
                                    ],
                                    'type': 'str'
                                },
                                'auth-usr-grp': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'category': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'log': {
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
                                'override-replacemsg': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'warn-duration': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'warning-duration-type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'session',
                                        'timeout'
                                    ],
                                    'type': 'str'
                                },
                                'warning-prompt': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'per-domain',
                                        'per-category'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'max-quota-timeout': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'options': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'error-allow',
                                'http-err-detail',
                                'rate-image-urls',
                                'strict-blocking',
                                'rate-server-ip',
                                'redir-block',
                                'connect-request-bypass',
                                'log-all-url',
                                'ftgd-disable'
                            ]
                        },
                        'ovrd': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'quota': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'category': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'duration': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'override-replacemsg': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'type': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'time',
                                        'traffic'
                                    ],
                                    'type': 'str'
                                },
                                'unit': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'B',
                                        'KB',
                                        'MB',
                                        'GB'
                                    ],
                                    'type': 'str'
                                },
                                'value': {
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
                        'rate-crl-urls': {
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
                        'rate-css-urls': {
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
                        'rate-image-urls': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'rate-javascript-urls': {
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
                        }
                    }
                },
                'override': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'ovrd-cookie': {
                            'required': False,
                            'revision': {
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
                        'ovrd-dur': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ovrd-dur-mode': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'constant',
                                'ask'
                            ],
                            'type': 'str'
                        },
                        'ovrd-scope': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'user',
                                'user-group',
                                'ip',
                                'ask',
                                'browser'
                            ],
                            'type': 'str'
                        },
                        'ovrd-user-group': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'profile': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'profile-attribute': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'User-Name',
                                'User-Password',
                                'CHAP-Password',
                                'NAS-IP-Address',
                                'NAS-Port',
                                'Service-Type',
                                'Framed-Protocol',
                                'Framed-IP-Address',
                                'Framed-IP-Netmask',
                                'Framed-Routing',
                                'Filter-Id',
                                'Framed-MTU',
                                'Framed-Compression',
                                'Login-IP-Host',
                                'Login-Service',
                                'Login-TCP-Port',
                                'Reply-Message',
                                'Callback-Number',
                                'Callback-Id',
                                'Framed-Route',
                                'Framed-IPX-Network',
                                'State',
                                'Class',
                                'Vendor-Specific',
                                'Session-Timeout',
                                'Idle-Timeout',
                                'Termination-Action',
                                'Called-Station-Id',
                                'Calling-Station-Id',
                                'NAS-Identifier',
                                'Proxy-State',
                                'Login-LAT-Service',
                                'Login-LAT-Node',
                                'Login-LAT-Group',
                                'Framed-AppleTalk-Link',
                                'Framed-AppleTalk-Network',
                                'Framed-AppleTalk-Zone',
                                'Acct-Status-Type',
                                'Acct-Delay-Time',
                                'Acct-Input-Octets',
                                'Acct-Output-Octets',
                                'Acct-Session-Id',
                                'Acct-Authentic',
                                'Acct-Session-Time',
                                'Acct-Input-Packets',
                                'Acct-Output-Packets',
                                'Acct-Terminate-Cause',
                                'Acct-Multi-Session-Id',
                                'Acct-Link-Count',
                                'CHAP-Challenge',
                                'NAS-Port-Type',
                                'Port-Limit',
                                'Login-LAT-Port'
                            ],
                            'type': 'str'
                        },
                        'profile-type': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'list',
                                'radius'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'url-extraction': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'redirect-header': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'redirect-no-content': {
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
                        'redirect-url': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'server-fqdn': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'status': {
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
                        }
                    }
                },
                'web': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'blacklist': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'bword-table': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'bword-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'content-header-list': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'keyword-match': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'log-search': {
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
                        'safe-search': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'google',
                                'yahoo',
                                'bing',
                                'url',
                                'header'
                            ]
                        },
                        'urlfilter-table': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'whitelist': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': False,
                                '7.2.0': False
                            },
                            'type': 'list',
                            'choices': [
                                'exempt-av',
                                'exempt-webcontent',
                                'exempt-activex-java-cookie',
                                'exempt-dlp',
                                'exempt-rangeblock',
                                'extended-log-others'
                            ]
                        },
                        'youtube-restrict': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': False,
                                '7.2.0': True
                            },
                            'choices': [
                                'strict',
                                'none',
                                'moderate'
                            ],
                            'type': 'str'
                        },
                        'allowlist': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'exempt-av',
                                'exempt-webcontent',
                                'exempt-activex-java-cookie',
                                'exempt-dlp',
                                'exempt-rangeblock',
                                'extended-log-others'
                            ]
                        },
                        'blocklist': {
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
                        'vimeo-restrict': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile'),
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
