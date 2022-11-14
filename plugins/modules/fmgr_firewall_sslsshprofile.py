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
    firewall_sslsshprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            caname:
                type: str
                description: no description
            comment:
                type: str
                description: no description
            mapi-over-https:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: no description
            rpc-over-https:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            server-cert:
                type: str
                description: no description
            server-cert-mode:
                type: str
                description: no description
                choices:
                    - 're-sign'
                    - 'replace'
            ssl-anomalies-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-exempt:
                description: no description
                type: list
                suboptions:
                    address:
                        type: str
                        description: no description
                    address6:
                        type: str
                        description: no description
                    fortiguard-category:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    regex:
                        type: str
                        description: no description
                    type:
                        type: str
                        description: no description
                        choices:
                            - 'fortiguard-category'
                            - 'address'
                            - 'address6'
                            - 'wildcard-fqdn'
                            - 'regex'
                            - 'finger-print'
                    wildcard-fqdn:
                        type: str
                        description: no description
            ssl-exemptions-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-server:
                description: no description
                type: list
                suboptions:
                    ftps-client-cert-request:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    https-client-cert-request:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    id:
                        type: int
                        description: no description
                    imaps-client-cert-request:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ip:
                        type: str
                        description: no description
                    pop3s-client-cert-request:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    smtps-client-cert-request:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ssl-other-client-cert-request:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ftps-client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    https-client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    imaps-client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    pop3s-client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    smtps-client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ssl-other-client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
            untrusted-caname:
                type: str
                description: no description
            use-ssl-server:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            whitelist:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-blacklisted-certificates:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-negotiation-log:
                type: str
                description: no description
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
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        description: no description
                        type: int
                    revoked-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    min-allowed-ssl-version:
                        type: str
                        description: no description
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    unsupported-ssl-version:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
            https:
                description: no description
                type: dict
                required: false
                suboptions:
                    cert-validation-failure:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'certificate-inspection'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-probe-failure:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'allow'
                    min-allowed-ssl-version:
                        type: str
                        description: no description
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    unsupported-ssl-version:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
            imaps:
                description: no description
                type: dict
                required: false
                suboptions:
                    cert-validation-failure:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported-ssl-version:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
            pop3s:
                description: no description
                type: dict
                required: false
                suboptions:
                    cert-validation-failure:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported-ssl-version:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
            smtps:
                description: no description
                type: dict
                required: false
                suboptions:
                    cert-validation-failure:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported-ssl-version:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
            ssh:
                description: no description
                type: dict
                required: false
                suboptions:
                    inspect-all:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    ports:
                        description: no description
                        type: int
                    proxy-after-tcp-handshake:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    ssh-algorithm:
                        type: str
                        description: no description
                        choices:
                            - 'compatible'
                            - 'high-encryption'
                    ssh-tun-policy-check:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-version:
                        type: str
                        description: no description
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
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    inspect-all:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'certificate-inspection'
                            - 'deep-inspection'
                    revoked-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    unsupported-ssl-cipher:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported-ssl-negotiation:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-probe-failure:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'allow'
                    min-allowed-ssl-version:
                        type: str
                        description: no description
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    unsupported-ssl-version:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
            allowlist:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            block-blocklisted-certificates:
                type: str
                description: no description
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
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert-validation-timeout:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client-certificate:
                        type: str
                        description: no description
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    proxy-after-tcp-handshake:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni-server-cert-check:
                        type: str
                        description: no description
                        choices:
                            - 'enable'
                            - 'strict'
                            - 'disable'
                    status:
                        type: str
                        description: no description
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported-ssl-cipher:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'allow'
                    unsupported-ssl-negotiation:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'allow'
                    untrusted-server-cert:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported-ssl-version:
                        type: str
                        description: no description
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
            supported-alpn:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'http1-1'
                    - 'http2'
                    - 'all'
            ssl-anomaly-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-exemption-ip-rating:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-exemption-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-handshake-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-server-cert-log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'

'''

EXAMPLES = '''
 - name: gathering fortimanager facts
   hosts: fortimanager00
   gather_facts: no
   connection: httpapi
   collections:
     - fortinet.fortimanager
   vars:
     ansible_httpapi_use_ssl: True
     ansible_httpapi_validate_certs: False
     ansible_httpapi_port: 443
   tasks:
    - name: retrieve all the SSL/SSH protocol options
      fmgr_fact:
        facts:
            selector: 'firewall_sslsshprofile'
            params:
                adom: 'ansible'
                ssl-ssh-profile: 'your_value'
 - hosts: fortimanager00
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
         adom: ansible
         state: present
         firewall_sslsshprofile:
            comment: 'ansible-comment1'
            mapi-over-https: disable #<value in [disable, enable]>
            name: 'ansible-test'
            use-ssl-server: disable #<value in [disable, enable]>
            whitelist: enable #<value in [disable, enable]>
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
                '7.0.0': True,
                '7.2.0': True
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
                        '7.0.0': True,
                        '7.2.0': True
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
                        '7.0.0': True,
                        '7.2.0': True
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
                        '7.0.0': True,
                        '7.2.0': True
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
                        '7.0.0': True,
                        '7.2.0': True
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
                        '7.0.0': True,
                        '7.2.0': True
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
                        '7.0.0': True,
                        '7.2.0': False
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
                        '7.0.0': True,
                        '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'fortiguard-category',
                                'address',
                                'address6',
                                'wildcard-fqdn',
                                'regex',
                                'finger-print'
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
                                '7.0.0': True,
                                '7.2.0': True
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
                        '7.0.0': True,
                        '7.2.0': False
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
                        '7.0.0': True,
                        '7.2.0': True
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
                                '7.0.0': False,
                                '7.2.0': False
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
                                '7.0.0': False,
                                '7.2.0': False
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': False,
                                '7.2.0': False
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': False,
                                '7.2.0': False
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
                                '7.0.0': False,
                                '7.2.0': False
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
                                '7.0.0': False,
                                '7.2.0': False
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                        '7.0.0': True,
                        '7.2.0': True
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
                        '7.0.0': True,
                        '7.2.0': True
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
                        '7.0.0': False,
                        '7.2.0': False
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
                        '7.0.0': False,
                        '7.2.0': False
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
                        '7.0.0': True,
                        '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'min-allowed-ssl-version': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'ssl-3.0',
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2',
                                'tls-1.3'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-version': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'block',
                                'allow',
                                'inspect'
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
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
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'block',
                                'allow'
                            ],
                            'type': 'str'
                        },
                        'min-allowed-ssl-version': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'ssl-3.0',
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2',
                                'tls-1.3'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-version': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'block',
                                'allow',
                                'inspect'
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
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
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-version': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'block',
                                'allow',
                                'inspect'
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
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
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-version': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'block',
                                'allow',
                                'inspect'
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
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
                        'revoked-server-cert': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-version': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'block',
                                'allow',
                                'inspect'
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'proxy-after-tcp-handshake': {
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
                        'ssh-algorithm': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.2.0': True
                            },
                            'choices': [
                                'block',
                                'allow'
                            ],
                            'type': 'str'
                        },
                        'min-allowed-ssl-version': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'ssl-3.0',
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2',
                                'tls-1.3'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-version': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'block',
                                'allow',
                                'inspect'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'allowlist': {
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
                'block-blocklisted-certificates': {
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
                'dot': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'required': False,
                            'revision': {
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
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
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'choices': [
                                'allow',
                                'block',
                                'ignore'
                            ],
                            'type': 'str'
                        },
                        'unsupported-ssl-version': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'block',
                                'allow',
                                'inspect'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'supported-alpn': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'choices': [
                        'none',
                        'http1-1',
                        'http2',
                        'all'
                    ],
                    'type': 'str'
                },
                'ssl-anomaly-log': {
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
                'ssl-exemption-ip-rating': {
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
                'ssl-exemption-log': {
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
                'ssl-handshake-log': {
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
                'ssl-server-cert-log': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
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
