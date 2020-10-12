#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2020 Fortinet, Inc.
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
module: fmgr_firewall_vip6_dynamicmapping
short_description: no description
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
    vip6:
        description: the parameter (vip6) in requested url
        type: str
        required: true
    firewall_vip6_dynamicmapping:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            _scope:
                description: no description
                type: list
                suboptions:
                    name:
                        type: str
                        description: no description
                    vdom:
                        type: str
                        description: no description
            arp-reply:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            color:
                type: int
                description: no description
            comment:
                type: str
                description: no description
            extip:
                type: str
                description: no description
            extport:
                type: str
                description: no description
            http-cookie-age:
                type: int
                description: no description
            http-cookie-domain:
                type: str
                description: no description
            http-cookie-domain-from-host:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            http-cookie-generation:
                type: int
                description: no description
            http-cookie-path:
                type: str
                description: no description
            http-cookie-share:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'same-ip'
            http-ip-header:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            http-ip-header-name:
                type: str
                description: no description
            http-multiplex:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            https-cookie-secure:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: int
                description: no description
            ldb-method:
                type: str
                description: no description
                choices:
                    - 'static'
                    - 'round-robin'
                    - 'weighted'
                    - 'least-session'
                    - 'least-rtt'
                    - 'first-alive'
                    - 'http-host'
            mappedip:
                type: str
                description: no description
            mappedport:
                type: str
                description: no description
            max-embryonic-connections:
                type: int
                description: no description
            monitor:
                type: str
                description: no description
            outlook-web-access:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            persistence:
                type: str
                description: no description
                choices:
                    - 'none'
                    - 'http-cookie'
                    - 'ssl-session-id'
            portforward:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            protocol:
                type: str
                description: no description
                choices:
                    - 'tcp'
                    - 'udp'
                    - 'sctp'
            server-type:
                type: str
                description: no description
                choices:
                    - 'http'
                    - 'https'
                    - 'ssl'
                    - 'tcp'
                    - 'udp'
                    - 'ip'
                    - 'imaps'
                    - 'pop3s'
                    - 'smtps'
            src-filter:
                description: no description
                type: str
            ssl-algorithm:
                type: str
                description: no description
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
                    - 'custom'
            ssl-certificate:
                type: str
                description: no description
            ssl-client-fallback:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-client-renegotiation:
                type: str
                description: no description
                choices:
                    - 'deny'
                    - 'allow'
                    - 'secure'
            ssl-client-session-state-max:
                type: int
                description: no description
            ssl-client-session-state-timeout:
                type: int
                description: no description
            ssl-client-session-state-type:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
            ssl-dh-bits:
                type: str
                description: no description
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
            ssl-hpkp:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
                    - 'report-only'
            ssl-hpkp-age:
                type: int
                description: no description
            ssl-hpkp-backup:
                type: str
                description: no description
            ssl-hpkp-include-subdomains:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-hpkp-primary:
                type: str
                description: no description
            ssl-hpkp-report-uri:
                type: str
                description: no description
            ssl-hsts:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-hsts-age:
                type: int
                description: no description
            ssl-hsts-include-subdomains:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-http-location-conversion:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-http-match-host:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-max-version:
                type: str
                description: no description
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
            ssl-min-version:
                type: str
                description: no description
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
            ssl-mode:
                type: str
                description: no description
                choices:
                    - 'half'
                    - 'full'
            ssl-pfs:
                type: str
                description: no description
                choices:
                    - 'require'
                    - 'deny'
                    - 'allow'
            ssl-send-empty-frags:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ssl-server-algorithm:
                type: str
                description: no description
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
                    - 'custom'
                    - 'client'
            ssl-server-max-version:
                type: str
                description: no description
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'client'
            ssl-server-min-version:
                type: str
                description: no description
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'client'
            ssl-server-session-state-max:
                type: int
                description: no description
            ssl-server-session-state-timeout:
                type: int
                description: no description
            ssl-server-session-state-type:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
            type:
                type: str
                description: no description
                choices:
                    - 'static-nat'
                    - 'server-load-balance'
            uuid:
                type: str
                description: no description
            weblogic-server:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            websphere-server:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'

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
      fmgr_firewall_vip6_dynamicmapping:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         vip6: <your own value>
         state: <value in [present, absent]>
         firewall_vip6_dynamicmapping:
            _scope:
              -
                  name: <value of string>
                  vdom: <value of string>
            arp-reply: <value in [disable, enable]>
            color: <value of integer>
            comment: <value of string>
            extip: <value of string>
            extport: <value of string>
            http-cookie-age: <value of integer>
            http-cookie-domain: <value of string>
            http-cookie-domain-from-host: <value in [disable, enable]>
            http-cookie-generation: <value of integer>
            http-cookie-path: <value of string>
            http-cookie-share: <value in [disable, same-ip]>
            http-ip-header: <value in [disable, enable]>
            http-ip-header-name: <value of string>
            http-multiplex: <value in [disable, enable]>
            https-cookie-secure: <value in [disable, enable]>
            id: <value of integer>
            ldb-method: <value in [static, round-robin, weighted, ...]>
            mappedip: <value of string>
            mappedport: <value of string>
            max-embryonic-connections: <value of integer>
            monitor: <value of string>
            outlook-web-access: <value in [disable, enable]>
            persistence: <value in [none, http-cookie, ssl-session-id]>
            portforward: <value in [disable, enable]>
            protocol: <value in [tcp, udp, sctp]>
            server-type: <value in [http, https, ssl, ...]>
            src-filter: <value of string>
            ssl-algorithm: <value in [high, low, medium, ...]>
            ssl-certificate: <value of string>
            ssl-client-fallback: <value in [disable, enable]>
            ssl-client-renegotiation: <value in [deny, allow, secure]>
            ssl-client-session-state-max: <value of integer>
            ssl-client-session-state-timeout: <value of integer>
            ssl-client-session-state-type: <value in [disable, time, count, ...]>
            ssl-dh-bits: <value in [768, 1024, 1536, ...]>
            ssl-hpkp: <value in [disable, enable, report-only]>
            ssl-hpkp-age: <value of integer>
            ssl-hpkp-backup: <value of string>
            ssl-hpkp-include-subdomains: <value in [disable, enable]>
            ssl-hpkp-primary: <value of string>
            ssl-hpkp-report-uri: <value of string>
            ssl-hsts: <value in [disable, enable]>
            ssl-hsts-age: <value of integer>
            ssl-hsts-include-subdomains: <value in [disable, enable]>
            ssl-http-location-conversion: <value in [disable, enable]>
            ssl-http-match-host: <value in [disable, enable]>
            ssl-max-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
            ssl-min-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
            ssl-mode: <value in [half, full]>
            ssl-pfs: <value in [require, deny, allow]>
            ssl-send-empty-frags: <value in [disable, enable]>
            ssl-server-algorithm: <value in [high, low, medium, ...]>
            ssl-server-max-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
            ssl-server-min-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
            ssl-server-session-state-max: <value of integer>
            ssl-server-session-state-timeout: <value of integer>
            ssl-server-session-state-type: <value in [disable, time, count, ...]>
            type: <value in [static-nat, server-load-balance]>
            uuid: <value of string>
            weblogic-server: <value in [disable, enable]>
            websphere-server: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping',
        '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}',
        '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}'
    ]

    url_params = ['adom', 'vip6']
    module_primary_key = 'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]'
    module_arg_spec = {
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
        'vip6': {
            'required': True,
            'type': 'str'
        },
        'firewall_vip6_dynamicmapping': {
            'required': False,
            'type': 'dict',
            'options': {
                '_scope': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'name': {
                            'required': False,
                            'type': 'str'
                        },
                        'vdom': {
                            'required': False,
                            'type': 'str'
                        }
                    }
                },
                'arp-reply': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'color': {
                    'required': False,
                    'type': 'int'
                },
                'comment': {
                    'required': False,
                    'type': 'str'
                },
                'extip': {
                    'required': False,
                    'type': 'str'
                },
                'extport': {
                    'required': False,
                    'type': 'str'
                },
                'http-cookie-age': {
                    'required': False,
                    'type': 'int'
                },
                'http-cookie-domain': {
                    'required': False,
                    'type': 'str'
                },
                'http-cookie-domain-from-host': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'http-cookie-generation': {
                    'required': False,
                    'type': 'int'
                },
                'http-cookie-path': {
                    'required': False,
                    'type': 'str'
                },
                'http-cookie-share': {
                    'required': False,
                    'choices': [
                        'disable',
                        'same-ip'
                    ],
                    'type': 'str'
                },
                'http-ip-header': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'http-ip-header-name': {
                    'required': False,
                    'type': 'str'
                },
                'http-multiplex': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'https-cookie-secure': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'id': {
                    'required': False,
                    'type': 'int'
                },
                'ldb-method': {
                    'required': False,
                    'choices': [
                        'static',
                        'round-robin',
                        'weighted',
                        'least-session',
                        'least-rtt',
                        'first-alive',
                        'http-host'
                    ],
                    'type': 'str'
                },
                'mappedip': {
                    'required': False,
                    'type': 'str'
                },
                'mappedport': {
                    'required': False,
                    'type': 'str'
                },
                'max-embryonic-connections': {
                    'required': False,
                    'type': 'int'
                },
                'monitor': {
                    'required': False,
                    'type': 'str'
                },
                'outlook-web-access': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'persistence': {
                    'required': False,
                    'choices': [
                        'none',
                        'http-cookie',
                        'ssl-session-id'
                    ],
                    'type': 'str'
                },
                'portforward': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'protocol': {
                    'required': False,
                    'choices': [
                        'tcp',
                        'udp',
                        'sctp'
                    ],
                    'type': 'str'
                },
                'server-type': {
                    'required': False,
                    'choices': [
                        'http',
                        'https',
                        'ssl',
                        'tcp',
                        'udp',
                        'ip',
                        'imaps',
                        'pop3s',
                        'smtps'
                    ],
                    'type': 'str'
                },
                'src-filter': {
                    'required': False,
                    'type': 'str'
                },
                'ssl-algorithm': {
                    'required': False,
                    'choices': [
                        'high',
                        'low',
                        'medium',
                        'custom'
                    ],
                    'type': 'str'
                },
                'ssl-certificate': {
                    'required': False,
                    'type': 'str'
                },
                'ssl-client-fallback': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-client-renegotiation': {
                    'required': False,
                    'choices': [
                        'deny',
                        'allow',
                        'secure'
                    ],
                    'type': 'str'
                },
                'ssl-client-session-state-max': {
                    'required': False,
                    'type': 'int'
                },
                'ssl-client-session-state-timeout': {
                    'required': False,
                    'type': 'int'
                },
                'ssl-client-session-state-type': {
                    'required': False,
                    'choices': [
                        'disable',
                        'time',
                        'count',
                        'both'
                    ],
                    'type': 'str'
                },
                'ssl-dh-bits': {
                    'required': False,
                    'choices': [
                        '768',
                        '1024',
                        '1536',
                        '2048',
                        '3072',
                        '4096'
                    ],
                    'type': 'str'
                },
                'ssl-hpkp': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable',
                        'report-only'
                    ],
                    'type': 'str'
                },
                'ssl-hpkp-age': {
                    'required': False,
                    'type': 'int'
                },
                'ssl-hpkp-backup': {
                    'required': False,
                    'type': 'str'
                },
                'ssl-hpkp-include-subdomains': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-hpkp-primary': {
                    'required': False,
                    'type': 'str'
                },
                'ssl-hpkp-report-uri': {
                    'required': False,
                    'type': 'str'
                },
                'ssl-hsts': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-hsts-age': {
                    'required': False,
                    'type': 'int'
                },
                'ssl-hsts-include-subdomains': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-http-location-conversion': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-http-match-host': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-max-version': {
                    'required': False,
                    'choices': [
                        'ssl-3.0',
                        'tls-1.0',
                        'tls-1.1',
                        'tls-1.2'
                    ],
                    'type': 'str'
                },
                'ssl-min-version': {
                    'required': False,
                    'choices': [
                        'ssl-3.0',
                        'tls-1.0',
                        'tls-1.1',
                        'tls-1.2'
                    ],
                    'type': 'str'
                },
                'ssl-mode': {
                    'required': False,
                    'choices': [
                        'half',
                        'full'
                    ],
                    'type': 'str'
                },
                'ssl-pfs': {
                    'required': False,
                    'choices': [
                        'require',
                        'deny',
                        'allow'
                    ],
                    'type': 'str'
                },
                'ssl-send-empty-frags': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ssl-server-algorithm': {
                    'required': False,
                    'choices': [
                        'high',
                        'low',
                        'medium',
                        'custom',
                        'client'
                    ],
                    'type': 'str'
                },
                'ssl-server-max-version': {
                    'required': False,
                    'choices': [
                        'ssl-3.0',
                        'tls-1.0',
                        'tls-1.1',
                        'tls-1.2',
                        'client'
                    ],
                    'type': 'str'
                },
                'ssl-server-min-version': {
                    'required': False,
                    'choices': [
                        'ssl-3.0',
                        'tls-1.0',
                        'tls-1.1',
                        'tls-1.2',
                        'client'
                    ],
                    'type': 'str'
                },
                'ssl-server-session-state-max': {
                    'required': False,
                    'type': 'int'
                },
                'ssl-server-session-state-timeout': {
                    'required': False,
                    'type': 'int'
                },
                'ssl-server-session-state-type': {
                    'required': False,
                    'choices': [
                        'disable',
                        'time',
                        'count',
                        'both'
                    ],
                    'type': 'str'
                },
                'type': {
                    'required': False,
                    'choices': [
                        'static-nat',
                        'server-load-balance'
                    ],
                    'type': 'str'
                },
                'uuid': {
                    'required': False,
                    'type': 'str'
                },
                'weblogic-server': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'websphere-server': {
                    'required': False,
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip6_dynamicmapping'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
