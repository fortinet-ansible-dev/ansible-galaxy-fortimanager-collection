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
module: fmgr_firewall_vip
short_description: Configure virtual IP for IPv4.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/firewall/vip
    - /pm/config/global/obj/firewall/vip
    - Examples include all parameters and values need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Frank Shen (@fshen01)
    - Link Zheng (@zhengl)
notes:
    - There are only three top-level parameters where 'method' is always required
      while other two 'params' and 'url_params' can be optional
    - Due to the complexity of fortimanager api schema, the validation is done
      out of Ansible native parameter validation procedure.
    - The syntax of OPTIONS doen not comply with the standard Ansible argument
      specification, but with the structure of fortimanager API schema, we need
      a trivial transformation when we are filling the ansible playbook
options:
    loose_validation:
        description:
          - Do parameter validation in a loose way
        type: bool
        required: false
    workspace_locking_adom:
        description:
          - the adom name to lock in case FortiManager running in workspace mode
          - it can be global or any other custom adom names
        required: false
        type: str
    workspace_locking_timeout:
        description:
          - the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    method:
        description:
          - The method in request
        required: true
        type: str
        choices:
          - add
          - get
          - set
          - update
    params:
        description:
          - The parameters for each method
          - See full parameters list in https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/latest
        type: list
        required: false
    url_params:
        description:
          - The parameters for each API request URL
          - Also see full URL parameters in https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/latest
        required: false
        type: dict

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

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/VIP
      fmgr_firewall_vip:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [add, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               data:
                 -
                     arp-reply: <value in [disable, enable]>
                     color: <value of integer>
                     comment: <value of string>
                     dns-mapping-ttl: <value of integer>
                     dynamic_mapping:
                       -
                           _scope:
                             -
                                 name: <value of string>
                                 vdom: <value of string>
                           arp-reply: <value in [disable, enable]>
                           color: <value of integer>
                           comment: <value of string>
                           dns-mapping-ttl: <value of integer>
                           extaddr: <value of string>
                           extintf: <value of string>
                           extip: <value of string>
                           extport: <value of string>
                           gratuitous-arp-interval: <value of integer>
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
                           mapped-addr: <value of string>
                           mappedip:
                             - <value of string>
                           mappedport: <value of string>
                           max-embryonic-connections: <value of integer>
                           monitor:
                             - <value of string>
                           nat-source-vip: <value in [disable, enable]>
                           outlook-web-access: <value in [disable, enable]>
                           persistence: <value in [none, http-cookie, ssl-session-id]>
                           portforward: <value in [disable, enable]>
                           portmapping-type: <value in [1-to-1, m-to-n]>
                           protocol: <value in [tcp, udp, sctp, ...]>
                           realservers:
                             -
                                 client-ip:
                                   - <value of string>
                                 healthcheck: <value in [disable, enable, vip]>
                                 holddown-interval: <value of integer>
                                 http-host: <value of string>
                                 ip: <value of string>
                                 max-connections: <value of integer>
                                 monitor: <value of string>
                                 port: <value of integer>
                                 seq: <value of integer>
                                 status: <value in [active, standby, disable]>
                                 weight: <value of integer>
                           server-type: <value in [http, https, ssl, ...]>
                           service: <value of string>
                           src-filter:
                             - <value of string>
                           srcintf-filter:
                             - <value of string>
                           ssl-algorithm: <value in [high, medium, low, ...]>
                           ssl-certificate: <value of string>
                           ssl-cipher-suites:
                             -
                                 cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
                                 id: <value of integer>
                                 versions:
                                   - <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
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
                           type: <value in [static-nat, load-balance, server-load-balance, ...]>
                           uuid: <value of string>
                           weblogic-server: <value in [disable, enable]>
                           websphere-server: <value in [disable, enable]>
                     extaddr: <value of string>
                     extintf: <value of string>
                     extip: <value of string>
                     extport: <value of string>
                     gratuitous-arp-interval: <value of integer>
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
                     mapped-addr: <value of string>
                     mappedip:
                       - <value of string>
                     mappedport: <value of string>
                     max-embryonic-connections: <value of integer>
                     monitor: <value of string>
                     name: <value of string>
                     nat-source-vip: <value in [disable, enable]>
                     outlook-web-access: <value in [disable, enable]>
                     persistence: <value in [none, http-cookie, ssl-session-id]>
                     portforward: <value in [disable, enable]>
                     portmapping-type: <value in [1-to-1, m-to-n]>
                     protocol: <value in [tcp, udp, sctp, ...]>
                     realservers:
                       -
                           client-ip:
                             - <value of string>
                           healthcheck: <value in [disable, enable, vip]>
                           holddown-interval: <value of integer>
                           http-host: <value of string>
                           ip: <value of string>
                           max-connections: <value of integer>
                           monitor: <value of string>
                           port: <value of integer>
                           seq: <value of integer>
                           status: <value in [active, standby, disable]>
                           weight: <value of integer>
                     server-type: <value in [http, https, ssl, ...]>
                     service: <value of string>
                     src-filter:
                       - <value of string>
                     srcintf-filter: <value of string>
                     ssl-algorithm: <value in [high, medium, low, ...]>
                     ssl-certificate: <value of string>
                     ssl-cipher-suites:
                       -
                           cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
                           id: <value of integer>
                           versions:
                             - <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
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
                     ssl-server-cipher-suites:
                       -
                           cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
                           priority: <value of integer>
                           versions:
                             - <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                     ssl-server-max-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                     ssl-server-min-version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
                     ssl-server-session-state-max: <value of integer>
                     ssl-server-session-state-timeout: <value of integer>
                     ssl-server-session-state-type: <value in [disable, time, count, ...]>
                     type: <value in [static-nat, load-balance, server-load-balance, ...]>
                     uuid: <value of string>
                     weblogic-server: <value in [disable, enable]>
                     websphere-server: <value in [disable, enable]>

    - name: REQUESTING /PM/CONFIG/OBJ/FIREWALL/VIP
      fmgr_firewall_vip:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
         params:
            -
               attr: <value of string>
               fields:
                 -
                    - <value in [arp-reply, color, comment, ...]>
               filter:
                 - <value of string>
               get used: <value of integer>
               loadsub: <value of integer>
               option: <value in [count, object member, datasrc, ...]>
               range:
                 - <value of integer>
               sortings:
                 -
                     varidic.attr_name: <value in [1, -1]>

'''

RETURN = '''
url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
status:
    description: The status of api request
    returned: always
    type: dict
data:
    description: The payload returned in the request
    type: dict
    returned: always

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FAIL_SOCKET_MSG
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import DEFAULT_RESULT_OBJ
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGRCommon
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGBaseException
from ansible_collections.fortinet.fortimanager.plugins.module_utils.fortimanager import FortiManagerHandler


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/vip',
        '/pm/config/global/obj/firewall/vip'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        }
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'name': 'data',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'arp-reply': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'color': {
                            'type': 'integer'
                        },
                        'comment': {
                            'type': 'string'
                        },
                        'dns-mapping-ttl': {
                            'type': 'integer'
                        },
                        'dynamic_mapping': {
                            'type': 'array',
                            'items': {
                                '_scope': {
                                    'type': 'array',
                                    'items': {
                                        'name': {
                                            'type': 'string'
                                        },
                                        'vdom': {
                                            'type': 'string'
                                        }
                                    }
                                },
                                'arp-reply': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'color': {
                                    'type': 'integer'
                                },
                                'comment': {
                                    'type': 'string'
                                },
                                'dns-mapping-ttl': {
                                    'type': 'integer'
                                },
                                'extaddr': {
                                    'type': 'string'
                                },
                                'extintf': {
                                    'type': 'string'
                                },
                                'extip': {
                                    'type': 'string'
                                },
                                'extport': {
                                    'type': 'string'
                                },
                                'gratuitous-arp-interval': {
                                    'type': 'integer'
                                },
                                'http-cookie-age': {
                                    'type': 'integer'
                                },
                                'http-cookie-domain': {
                                    'type': 'string'
                                },
                                'http-cookie-domain-from-host': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'http-cookie-generation': {
                                    'type': 'integer'
                                },
                                'http-cookie-path': {
                                    'type': 'string'
                                },
                                'http-cookie-share': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'same-ip'
                                    ]
                                },
                                'http-ip-header': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'http-ip-header-name': {
                                    'type': 'string'
                                },
                                'http-multiplex': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'https-cookie-secure': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'id': {
                                    'type': 'integer'
                                },
                                'ldb-method': {
                                    'type': 'string',
                                    'enum': [
                                        'static',
                                        'round-robin',
                                        'weighted',
                                        'least-session',
                                        'least-rtt',
                                        'first-alive',
                                        'http-host'
                                    ]
                                },
                                'mapped-addr': {
                                    'type': 'string'
                                },
                                'mappedip': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'mappedport': {
                                    'type': 'string'
                                },
                                'max-embryonic-connections': {
                                    'type': 'integer'
                                },
                                'monitor': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'nat-source-vip': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'outlook-web-access': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'persistence': {
                                    'type': 'string',
                                    'enum': [
                                        'none',
                                        'http-cookie',
                                        'ssl-session-id'
                                    ]
                                },
                                'portforward': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'portmapping-type': {
                                    'type': 'string',
                                    'enum': [
                                        '1-to-1',
                                        'm-to-n'
                                    ]
                                },
                                'protocol': {
                                    'type': 'string',
                                    'enum': [
                                        'tcp',
                                        'udp',
                                        'sctp',
                                        'icmp'
                                    ]
                                },
                                'realservers': {
                                    'type': 'array',
                                    'items': {
                                        'client-ip': {
                                            'type': 'array',
                                            'items': {
                                                'type': 'string'
                                            }
                                        },
                                        'healthcheck': {
                                            'type': 'string',
                                            'enum': [
                                                'disable',
                                                'enable',
                                                'vip'
                                            ]
                                        },
                                        'holddown-interval': {
                                            'type': 'integer'
                                        },
                                        'http-host': {
                                            'type': 'string'
                                        },
                                        'ip': {
                                            'type': 'string'
                                        },
                                        'max-connections': {
                                            'type': 'integer'
                                        },
                                        'monitor': {
                                            'type': 'string'
                                        },
                                        'port': {
                                            'type': 'integer'
                                        },
                                        'seq': {
                                            'type': 'integer'
                                        },
                                        'status': {
                                            'type': 'string',
                                            'enum': [
                                                'active',
                                                'standby',
                                                'disable'
                                            ]
                                        },
                                        'weight': {
                                            'type': 'integer'
                                        }
                                    }
                                },
                                'server-type': {
                                    'type': 'string',
                                    'enum': [
                                        'http',
                                        'https',
                                        'ssl',
                                        'tcp',
                                        'udp',
                                        'ip',
                                        'imaps',
                                        'pop3s',
                                        'smtps'
                                    ]
                                },
                                'service': {
                                    'type': 'string'
                                },
                                'src-filter': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'srcintf-filter': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'ssl-algorithm': {
                                    'type': 'string',
                                    'enum': [
                                        'high',
                                        'medium',
                                        'low',
                                        'custom'
                                    ]
                                },
                                'ssl-certificate': {
                                    'type': 'string'
                                },
                                'ssl-cipher-suites': {
                                    'type': 'array',
                                    'items': {
                                        'cipher': {
                                            'type': 'string',
                                            'enum': [
                                                'TLS-RSA-WITH-RC4-128-MD5',
                                                'TLS-RSA-WITH-RC4-128-SHA',
                                                'TLS-RSA-WITH-DES-CBC-SHA',
                                                'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                                                'TLS-RSA-WITH-AES-128-CBC-SHA',
                                                'TLS-RSA-WITH-AES-256-CBC-SHA',
                                                'TLS-RSA-WITH-AES-128-CBC-SHA256',
                                                'TLS-RSA-WITH-AES-256-CBC-SHA256',
                                                'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                                'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                                'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                                'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                                'TLS-RSA-WITH-SEED-CBC-SHA',
                                                'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                                'TLS-RSA-WITH-ARIA-256-CBC-SHA384',
                                                'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-AES-128-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                                'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256',
                                                'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                                'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                                'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                                'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                                'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                                'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                                'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                                'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                                                'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                                'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                                                'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                                'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                                                'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384',
                                                'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256',
                                                'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                                'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                                                'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                                'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256',
                                                'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                                'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384',
                                                'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                                'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                                                'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                                'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                                'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384',
                                                'TLS-RSA-WITH-AES-128-GCM-SHA256',
                                                'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                                'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256',
                                                'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                                'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256',
                                                'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                                'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                                'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                                'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                                                'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                                'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA',
                                                'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                                            ]
                                        },
                                        'id': {
                                            'type': 'integer'
                                        },
                                        'versions': {
                                            'type': 'array',
                                            'items': {
                                                'type': 'string',
                                                'enum': [
                                                    'ssl-3.0',
                                                    'tls-1.0',
                                                    'tls-1.1',
                                                    'tls-1.2'
                                                ]
                                            }
                                        }
                                    }
                                },
                                'ssl-client-fallback': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-client-renegotiation': {
                                    'type': 'string',
                                    'enum': [
                                        'deny',
                                        'allow',
                                        'secure'
                                    ]
                                },
                                'ssl-client-session-state-max': {
                                    'type': 'integer'
                                },
                                'ssl-client-session-state-timeout': {
                                    'type': 'integer'
                                },
                                'ssl-client-session-state-type': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'time',
                                        'count',
                                        'both'
                                    ]
                                },
                                'ssl-dh-bits': {
                                    'type': 'string',
                                    'enum': [
                                        '768',
                                        '1024',
                                        '1536',
                                        '2048',
                                        '3072',
                                        '4096'
                                    ]
                                },
                                'ssl-hpkp': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable',
                                        'report-only'
                                    ]
                                },
                                'ssl-hpkp-age': {
                                    'type': 'integer'
                                },
                                'ssl-hpkp-backup': {
                                    'type': 'string'
                                },
                                'ssl-hpkp-include-subdomains': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-hpkp-primary': {
                                    'type': 'string'
                                },
                                'ssl-hpkp-report-uri': {
                                    'type': 'string'
                                },
                                'ssl-hsts': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-hsts-age': {
                                    'type': 'integer'
                                },
                                'ssl-hsts-include-subdomains': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-http-location-conversion': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-http-match-host': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-max-version': {
                                    'type': 'string',
                                    'enum': [
                                        'ssl-3.0',
                                        'tls-1.0',
                                        'tls-1.1',
                                        'tls-1.2'
                                    ]
                                },
                                'ssl-min-version': {
                                    'type': 'string',
                                    'enum': [
                                        'ssl-3.0',
                                        'tls-1.0',
                                        'tls-1.1',
                                        'tls-1.2'
                                    ]
                                },
                                'ssl-mode': {
                                    'type': 'string',
                                    'enum': [
                                        'half',
                                        'full'
                                    ]
                                },
                                'ssl-pfs': {
                                    'type': 'string',
                                    'enum': [
                                        'require',
                                        'deny',
                                        'allow'
                                    ]
                                },
                                'ssl-send-empty-frags': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'ssl-server-algorithm': {
                                    'type': 'string',
                                    'enum': [
                                        'high',
                                        'low',
                                        'medium',
                                        'custom',
                                        'client'
                                    ]
                                },
                                'ssl-server-max-version': {
                                    'type': 'string',
                                    'enum': [
                                        'ssl-3.0',
                                        'tls-1.0',
                                        'tls-1.1',
                                        'tls-1.2',
                                        'client'
                                    ]
                                },
                                'ssl-server-min-version': {
                                    'type': 'string',
                                    'enum': [
                                        'ssl-3.0',
                                        'tls-1.0',
                                        'tls-1.1',
                                        'tls-1.2',
                                        'client'
                                    ]
                                },
                                'ssl-server-session-state-max': {
                                    'type': 'integer'
                                },
                                'ssl-server-session-state-timeout': {
                                    'type': 'integer'
                                },
                                'ssl-server-session-state-type': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'time',
                                        'count',
                                        'both'
                                    ]
                                },
                                'type': {
                                    'type': 'string',
                                    'enum': [
                                        'static-nat',
                                        'load-balance',
                                        'server-load-balance',
                                        'dns-translation',
                                        'fqdn'
                                    ]
                                },
                                'uuid': {
                                    'type': 'string'
                                },
                                'weblogic-server': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                },
                                'websphere-server': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable'
                                    ]
                                }
                            }
                        },
                        'extaddr': {
                            'type': 'string'
                        },
                        'extintf': {
                            'type': 'string'
                        },
                        'extip': {
                            'type': 'string'
                        },
                        'extport': {
                            'type': 'string'
                        },
                        'gratuitous-arp-interval': {
                            'type': 'integer'
                        },
                        'http-cookie-age': {
                            'type': 'integer'
                        },
                        'http-cookie-domain': {
                            'type': 'string'
                        },
                        'http-cookie-domain-from-host': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'http-cookie-generation': {
                            'type': 'integer'
                        },
                        'http-cookie-path': {
                            'type': 'string'
                        },
                        'http-cookie-share': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'same-ip'
                            ]
                        },
                        'http-ip-header': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'http-ip-header-name': {
                            'type': 'string'
                        },
                        'http-multiplex': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'https-cookie-secure': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'id': {
                            'type': 'integer'
                        },
                        'ldb-method': {
                            'type': 'string',
                            'enum': [
                                'static',
                                'round-robin',
                                'weighted',
                                'least-session',
                                'least-rtt',
                                'first-alive',
                                'http-host'
                            ]
                        },
                        'mapped-addr': {
                            'type': 'string'
                        },
                        'mappedip': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'mappedport': {
                            'type': 'string'
                        },
                        'max-embryonic-connections': {
                            'type': 'integer'
                        },
                        'monitor': {
                            'type': 'string'
                        },
                        'name': {
                            'type': 'string'
                        },
                        'nat-source-vip': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'outlook-web-access': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'persistence': {
                            'type': 'string',
                            'enum': [
                                'none',
                                'http-cookie',
                                'ssl-session-id'
                            ]
                        },
                        'portforward': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'portmapping-type': {
                            'type': 'string',
                            'enum': [
                                '1-to-1',
                                'm-to-n'
                            ]
                        },
                        'protocol': {
                            'type': 'string',
                            'enum': [
                                'tcp',
                                'udp',
                                'sctp',
                                'icmp'
                            ]
                        },
                        'realservers': {
                            'type': 'array',
                            'items': {
                                'client-ip': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    }
                                },
                                'healthcheck': {
                                    'type': 'string',
                                    'enum': [
                                        'disable',
                                        'enable',
                                        'vip'
                                    ]
                                },
                                'holddown-interval': {
                                    'type': 'integer'
                                },
                                'http-host': {
                                    'type': 'string'
                                },
                                'ip': {
                                    'type': 'string'
                                },
                                'max-connections': {
                                    'type': 'integer'
                                },
                                'monitor': {
                                    'type': 'string'
                                },
                                'port': {
                                    'type': 'integer'
                                },
                                'seq': {
                                    'type': 'integer'
                                },
                                'status': {
                                    'type': 'string',
                                    'enum': [
                                        'active',
                                        'standby',
                                        'disable'
                                    ]
                                },
                                'weight': {
                                    'type': 'integer'
                                }
                            }
                        },
                        'server-type': {
                            'type': 'string',
                            'enum': [
                                'http',
                                'https',
                                'ssl',
                                'tcp',
                                'udp',
                                'ip',
                                'imaps',
                                'pop3s',
                                'smtps'
                            ]
                        },
                        'service': {
                            'type': 'string'
                        },
                        'src-filter': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'srcintf-filter': {
                            'type': 'string'
                        },
                        'ssl-algorithm': {
                            'type': 'string',
                            'enum': [
                                'high',
                                'medium',
                                'low',
                                'custom'
                            ]
                        },
                        'ssl-certificate': {
                            'type': 'string'
                        },
                        'ssl-cipher-suites': {
                            'type': 'array',
                            'items': {
                                'cipher': {
                                    'type': 'string',
                                    'enum': [
                                        'TLS-RSA-WITH-RC4-128-MD5',
                                        'TLS-RSA-WITH-RC4-128-SHA',
                                        'TLS-RSA-WITH-DES-CBC-SHA',
                                        'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-RSA-WITH-AES-256-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                        'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                                    ]
                                },
                                'id': {
                                    'type': 'integer'
                                },
                                'versions': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string',
                                        'enum': [
                                            'ssl-3.0',
                                            'tls-1.0',
                                            'tls-1.1',
                                            'tls-1.2'
                                        ]
                                    }
                                }
                            }
                        },
                        'ssl-client-fallback': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-client-renegotiation': {
                            'type': 'string',
                            'enum': [
                                'deny',
                                'allow',
                                'secure'
                            ]
                        },
                        'ssl-client-session-state-max': {
                            'type': 'integer'
                        },
                        'ssl-client-session-state-timeout': {
                            'type': 'integer'
                        },
                        'ssl-client-session-state-type': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'time',
                                'count',
                                'both'
                            ]
                        },
                        'ssl-dh-bits': {
                            'type': 'string',
                            'enum': [
                                '768',
                                '1024',
                                '1536',
                                '2048',
                                '3072',
                                '4096'
                            ]
                        },
                        'ssl-hpkp': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable',
                                'report-only'
                            ]
                        },
                        'ssl-hpkp-age': {
                            'type': 'integer'
                        },
                        'ssl-hpkp-backup': {
                            'type': 'string'
                        },
                        'ssl-hpkp-include-subdomains': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-hpkp-primary': {
                            'type': 'string'
                        },
                        'ssl-hpkp-report-uri': {
                            'type': 'string'
                        },
                        'ssl-hsts': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-hsts-age': {
                            'type': 'integer'
                        },
                        'ssl-hsts-include-subdomains': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-http-location-conversion': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-http-match-host': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-max-version': {
                            'type': 'string',
                            'enum': [
                                'ssl-3.0',
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2'
                            ]
                        },
                        'ssl-min-version': {
                            'type': 'string',
                            'enum': [
                                'ssl-3.0',
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2'
                            ]
                        },
                        'ssl-mode': {
                            'type': 'string',
                            'enum': [
                                'half',
                                'full'
                            ]
                        },
                        'ssl-pfs': {
                            'type': 'string',
                            'enum': [
                                'require',
                                'deny',
                                'allow'
                            ]
                        },
                        'ssl-send-empty-frags': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-server-algorithm': {
                            'type': 'string',
                            'enum': [
                                'high',
                                'low',
                                'medium',
                                'custom',
                                'client'
                            ]
                        },
                        'ssl-server-cipher-suites': {
                            'type': 'array',
                            'items': {
                                'cipher': {
                                    'type': 'string',
                                    'enum': [
                                        'TLS-RSA-WITH-RC4-128-MD5',
                                        'TLS-RSA-WITH-RC4-128-SHA',
                                        'TLS-RSA-WITH-DES-CBC-SHA',
                                        'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-RSA-WITH-AES-256-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                        'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                                    ]
                                },
                                'priority': {
                                    'type': 'integer'
                                },
                                'versions': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string',
                                        'enum': [
                                            'ssl-3.0',
                                            'tls-1.0',
                                            'tls-1.1',
                                            'tls-1.2'
                                        ]
                                    }
                                }
                            }
                        },
                        'ssl-server-max-version': {
                            'type': 'string',
                            'enum': [
                                'ssl-3.0',
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2',
                                'client'
                            ]
                        },
                        'ssl-server-min-version': {
                            'type': 'string',
                            'enum': [
                                'ssl-3.0',
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2',
                                'client'
                            ]
                        },
                        'ssl-server-session-state-max': {
                            'type': 'integer'
                        },
                        'ssl-server-session-state-timeout': {
                            'type': 'integer'
                        },
                        'ssl-server-session-state-type': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'time',
                                'count',
                                'both'
                            ]
                        },
                        'type': {
                            'type': 'string',
                            'enum': [
                                'static-nat',
                                'load-balance',
                                'server-load-balance',
                                'dns-translation',
                                'fqdn'
                            ]
                        },
                        'uuid': {
                            'type': 'string'
                        },
                        'weblogic-server': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'websphere-server': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        }
                    }
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object1': [
                {
                    'type': 'string',
                    'name': 'attr',
                    'api_tag': 0
                },
                {
                    'name': 'fields',
                    'api_tag': 0,
                    'type': 'array',
                    'items': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'enum': [
                                'arp-reply',
                                'color',
                                'comment',
                                'dns-mapping-ttl',
                                'extaddr',
                                'extintf',
                                'extip',
                                'extport',
                                'gratuitous-arp-interval',
                                'http-cookie-age',
                                'http-cookie-domain',
                                'http-cookie-domain-from-host',
                                'http-cookie-generation',
                                'http-cookie-path',
                                'http-cookie-share',
                                'http-ip-header',
                                'http-ip-header-name',
                                'http-multiplex',
                                'https-cookie-secure',
                                'id',
                                'ldb-method',
                                'mapped-addr',
                                'mappedip',
                                'mappedport',
                                'max-embryonic-connections',
                                'monitor',
                                'name',
                                'nat-source-vip',
                                'outlook-web-access',
                                'persistence',
                                'portforward',
                                'portmapping-type',
                                'protocol',
                                'server-type',
                                'service',
                                'src-filter',
                                'srcintf-filter',
                                'ssl-algorithm',
                                'ssl-certificate',
                                'ssl-client-fallback',
                                'ssl-client-renegotiation',
                                'ssl-client-session-state-max',
                                'ssl-client-session-state-timeout',
                                'ssl-client-session-state-type',
                                'ssl-dh-bits',
                                'ssl-hpkp',
                                'ssl-hpkp-age',
                                'ssl-hpkp-backup',
                                'ssl-hpkp-include-subdomains',
                                'ssl-hpkp-primary',
                                'ssl-hpkp-report-uri',
                                'ssl-hsts',
                                'ssl-hsts-age',
                                'ssl-hsts-include-subdomains',
                                'ssl-http-location-conversion',
                                'ssl-http-match-host',
                                'ssl-max-version',
                                'ssl-min-version',
                                'ssl-mode',
                                'ssl-pfs',
                                'ssl-send-empty-frags',
                                'ssl-server-algorithm',
                                'ssl-server-max-version',
                                'ssl-server-min-version',
                                'ssl-server-session-state-max',
                                'ssl-server-session-state-timeout',
                                'ssl-server-session-state-type',
                                'type',
                                'uuid',
                                'weblogic-server',
                                'websphere-server'
                            ]
                        }
                    }
                },
                {
                    'name': 'filter',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'example': [
                                '<attr>',
                                '==',
                                'test'
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'integer',
                    'name': 'get used',
                    'api_tag': 0
                },
                {
                    'type': 'integer',
                    'name': 'loadsub',
                    'api_tag': 0
                },
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'count',
                            'object member',
                            'datasrc',
                            'get reserved',
                            'syntax'
                        ]
                    },
                    'api_tag': 0
                },
                {
                    'name': 'range',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            'type': 'integer',
                            'example': [
                                2,
                                5
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'name': 'sortings',
                    'type': 'dict',
                    'dict': {
                        'type': 'array',
                        'items': {
                            '{attr_name}': {
                                'type': 'integer',
                                'enum': [
                                    1,
                                    -1
                                ]
                            }
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ]
        },
        'method_mapping': {
            'add': 'object0',
            'get': 'object1',
            'set': 'object0',
            'update': 'object0'
        }
    }

    module_arg_spec = {
        'loose_validation': {
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
        'params': {
            'type': 'list',
            'required': False
        },
        'method': {
            'type': 'str',
            'required': True,
            'choices': [
                'add',
                'get',
                'set',
                'update'
            ]
        },
        'url_params': {
            'type': 'dict',
            'required': False
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    method = module.params['method']
    loose_validation = module.params['loose_validation']

    fmgr = None
    payload = None
    response = DEFAULT_RESULT_OBJ

    if module._socket_path:
        connection = Connection(module._socket_path)
        tools = FMGRCommon()
        if loose_validation is False:
            tools.validate_module_params(module, body_schema)
        tools.validate_module_url_params(module, jrpc_urls, url_schema)
        full_url = tools.get_full_url_path(module, jrpc_urls)
        payload = tools.get_full_payload(module, full_url)
        fmgr = FortiManagerHandler(connection, module)
        fmgr.tools = tools
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    try:
        response = fmgr._conn.send_request(method, payload)
        fmgr.govern_response(module=module, results=response,
                             msg='Operation Finished',
                             ansible_facts=fmgr.construct_ansible_facts(response, module.params, module.params))
    except Exception as e:
        raise FMGBaseException(e)

    module.exit_json(meta=response[1])


if __name__ == '__main__':
    main()
