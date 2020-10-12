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
module: fmgr_firewall_service_custom
short_description: Configure custom services.
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
    firewall_service_custom:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            app-category:
                description: no description
                type: int
            app-service-type:
                type: str
                description: 'Application service type.'
                choices:
                    - 'disable'
                    - 'app-id'
                    - 'app-category'
            application:
                description: no description
                type: int
            category:
                type: str
                description: 'Service category.'
            check-reset-range:
                type: str
                description: 'Configure the type of ICMP error message verification.'
                choices:
                    - 'disable'
                    - 'default'
                    - 'strict'
            color:
                type: int
                description: 'Color of icon on the GUI.'
            comment:
                type: str
                description: no description
            fqdn:
                type: str
                description: 'Fully qualified domain name.'
            helper:
                type: str
                description: 'Helper name.'
                choices:
                    - 'disable'
                    - 'auto'
                    - 'ftp'
                    - 'tftp'
                    - 'ras'
                    - 'h323'
                    - 'tns'
                    - 'mms'
                    - 'sip'
                    - 'pptp'
                    - 'rtsp'
                    - 'dns-udp'
                    - 'dns-tcp'
                    - 'pmap'
                    - 'rsh'
                    - 'dcerpc'
                    - 'mgcp'
                    - 'gtp-c'
                    - 'gtp-u'
                    - 'gtp-b'
            icmpcode:
                type: int
                description: 'ICMP code.'
            icmptype:
                type: int
                description: 'ICMP type.'
            iprange:
                type: str
                description: 'Start and end of the IP range associated with service.'
            name:
                type: str
                description: 'Custom service name.'
            protocol:
                type: str
                description: 'Protocol type based on IANA numbers.'
                choices:
                    - 'ICMP'
                    - 'IP'
                    - 'TCP/UDP/SCTP'
                    - 'ICMP6'
                    - 'HTTP'
                    - 'FTP'
                    - 'CONNECT'
                    - 'SOCKS'
                    - 'ALL'
                    - 'SOCKS-TCP'
                    - 'SOCKS-UDP'
            protocol-number:
                type: int
                description: 'IP protocol number.'
            proxy:
                type: str
                description: 'Enable/disable web proxy service.'
                choices:
                    - 'disable'
                    - 'enable'
            sctp-portrange:
                type: str
                description: 'Multiple SCTP port ranges.'
            session-ttl:
                type: int
                description: 'Session TTL (300 - 604800, 0 = default).'
            tcp-halfclose-timer:
                type: int
                description: 'Wait time to close a TCP session waiting for an unanswered FIN packet (1 - 86400 sec, 0 = default).'
            tcp-halfopen-timer:
                type: int
                description: 'Wait time to close a TCP session waiting for an unanswered open session packet (1 - 86400 sec, 0 = default).'
            tcp-portrange:
                type: str
                description: 'Multiple TCP port ranges.'
            tcp-timewait-timer:
                type: int
                description: 'Set the length of the TCP TIME-WAIT state in seconds (1 - 300 sec, 0 = default).'
            udp-idle-timer:
                type: int
                description: 'UDP half close timeout (0 - 86400 sec, 0 = default).'
            udp-portrange:
                type: str
                description: 'Multiple UDP port ranges.'
            visibility:
                type: str
                description: 'Enable/disable the visibility of the service on the GUI.'
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
    - name: Configure custom services.
      fmgr_firewall_service_custom:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         firewall_service_custom:
            app-category: <value of integer>
            app-service-type: <value in [disable, app-id, app-category]>
            application: <value of integer>
            category: <value of string>
            check-reset-range: <value in [disable, default, strict]>
            color: <value of integer>
            comment: <value of string>
            fqdn: <value of string>
            helper: <value in [disable, auto, ftp, ...]>
            icmpcode: <value of integer>
            icmptype: <value of integer>
            iprange: <value of string>
            name: <value of string>
            protocol: <value in [ICMP, IP, TCP/UDP/SCTP, ...]>
            protocol-number: <value of integer>
            proxy: <value in [disable, enable]>
            sctp-portrange: <value of string>
            session-ttl: <value of integer>
            tcp-halfclose-timer: <value of integer>
            tcp-halfopen-timer: <value of integer>
            tcp-portrange: <value of string>
            tcp-timewait-timer: <value of integer>
            udp-idle-timer: <value of integer>
            udp-portrange: <value of string>
            visibility: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/obj/firewall/service/custom',
        '/pm/config/global/obj/firewall/service/custom'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/service/custom/{custom}',
        '/pm/config/global/obj/firewall/service/custom/{custom}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
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
        'firewall_service_custom': {
            'required': False,
            'type': 'dict',
            'options': {
                'app-category': {
                    'required': False,
                    'type': 'int'
                },
                'app-service-type': {
                    'required': False,
                    'choices': [
                        'disable',
                        'app-id',
                        'app-category'
                    ],
                    'type': 'str'
                },
                'application': {
                    'required': False,
                    'type': 'int'
                },
                'category': {
                    'required': False,
                    'type': 'str'
                },
                'check-reset-range': {
                    'required': False,
                    'choices': [
                        'disable',
                        'default',
                        'strict'
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
                'fqdn': {
                    'required': False,
                    'type': 'str'
                },
                'helper': {
                    'required': False,
                    'choices': [
                        'disable',
                        'auto',
                        'ftp',
                        'tftp',
                        'ras',
                        'h323',
                        'tns',
                        'mms',
                        'sip',
                        'pptp',
                        'rtsp',
                        'dns-udp',
                        'dns-tcp',
                        'pmap',
                        'rsh',
                        'dcerpc',
                        'mgcp',
                        'gtp-c',
                        'gtp-u',
                        'gtp-b'
                    ],
                    'type': 'str'
                },
                'icmpcode': {
                    'required': False,
                    'type': 'int'
                },
                'icmptype': {
                    'required': False,
                    'type': 'int'
                },
                'iprange': {
                    'required': False,
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'protocol': {
                    'required': False,
                    'choices': [
                        'ICMP',
                        'IP',
                        'TCP/UDP/SCTP',
                        'ICMP6',
                        'HTTP',
                        'FTP',
                        'CONNECT',
                        'SOCKS',
                        'ALL',
                        'SOCKS-TCP',
                        'SOCKS-UDP'
                    ],
                    'type': 'str'
                },
                'protocol-number': {
                    'required': False,
                    'type': 'int'
                },
                'proxy': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sctp-portrange': {
                    'required': False,
                    'type': 'str'
                },
                'session-ttl': {
                    'required': False,
                    'type': 'int'
                },
                'tcp-halfclose-timer': {
                    'required': False,
                    'type': 'int'
                },
                'tcp-halfopen-timer': {
                    'required': False,
                    'type': 'int'
                },
                'tcp-portrange': {
                    'required': False,
                    'type': 'str'
                },
                'tcp-timewait-timer': {
                    'required': False,
                    'type': 'int'
                },
                'udp-idle-timer': {
                    'required': False,
                    'type': 'int'
                },
                'udp-portrange': {
                    'required': False,
                    'type': 'str'
                },
                'visibility': {
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_service_custom'),
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
