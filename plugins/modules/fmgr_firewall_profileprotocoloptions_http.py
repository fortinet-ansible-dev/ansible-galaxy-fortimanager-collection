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
module: fmgr_firewall_profileprotocoloptions_http
short_description: Configure HTTP protocol options.
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
    profile-protocol-options:
        description: the parameter (profile-protocol-options) in requested url
        type: str
        required: true
    firewall_profileprotocoloptions_http:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            block-page-status-code:
                type: int
                description: 'Code number returned for blocked HTTP pages (non-FortiGuard only) (100 - 599, default = 403).'
            comfort-amount:
                type: int
                description: 'Amount of data to send in a transmission for client comforting (1 - 10240 bytes, default = 1).'
            comfort-interval:
                type: int
                description: 'Period of time between start, or last transmission, and the next client comfort transmission of data (1 - 900 sec, default = 10).'
            fortinet-bar:
                type: str
                description: 'Enable/disable Fortinet bar on HTML content.'
                choices:
                    - 'disable'
                    - 'enable'
            fortinet-bar-port:
                type: int
                description: 'Port for use by Fortinet Bar (1 - 65535, default = 8011).'
            http-policy:
                type: str
                description: 'Enable/disable HTTP policy check.'
                choices:
                    - 'disable'
                    - 'enable'
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
            status:
                type: str
                description: 'Enable/disable the active status of scanning for this protocol.'
                choices:
                    - 'disable'
                    - 'enable'
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
            uncompressed-nest-limit:
                type: int
                description: 'Maximum nested levels of compression that can be uncompressed and scanned (2 - 100, default = 12).'
            uncompressed-oversize-limit:
                type: int
                description: 'Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited, default = 10).'

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
    - name: Configure HTTP protocol options.
      fmgr_firewall_profileprotocoloptions_http:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         profile-protocol-options: <your own value>
         firewall_profileprotocoloptions_http:
            block-page-status-code: <value of integer>
            comfort-amount: <value of integer>
            comfort-interval: <value of integer>
            fortinet-bar: <value in [disable, enable]>
            fortinet-bar-port: <value of integer>
            http-policy: <value in [disable, enable]>
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
            range-block: <value in [disable, enable]>
            retry-count: <value of integer>
            scan-bzip2: <value in [disable, enable]>
            status: <value in [disable, enable]>
            streaming-content-bypass: <value in [disable, enable]>
            strip-x-forwarded-for: <value in [disable, enable]>
            switching-protocols: <value in [bypass, block]>
            uncompressed-nest-limit: <value of integer>
            uncompressed-oversize-limit: <value of integer>

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
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/http',
        '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/http'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/http/{http}',
        '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/http/{http}'
    ]

    url_params = ['adom', 'profile-protocol-options']
    module_primary_key = None
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'profile-protocol-options': {
            'required': True,
            'type': 'str'
        },
        'firewall_profileprotocoloptions_http': {
            'required': False,
            'type': 'dict',
            'options': {
                'block-page-status-code': {
                    'required': False,
                    'type': 'int'
                },
                'comfort-amount': {
                    'required': False,
                    'type': 'int'
                },
                'comfort-interval': {
                    'required': False,
                    'type': 'int'
                },
                'fortinet-bar': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fortinet-bar-port': {
                    'required': False,
                    'type': 'int'
                },
                'http-policy': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'inspect-all': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'options': {
                    'required': False,
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
                    'type': 'int'
                },
                'ports': {
                    'required': False,
                    'type': 'int'
                },
                'post-lang': {
                    'required': False,
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
                'range-block': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'retry-count': {
                    'required': False,
                    'type': 'int'
                },
                'scan-bzip2': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'streaming-content-bypass': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'strip-x-forwarded-for': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'switching-protocols': {
                    'required': False,
                    'choices': [
                        'bypass',
                        'block'
                    ],
                    'type': 'str'
                },
                'uncompressed-nest-limit': {
                    'required': False,
                    'type': 'int'
                },
                'uncompressed-oversize-limit': {
                    'required': False,
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profileprotocoloptions_http'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
