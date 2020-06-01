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
module: fmgr_system_global
short_description: Global range attributes.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ get set update ] the following apis.
    - /cli/global/system/global
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

    - name: REQUESTING /CLI/SYSTEM/GLOBAL
      fmgr_system_global:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [set, update]>
         params:
            -
               data:
                  admin-lockout-duration: <value of integer>
                  admin-lockout-threshold: <value of integer>
                  adom-mode: <value in [normal, advanced]>
                  adom-rev-auto-delete: <value in [disable, by-revisions, by-days]>
                  adom-rev-max-backup-revisions: <value of integer>
                  adom-rev-max-days: <value of integer>
                  adom-rev-max-revisions: <value of integer>
                  adom-select: <value in [disable, enable]>
                  adom-status: <value in [disable, enable]>
                  clt-cert-req: <value in [disable, enable, optional]>
                  console-output: <value in [standard, more]>
                  country-flag: <value in [disable, enable]>
                  create-revision: <value in [disable, enable]>
                  daylightsavetime: <value in [disable, enable]>
                  default-disk-quota: <value of integer>
                  detect-unregistered-log-device: <value in [disable, enable]>
                  device-view-mode: <value in [regular, tree]>
                  dh-params: <value in [1024, 1536, 2048, ...]>
                  disable-module:
                    - <value in [fortiview-noc]>
                  enc-algorithm: <value in [low, medium, high]>
                  faz-status: <value in [disable, enable]>
                  fgfm-local-cert: <value of string>
                  fgfm-ssl-protocol: <value in [sslv3, tlsv1.0, tlsv1.1, ...]>
                  ha-member-auto-grouping: <value in [disable, enable]>
                  hitcount_concurrent: <value of integer>
                  hitcount_interval: <value of integer>
                  hostname: <value of string>
                  import-ignore-addr-cmt: <value in [disable, enable]>
                  language: <value in [english, simch, japanese, ...]>
                  latitude: <value of string>
                  ldap-cache-timeout: <value of integer>
                  ldapconntimeout: <value of integer>
                  lock-preempt: <value in [disable, enable]>
                  log-checksum: <value in [none, md5, md5-auth]>
                  log-forward-cache-size: <value of integer>
                  longitude: <value of string>
                  max-log-forward: <value of integer>
                  max-running-reports: <value of integer>
                  oftp-ssl-protocol: <value in [sslv3, tlsv1.0, tlsv1.1, ...]>
                  partial-install: <value in [disable, enable]>
                  partial-install-force: <value in [disable, enable]>
                  partial-install-rev: <value in [disable, enable]>
                  perform-improve-by-ha: <value in [disable, enable]>
                  policy-hit-count: <value in [disable, enable]>
                  policy-object-in-dual-pane: <value in [disable, enable]>
                  pre-login-banner: <value in [disable, enable]>
                  pre-login-banner-message: <value of string>
                  remoteauthtimeout: <value of integer>
                  search-all-adoms: <value in [disable, enable]>
                  ssl-low-encryption: <value in [disable, enable]>
                  ssl-protocol:
                    - <value in [tlsv1.2, tlsv1.1, tlsv1.0, ...]>
                  ssl-static-key-ciphers: <value in [disable, enable]>
                  task-list-size: <value of integer>
                  tftp: <value in [disable, enable]>
                  timezone: <value in [00, 01, 02, ...]>
                  tunnel-mtu: <value of integer>
                  usg: <value in [disable, enable]>
                  vdom-mirror: <value in [disable, enable]>
                  webservice-proto:
                    - <value in [tlsv1.2, tlsv1.1, tlsv1.0, ...]>
                  workflow-max-sessions: <value of integer>
                  workspace-mode: <value in [disabled, normal, workflow]>

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
        '/cli/global/system/global'
    ]

    url_schema = [
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object1': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'admin-lockout-duration': {
                            'type': 'integer',
                            'default': 60,
                            'example': 60
                        },
                        'admin-lockout-threshold': {
                            'type': 'integer',
                            'default': 3,
                            'example': 3
                        },
                        'adom-mode': {
                            'type': 'string',
                            'enum': [
                                'normal',
                                'advanced'
                            ]
                        },
                        'adom-rev-auto-delete': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'by-revisions',
                                'by-days'
                            ]
                        },
                        'adom-rev-max-backup-revisions': {
                            'type': 'integer',
                            'default': 5,
                            'example': 5
                        },
                        'adom-rev-max-days': {
                            'type': 'integer',
                            'default': 30,
                            'example': 30
                        },
                        'adom-rev-max-revisions': {
                            'type': 'integer',
                            'default': 120,
                            'example': 120
                        },
                        'adom-select': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'adom-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'clt-cert-req': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable',
                                'optional'
                            ]
                        },
                        'console-output': {
                            'type': 'string',
                            'enum': [
                                'standard',
                                'more'
                            ]
                        },
                        'country-flag': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'create-revision': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'daylightsavetime': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'default-disk-quota': {
                            'type': 'integer',
                            'default': 1000,
                            'example': 1000
                        },
                        'detect-unregistered-log-device': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'device-view-mode': {
                            'type': 'string',
                            'enum': [
                                'regular',
                                'tree'
                            ]
                        },
                        'dh-params': {
                            'type': 'string',
                            'enum': [
                                '1024',
                                '1536',
                                '2048',
                                '3072',
                                '4096',
                                '6144',
                                '8192'
                            ]
                        },
                        'disable-module': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'fortiview-noc'
                                ]
                            }
                        },
                        'enc-algorithm': {
                            'type': 'string',
                            'enum': [
                                'low',
                                'medium',
                                'high'
                            ]
                        },
                        'faz-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'fgfm-local-cert': {
                            'type': 'string'
                        },
                        'fgfm-ssl-protocol': {
                            'type': 'string',
                            'enum': [
                                'sslv3',
                                'tlsv1.0',
                                'tlsv1.1',
                                'tlsv1.2'
                            ]
                        },
                        'ha-member-auto-grouping': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'hitcount_concurrent': {
                            'type': 'integer',
                            'default': 100,
                            'example': 100
                        },
                        'hitcount_interval': {
                            'type': 'integer',
                            'default': 300,
                            'example': 300
                        },
                        'hostname': {
                            'type': 'string'
                        },
                        'import-ignore-addr-cmt': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'language': {
                            'type': 'string',
                            'enum': [
                                'english',
                                'simch',
                                'japanese',
                                'korean',
                                'spanish',
                                'trach'
                            ]
                        },
                        'latitude': {
                            'type': 'string'
                        },
                        'ldap-cache-timeout': {
                            'type': 'integer',
                            'default': 86400,
                            'example': 86400
                        },
                        'ldapconntimeout': {
                            'type': 'integer',
                            'default': 60000,
                            'example': 60000
                        },
                        'lock-preempt': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'log-checksum': {
                            'type': 'string',
                            'enum': [
                                'none',
                                'md5',
                                'md5-auth'
                            ]
                        },
                        'log-forward-cache-size': {
                            'type': 'integer',
                            'default': 0,
                            'example': 0
                        },
                        'longitude': {
                            'type': 'string'
                        },
                        'max-log-forward': {
                            'type': 'integer',
                            'default': 5,
                            'example': 5
                        },
                        'max-running-reports': {
                            'type': 'integer',
                            'default': 1,
                            'example': 1
                        },
                        'oftp-ssl-protocol': {
                            'type': 'string',
                            'enum': [
                                'sslv3',
                                'tlsv1.0',
                                'tlsv1.1',
                                'tlsv1.2'
                            ]
                        },
                        'partial-install': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'partial-install-force': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'partial-install-rev': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'perform-improve-by-ha': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'policy-hit-count': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'policy-object-in-dual-pane': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'pre-login-banner': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'pre-login-banner-message': {
                            'type': 'string'
                        },
                        'remoteauthtimeout': {
                            'type': 'integer',
                            'default': 10,
                            'example': 10
                        },
                        'search-all-adoms': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-low-encryption': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-protocol': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'tlsv1.2',
                                    'tlsv1.1',
                                    'tlsv1.0',
                                    'sslv3'
                                ]
                            }
                        },
                        'ssl-static-key-ciphers': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'task-list-size': {
                            'type': 'integer',
                            'default': 2000,
                            'example': 2000
                        },
                        'tftp': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'timezone': {
                            'type': 'string',
                            'enum': [
                                '00',
                                '01',
                                '02',
                                '03',
                                '04',
                                '05',
                                '06',
                                '07',
                                '08',
                                '09',
                                '10',
                                '11',
                                '12',
                                '13',
                                '14',
                                '15',
                                '16',
                                '17',
                                '18',
                                '19',
                                '20',
                                '21',
                                '22',
                                '23',
                                '24',
                                '25',
                                '26',
                                '27',
                                '28',
                                '29',
                                '30',
                                '31',
                                '32',
                                '33',
                                '34',
                                '35',
                                '36',
                                '37',
                                '38',
                                '39',
                                '40',
                                '41',
                                '42',
                                '43',
                                '44',
                                '45',
                                '46',
                                '47',
                                '48',
                                '49',
                                '50',
                                '51',
                                '52',
                                '53',
                                '54',
                                '55',
                                '56',
                                '57',
                                '58',
                                '59',
                                '60',
                                '61',
                                '62',
                                '63',
                                '64',
                                '65',
                                '66',
                                '67',
                                '68',
                                '69',
                                '70',
                                '71',
                                '72',
                                '73',
                                '74',
                                '75',
                                '76',
                                '77',
                                '78',
                                '79',
                                '80',
                                '81',
                                '82',
                                '83',
                                '84',
                                '85',
                                '86',
                                '87',
                                '88',
                                '89'
                            ]
                        },
                        'tunnel-mtu': {
                            'type': 'integer',
                            'default': 1500,
                            'example': 1500
                        },
                        'usg': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'vdom-mirror': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'webservice-proto': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'tlsv1.2',
                                    'tlsv1.1',
                                    'tlsv1.0',
                                    'sslv3',
                                    'sslv2'
                                ]
                            }
                        },
                        'workflow-max-sessions': {
                            'type': 'integer',
                            'default': 500,
                            'example': 500
                        },
                        'workspace-mode': {
                            'type': 'string',
                            'enum': [
                                'disabled',
                                'normal',
                                'workflow'
                            ]
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
            'get': 'object0',
            'set': 'object1',
            'update': 'object1'
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
