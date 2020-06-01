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
module: fmgr_webfilter_profile
short_description: Configure Web filter profiles.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ add get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/webfilter/profile
    - /pm/config/global/obj/webfilter/profile
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

    - name: REQUESTING /PM/CONFIG/OBJ/WEBFILTER/PROFILE
      fmgr_webfilter_profile:
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
                     comment: <value of string>
                     extended-log: <value in [disable, enable]>
                     https-replacemsg: <value in [disable, enable]>
                     inspection-mode: <value in [proxy, flow-based, dns]>
                     log-all-url: <value in [disable, enable]>
                     name: <value of string>
                     options:
                       - <value in [block-invalid-url, jscript, js, ...]>
                     ovrd-perm:
                       - <value in [bannedword-override, urlfilter-override, fortiguard-wf-override, ...]>
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

    - name: REQUESTING /PM/CONFIG/OBJ/WEBFILTER/PROFILE
      fmgr_webfilter_profile:
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
                    - <value in [comment, extended-log, https-replacemsg, ...]>
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
        '/pm/config/adom/{adom}/obj/webfilter/profile',
        '/pm/config/global/obj/webfilter/profile'
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
                        'comment': {
                            'type': 'string'
                        },
                        'extended-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'https-replacemsg': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'inspection-mode': {
                            'type': 'string',
                            'enum': [
                                'proxy',
                                'flow-based',
                                'dns'
                            ]
                        },
                        'log-all-url': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'name': {
                            'type': 'string'
                        },
                        'options': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
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
                                    'contenttype-check'
                                ]
                            }
                        },
                        'ovrd-perm': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'bannedword-override',
                                    'urlfilter-override',
                                    'fortiguard-wf-override',
                                    'contenttype-check-override'
                                ]
                            }
                        },
                        'post-action': {
                            'type': 'string',
                            'enum': [
                                'normal',
                                'comfort',
                                'block'
                            ]
                        },
                        'replacemsg-group': {
                            'type': 'string'
                        },
                        'web-content-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-extended-all-action-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-filter-activex-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-filter-applet-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-filter-command-block-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-filter-cookie-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-filter-cookie-removal-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-filter-js-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-filter-jscript-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-filter-referer-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-filter-unknown-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-filter-vbs-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-ftgd-err-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-ftgd-quota-usage': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-invalid-domain-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'web-url-log': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'wisp': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'wisp-algorithm': {
                            'type': 'string',
                            'enum': [
                                'auto-learning',
                                'primary-secondary',
                                'round-robin'
                            ]
                        },
                        'wisp-servers': {
                            'type': 'string'
                        },
                        'youtube-channel-filter': {
                            'type': 'array',
                            'items': {
                                'channel-id': {
                                    'type': 'string'
                                },
                                'comment': {
                                    'type': 'string'
                                },
                                'id': {
                                    'type': 'integer'
                                }
                            }
                        },
                        'youtube-channel-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'blacklist',
                                'whitelist'
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
                                'comment',
                                'extended-log',
                                'https-replacemsg',
                                'inspection-mode',
                                'log-all-url',
                                'name',
                                'options',
                                'ovrd-perm',
                                'post-action',
                                'replacemsg-group',
                                'web-content-log',
                                'web-extended-all-action-log',
                                'web-filter-activex-log',
                                'web-filter-applet-log',
                                'web-filter-command-block-log',
                                'web-filter-cookie-log',
                                'web-filter-cookie-removal-log',
                                'web-filter-js-log',
                                'web-filter-jscript-log',
                                'web-filter-referer-log',
                                'web-filter-unknown-log',
                                'web-filter-vbs-log',
                                'web-ftgd-err-log',
                                'web-ftgd-quota-usage',
                                'web-invalid-domain-log',
                                'web-url-log',
                                'wisp',
                                'wisp-algorithm',
                                'wisp-servers',
                                'youtube-channel-status'
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
