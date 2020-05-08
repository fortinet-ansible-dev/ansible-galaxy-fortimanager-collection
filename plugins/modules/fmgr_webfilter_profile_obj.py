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
module: fmgr_webfilter_profile_obj
short_description: Configure Web filter profiles.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ clone delete get set update ] the following apis.
    - /pm/config/adom/{adom}/obj/webfilter/profile/{profile}
    - /pm/config/global/obj/webfilter/profile/{profile}
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
        description: Do parameter validation in a loose way
        required: False
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock in case FortiManager running in workspace mode
        required: False
        type: string
        choices:
          - global
          - custom adom
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: False
        type: integer
        default: 300
    url_params:
        description: the parameters in url path
        required: True
        type: dict
        suboptions:
            adom:
                type: str
                description: the domain prefix, the none and global are reserved
                choices:
                  - none
                  - global
                  - custom dom
            profile:
                type: str
    schema_object0:
        methods: [clone, set, update]
        description: 'Configure Web filter profiles.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                comment:
                    type: str
                    description: 'Optional comments.'
                extended-log:
                    type: str
                    description: 'Enable/disable extended logging for web filtering.'
                    choices:
                        - 'disable'
                        - 'enable'
                https-replacemsg:
                    type: str
                    description: 'Enable replacement messages for HTTPS.'
                    choices:
                        - 'disable'
                        - 'enable'
                inspection-mode:
                    type: str
                    description: 'Web filtering inspection mode.'
                    choices:
                        - 'proxy'
                        - 'flow-based'
                        - 'dns'
                log-all-url:
                    type: str
                    description: 'Enable/disable logging all URLs visited.'
                    choices:
                        - 'disable'
                        - 'enable'
                name:
                    type: str
                    description: 'Profile name.'
                options:
                    -
                        type: str
                        choices:
                            - 'block-invalid-url'
                            - 'jscript'
                            - 'js'
                            - 'vbs'
                            - 'unknown'
                            - 'wf-referer'
                            - 'https-scan'
                            - 'intrinsic'
                            - 'wf-cookie'
                            - 'per-user-bwl'
                            - 'activexfilter'
                            - 'cookiefilter'
                            - 'https-url-scan'
                            - 'javafilter'
                            - 'rangeblock'
                            - 'contenttype-check'
                ovrd-perm:
                    -
                        type: str
                        choices:
                            - 'bannedword-override'
                            - 'urlfilter-override'
                            - 'fortiguard-wf-override'
                            - 'contenttype-check-override'
                post-action:
                    type: str
                    description: 'Action taken for HTTP POST traffic.'
                    choices:
                        - 'normal'
                        - 'comfort'
                        - 'block'
                replacemsg-group:
                    type: str
                    description: 'Replacement message group.'
                web-content-log:
                    type: str
                    description: 'Enable/disable logging logging blocked web content.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-extended-all-action-log:
                    type: str
                    description: 'Enable/disable extended any filter action logging for web filtering.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-filter-activex-log:
                    type: str
                    description: 'Enable/disable logging ActiveX.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-filter-applet-log:
                    type: str
                    description: 'Enable/disable logging Java applets.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-filter-command-block-log:
                    type: str
                    description: 'Enable/disable logging blocked commands.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-filter-cookie-log:
                    type: str
                    description: 'Enable/disable logging cookie filtering.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-filter-cookie-removal-log:
                    type: str
                    description: 'Enable/disable logging blocked cookies.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-filter-js-log:
                    type: str
                    description: 'Enable/disable logging Java scripts.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-filter-jscript-log:
                    type: str
                    description: 'Enable/disable logging JScripts.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-filter-referer-log:
                    type: str
                    description: 'Enable/disable logging referrers.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-filter-unknown-log:
                    type: str
                    description: 'Enable/disable logging unknown scripts.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-filter-vbs-log:
                    type: str
                    description: 'Enable/disable logging VBS scripts.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-ftgd-err-log:
                    type: str
                    description: 'Enable/disable logging rating errors.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-ftgd-quota-usage:
                    type: str
                    description: 'Enable/disable logging daily quota usage.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-invalid-domain-log:
                    type: str
                    description: 'Enable/disable logging invalid domain names.'
                    choices:
                        - 'disable'
                        - 'enable'
                web-url-log:
                    type: str
                    description: 'Enable/disable logging URL filtering.'
                    choices:
                        - 'disable'
                        - 'enable'
                wisp:
                    type: str
                    description: 'Enable/disable web proxy WISP.'
                    choices:
                        - 'disable'
                        - 'enable'
                wisp-algorithm:
                    type: str
                    description: 'WISP server selection algorithm.'
                    choices:
                        - 'auto-learning'
                        - 'primary-secondary'
                        - 'round-robin'
                wisp-servers:
                    type: str
                    description: 'WISP servers.'
                youtube-channel-filter:
                    -
                        channel-id:
                            type: str
                            description: 'YouTube channel ID to be filtered.'
                        comment:
                            type: str
                            description: 'Comment.'
                        id:
                            type: int
                            description: 'ID.'
                youtube-channel-status:
                    type: str
                    description: 'YouTube channel filter status.'
                    choices:
                        - 'disable'
                        - 'blacklist'
                        - 'whitelist'
    schema_object1:
        methods: [delete]
        description: 'Configure Web filter profiles.'
        api_categories: [api_tag0]
        api_tag0:
    schema_object2:
        methods: [get]
        description: 'Configure Web filter profiles.'
        api_categories: [api_tag0]
        api_tag0:
            option:
                type: str
                description:
                 - 'Set fetch option for the request. If no option is specified, by default the attributes of the object will be returned.'
                 - 'object member - Return a list of object members along with other attributes.'
                 - 'chksum - Return the check-sum value instead of attributes.'
                choices:
                    - 'object member'
                    - 'chksum'
                    - 'datasrc'

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

    - name: REQUESTING /PM/CONFIG/OBJ/WEBFILTER/PROFILE/{PROFILE}
      fmgr_webfilter_profile_obj:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [clone, set, update]>
         url_params:
            adom: <value in [none, global, custom dom]>
            profile: <value of string>
         params:
            -
               data:
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

    - name: REQUESTING /PM/CONFIG/OBJ/WEBFILTER/PROFILE/{PROFILE}
      fmgr_webfilter_profile_obj:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [get]>
         url_params:
            adom: <value in [none, global, custom dom]>
            profile: <value of string>
         params:
            -
               option: <value in [object member, chksum, datasrc]>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[clone, delete, set, update]
   returned: always
   suboptions:
      id:
         type: int
      result:
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}'
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            comment:
               type: str
               description: 'Optional comments.'
            extended-log:
               type: str
               description: 'Enable/disable extended logging for web filtering.'
            https-replacemsg:
               type: str
               description: 'Enable replacement messages for HTTPS.'
            inspection-mode:
               type: str
               description: 'Web filtering inspection mode.'
            log-all-url:
               type: str
               description: 'Enable/disable logging all URLs visited.'
            name:
               type: str
               description: 'Profile name.'
            options:
               type: array
               suboptions:
                  type: str
            ovrd-perm:
               type: array
               suboptions:
                  type: str
            post-action:
               type: str
               description: 'Action taken for HTTP POST traffic.'
            replacemsg-group:
               type: str
               description: 'Replacement message group.'
            web-content-log:
               type: str
               description: 'Enable/disable logging logging blocked web content.'
            web-extended-all-action-log:
               type: str
               description: 'Enable/disable extended any filter action logging for web filtering.'
            web-filter-activex-log:
               type: str
               description: 'Enable/disable logging ActiveX.'
            web-filter-applet-log:
               type: str
               description: 'Enable/disable logging Java applets.'
            web-filter-command-block-log:
               type: str
               description: 'Enable/disable logging blocked commands.'
            web-filter-cookie-log:
               type: str
               description: 'Enable/disable logging cookie filtering.'
            web-filter-cookie-removal-log:
               type: str
               description: 'Enable/disable logging blocked cookies.'
            web-filter-js-log:
               type: str
               description: 'Enable/disable logging Java scripts.'
            web-filter-jscript-log:
               type: str
               description: 'Enable/disable logging JScripts.'
            web-filter-referer-log:
               type: str
               description: 'Enable/disable logging referrers.'
            web-filter-unknown-log:
               type: str
               description: 'Enable/disable logging unknown scripts.'
            web-filter-vbs-log:
               type: str
               description: 'Enable/disable logging VBS scripts.'
            web-ftgd-err-log:
               type: str
               description: 'Enable/disable logging rating errors.'
            web-ftgd-quota-usage:
               type: str
               description: 'Enable/disable logging daily quota usage.'
            web-invalid-domain-log:
               type: str
               description: 'Enable/disable logging invalid domain names.'
            web-url-log:
               type: str
               description: 'Enable/disable logging URL filtering.'
            wisp:
               type: str
               description: 'Enable/disable web proxy WISP.'
            wisp-algorithm:
               type: str
               description: 'WISP server selection algorithm.'
            wisp-servers:
               type: str
               description: 'WISP servers.'
            youtube-channel-filter:
               type: array
               suboptions:
                  channel-id:
                     type: str
                     description: 'YouTube channel ID to be filtered.'
                  comment:
                     type: str
                     description: 'Comment.'
                  id:
                     type: int
                     description: 'ID.'
            youtube-channel-status:
               type: str
               description: 'YouTube channel filter status.'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}'

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
        '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}',
        '/pm/config/global/obj/webfilter/profile/{profile}'
    ]

    url_schema = [
        {
            'name': 'adom',
            'type': 'string'
        },
        {
            'name': 'profile',
            'type': 'string'
        }
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
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
                    },
                    'api_tag': 0
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
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object2': [
                {
                    'name': 'option',
                    'type': 'dict',
                    'dict': {
                        'type': 'string',
                        'enum': [
                            'object member',
                            'chksum',
                            'datasrc'
                        ]
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
            'clone': 'object0',
            'delete': 'object1',
            'get': 'object2',
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
                'clone',
                'delete',
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
