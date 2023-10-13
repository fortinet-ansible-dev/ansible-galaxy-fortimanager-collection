#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2023 Fortinet, Inc.
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
module: fmgr_casb_useractivity_match_rules
short_description: CASB user activity rules.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.3.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
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
    access_token:
        description: The token to access FortiManager without using username and password.
        required: false
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        required: false
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        required: false
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        required: false
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        required: false
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        required: false
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        required: false
        type: int
        default: 300
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    user-activity:
        description: the parameter (user-activity) in requested url
        type: str
        required: true
    match:
        description: the parameter (match) in requested url
        type: str
        required: true
    casb_useractivity_match_rules:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            case-sensitive:
                type: str
                description: CASB user activity match case sensitive.
                choices:
                    - 'disable'
                    - 'enable'
            domains:
                type: list
                elements: str
                description: no description
            header-name:
                type: str
                description: CASB user activity rule header name.
            id:
                type: int
                description: CASB user activity rule ID.
                required: true
            match-pattern:
                type: str
                description: CASB user activity rule match pattern.
                choices:
                    - 'simple'
                    - 'substr'
                    - 'regexp'
            match-value:
                type: str
                description: CASB user activity rule match value.
            methods:
                type: list
                elements: str
                description: no description
            negate:
                type: str
                description: Enable/disable what the matching strategy must not be.
                choices:
                    - 'disable'
                    - 'enable'
            type:
                type: str
                description: CASB user activity rule type.
                choices:
                    - 'domains'
                    - 'host'
                    - 'path'
                    - 'header'
                    - 'header-value'
                    - 'method'

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
    - name: CASB user activity rules.
      fmgr_casb_useractivity_match_rules:
        bypass_validation: False
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        rc_succeeded: [0, -2, -3, ...]
        rc_failed: [-2, -3, ...]
        adom: <your own value>
        user-activity: <your own value>
        match: <your own value>
        state: <value in [present, absent]>
        casb_useractivity_match_rules:
          case-sensitive: <value in [disable, enable]>
          domains: <list or string>
          header-name: <string>
          id: <integer>
          match-pattern: <value in [simple, substr, regexp]>
          match-value: <string>
          methods: <list or string>
          negate: <value in [disable, enable]>
          type: <value in [domains, host, path, ...]>

'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}/rules',
        '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}/rules'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}/rules/{rules}',
        '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}/rules/{rules}'
    ]

    url_params = ['adom', 'user-activity', 'match']
    module_primary_key = 'id'
    module_arg_spec = {
        'access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
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
        'rc_succeeded': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'rc_failed': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
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
        'adom': {
            'required': True,
            'type': 'str'
        },
        'user-activity': {
            'required': True,
            'type': 'str'
        },
        'match': {
            'required': True,
            'type': 'str'
        },
        'casb_useractivity_match_rules': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.4.1': True
            },
            'options': {
                'case-sensitive': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'domains': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'list',
                    'elements': 'str'
                },
                'header-name': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'id': {
                    'required': True,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'int'
                },
                'match-pattern': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'simple',
                        'substr',
                        'regexp'
                    ],
                    'type': 'str'
                },
                'match-value': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'methods': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'type': 'list',
                    'elements': 'str'
                },
                'negate': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'type': {
                    'required': False,
                    'revision': {
                        '7.4.1': True
                    },
                    'choices': [
                        'domains',
                        'host',
                        'path',
                        'header',
                        'header-value',
                        'method'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_useractivity_match_rules'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('access_token', module.params['access_token'] if 'access_token' in module.params else None)
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
