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
module: fmgr_sshfilter_profile
short_description: SSH filter profile.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
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
    sshfilter_profile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            block:
                type: list
                elements: str
                description: SSH blocking options.
                choices:
                    - 'x11'
                    - 'shell'
                    - 'exec'
                    - 'port-forward'
                    - 'tun-forward'
                    - 'sftp'
                    - 'unknown'
                    - 'scp'
            default-command-log:
                type: str
                description: Enable/disable logging unmatched shell commands.
                choices:
                    - 'disable'
                    - 'enable'
            log:
                type: list
                elements: str
                description: SSH logging options.
                choices:
                    - 'x11'
                    - 'shell'
                    - 'exec'
                    - 'port-forward'
                    - 'tun-forward'
                    - 'sftp'
                    - 'unknown'
                    - 'scp'
            name:
                type: str
                description: SSH filter profile name.
                required: true
            shell-commands:
                type: list
                elements: dict
                description: Shell-Commands.
                suboptions:
                    action:
                        type: str
                        description: Action to take for URL filter matches.
                        choices:
                            - 'block'
                            - 'allow'
                    alert:
                        type: str
                        description: Enable/disable alert.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: Id.
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    pattern:
                        type: str
                        description: SSH shell command pattern.
                    severity:
                        type: str
                        description: Log severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    type:
                        type: str
                        description: Matching type.
                        choices:
                            - 'regex'
                            - 'simple'
            file-filter:
                type: dict
                description: no description
                suboptions:
                    entries:
                        type: list
                        elements: dict
                        description: no description
                        suboptions:
                            action:
                                type: str
                                description: Action taken for matched file.
                                choices:
                                    - 'log'
                                    - 'block'
                            comment:
                                type: str
                                description: Comment.
                            direction:
                                type: str
                                description: Match files transmitted in the sessions originating or reply direction.
                                choices:
                                    - 'any'
                                    - 'incoming'
                                    - 'outgoing'
                            file-type:
                                type: raw
                                description: (list) no description
                            filter:
                                type: str
                                description: Add a file filter.
                            password-protected:
                                type: str
                                description: Match password-protected files.
                                choices:
                                    - 'any'
                                    - 'yes'
                            protocol:
                                type: list
                                elements: str
                                description: no description
                                choices:
                                    - 'ssh'
                    log:
                        type: str
                        description: Enable/disable file filter logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    scan-archive-contents:
                        type: str
                        description: Enable/disable file filter archive contents scan.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable file filter.
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
    - name: SSH filter profile.
      fmgr_sshfilter_profile:
        bypass_validation: False
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        rc_succeeded: [0, -2, -3, ...]
        rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: <value in [present, absent]>
        sshfilter_profile:
          block:
            - x11
            - shell
            - exec
            - port-forward
            - tun-forward
            - sftp
            - unknown
            - scp
          default-command-log: <value in [disable, enable]>
          log:
            - x11
            - shell
            - exec
            - port-forward
            - tun-forward
            - sftp
            - unknown
            - scp
          name: <string>
          shell-commands:
            -
              action: <value in [block, allow]>
              alert: <value in [disable, enable]>
              id: <integer>
              log: <value in [disable, enable]>
              pattern: <string>
              severity: <value in [low, medium, high, ...]>
              type: <value in [regex, simple]>
          file-filter:
            entries:
              -
                action: <value in [log, block]>
                comment: <string>
                direction: <value in [any, incoming, outgoing]>
                file-type: <list or string>
                filter: <string>
                password-protected: <value in [any, yes]>
                protocol:
                  - ssh
            log: <value in [disable, enable]>
            scan-archive-contents: <value in [disable, enable]>
            status: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/obj/ssh-filter/profile',
        '/pm/config/global/obj/ssh-filter/profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}',
        '/pm/config/global/obj/ssh-filter/profile/{profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
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
        'sshfilter_profile': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.2.11': True,
                '6.2.12': True,
                '6.4.0': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '6.4.6': True,
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '6.4.12': True,
                '6.4.13': True,
                '7.0.0': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.0.8': True,
                '7.0.9': True,
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.2.3': True,
                '7.2.4': True,
                '7.4.0': True,
                '7.4.1': True
            },
            'options': {
                'block': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.0': True,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'list',
                    'choices': [
                        'x11',
                        'shell',
                        'exec',
                        'port-forward',
                        'tun-forward',
                        'sftp',
                        'unknown',
                        'scp'
                    ],
                    'elements': 'str'
                },
                'default-command-log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.0': True,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'log': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.0': True,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'list',
                    'choices': [
                        'x11',
                        'shell',
                        'exec',
                        'port-forward',
                        'tun-forward',
                        'sftp',
                        'unknown',
                        'scp'
                    ],
                    'elements': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.0': True,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'str'
                },
                'shell-commands': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.0': True,
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.2.11': True,
                        '6.2.12': True,
                        '6.4.0': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '6.4.12': True,
                        '6.4.13': True,
                        '7.0.0': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.0.8': True,
                        '7.0.9': True,
                        '7.2.0': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.2.3': True,
                        '7.2.4': True,
                        '7.4.0': True,
                        '7.4.1': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.0': True,
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.2.11': True,
                                '6.2.12': True,
                                '6.4.0': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '6.4.12': True,
                                '6.4.13': True,
                                '7.0.0': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.0.8': True,
                                '7.0.9': True,
                                '7.2.0': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.2.3': True,
                                '7.2.4': True,
                                '7.4.0': True,
                                '7.4.1': True
                            },
                            'choices': [
                                'block',
                                'allow'
                            ],
                            'type': 'str'
                        },
                        'alert': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.0': True,
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.2.11': True,
                                '6.2.12': True,
                                '6.4.0': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '6.4.12': True,
                                '6.4.13': True,
                                '7.0.0': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.0.8': True,
                                '7.0.9': True,
                                '7.2.0': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.2.3': True,
                                '7.2.4': True,
                                '7.4.0': True,
                                '7.4.1': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.0': True,
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.2.11': True,
                                '6.2.12': True,
                                '6.4.0': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '6.4.12': True,
                                '6.4.13': True,
                                '7.0.0': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.0.8': True,
                                '7.0.9': True,
                                '7.2.0': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.2.3': True,
                                '7.2.4': True,
                                '7.4.0': True,
                                '7.4.1': True
                            },
                            'type': 'int'
                        },
                        'log': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.0': True,
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.2.11': True,
                                '6.2.12': True,
                                '6.4.0': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '6.4.12': True,
                                '6.4.13': True,
                                '7.0.0': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.0.8': True,
                                '7.0.9': True,
                                '7.2.0': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.2.3': True,
                                '7.2.4': True,
                                '7.4.0': True,
                                '7.4.1': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'pattern': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.0': True,
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.2.11': True,
                                '6.2.12': True,
                                '6.4.0': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '6.4.12': True,
                                '6.4.13': True,
                                '7.0.0': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.0.8': True,
                                '7.0.9': True,
                                '7.2.0': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.2.3': True,
                                '7.2.4': True,
                                '7.4.0': True,
                                '7.4.1': True
                            },
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.0': True,
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.2.11': True,
                                '6.2.12': True,
                                '6.4.0': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '6.4.12': True,
                                '6.4.13': True,
                                '7.0.0': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.0.8': True,
                                '7.0.9': True,
                                '7.2.0': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.2.3': True,
                                '7.2.4': True,
                                '7.4.0': True,
                                '7.4.1': True
                            },
                            'choices': [
                                'low',
                                'medium',
                                'high',
                                'critical'
                            ],
                            'type': 'str'
                        },
                        'type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.0': True,
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.2.11': True,
                                '6.2.12': True,
                                '6.4.0': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '6.4.12': True,
                                '6.4.13': True,
                                '7.0.0': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.0.8': True,
                                '7.0.9': True,
                                '7.2.0': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.2.3': True,
                                '7.2.4': True,
                                '7.4.0': True,
                                '7.4.1': True
                            },
                            'choices': [
                                'regex',
                                'simple'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'file-filter': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'entries': {
                            'required': False,
                            'revision': {
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.2.11': True,
                                '6.2.12': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.5': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '6.4.12': True,
                                '6.4.13': True,
                                '7.0.0': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.0.8': True,
                                '7.0.9': True,
                                '7.2.0': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.2.3': True,
                                '7.2.4': True,
                                '7.4.0': True,
                                '7.4.1': True
                            },
                            'type': 'list',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.2.11': True,
                                        '6.2.12': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.5': True,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '6.4.12': True,
                                        '6.4.13': True,
                                        '7.0.0': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.0.8': True,
                                        '7.0.9': True,
                                        '7.2.0': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.2.3': True,
                                        '7.2.4': True,
                                        '7.4.0': True,
                                        '7.4.1': True
                                    },
                                    'choices': [
                                        'log',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'comment': {
                                    'required': False,
                                    'revision': {
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.2.11': True,
                                        '6.2.12': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.5': True,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '6.4.12': True,
                                        '6.4.13': True,
                                        '7.0.0': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.0.8': True,
                                        '7.0.9': True,
                                        '7.2.0': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.2.3': True,
                                        '7.2.4': True,
                                        '7.4.0': True,
                                        '7.4.1': True
                                    },
                                    'type': 'str'
                                },
                                'direction': {
                                    'required': False,
                                    'revision': {
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.2.11': True,
                                        '6.2.12': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.5': True,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '6.4.12': True,
                                        '6.4.13': True,
                                        '7.0.0': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.0.8': True,
                                        '7.0.9': True,
                                        '7.2.0': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.2.3': True,
                                        '7.2.4': True,
                                        '7.4.0': True,
                                        '7.4.1': True
                                    },
                                    'choices': [
                                        'any',
                                        'incoming',
                                        'outgoing'
                                    ],
                                    'type': 'str'
                                },
                                'file-type': {
                                    'required': False,
                                    'revision': {
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.2.11': True,
                                        '6.2.12': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.5': True,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '6.4.12': True,
                                        '6.4.13': True,
                                        '7.0.0': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.0.8': True,
                                        '7.0.9': True,
                                        '7.2.0': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.2.3': True,
                                        '7.2.4': True,
                                        '7.4.0': True,
                                        '7.4.1': True
                                    },
                                    'type': 'raw'
                                },
                                'filter': {
                                    'required': False,
                                    'revision': {
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.2.11': True,
                                        '6.2.12': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.5': True,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '6.4.12': True,
                                        '6.4.13': True,
                                        '7.0.0': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.0.8': True,
                                        '7.0.9': True,
                                        '7.2.0': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.2.3': True,
                                        '7.2.4': True,
                                        '7.4.0': True,
                                        '7.4.1': True
                                    },
                                    'type': 'str'
                                },
                                'password-protected': {
                                    'required': False,
                                    'revision': {
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.2.11': True,
                                        '6.2.12': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.5': True,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '6.4.12': True,
                                        '6.4.13': True,
                                        '7.0.0': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.0.8': True,
                                        '7.0.9': True,
                                        '7.2.0': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.2.3': True,
                                        '7.2.4': True,
                                        '7.4.0': True,
                                        '7.4.1': True
                                    },
                                    'choices': [
                                        'any',
                                        'yes'
                                    ],
                                    'type': 'str'
                                },
                                'protocol': {
                                    'required': False,
                                    'revision': {
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
                                        '6.2.11': True,
                                        '6.2.12': True,
                                        '6.4.1': False,
                                        '6.4.3': False,
                                        '6.4.4': False,
                                        '6.4.5': True,
                                        '6.4.6': True,
                                        '6.4.7': True,
                                        '6.4.8': True,
                                        '6.4.9': True,
                                        '6.4.10': True,
                                        '6.4.11': True,
                                        '6.4.12': True,
                                        '6.4.13': True,
                                        '7.0.0': True,
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': True,
                                        '7.0.4': True,
                                        '7.0.5': True,
                                        '7.0.6': True,
                                        '7.0.7': True,
                                        '7.0.8': True,
                                        '7.0.9': True,
                                        '7.2.0': True,
                                        '7.2.1': True,
                                        '7.2.2': True,
                                        '7.2.3': True,
                                        '7.2.4': True,
                                        '7.4.0': True,
                                        '7.4.1': True
                                    },
                                    'type': 'list',
                                    'choices': [
                                        'ssh'
                                    ],
                                    'elements': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'log': {
                            'required': False,
                            'revision': {
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.2.11': True,
                                '6.2.12': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.5': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '6.4.12': True,
                                '6.4.13': True,
                                '7.0.0': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.0.8': True,
                                '7.0.9': True,
                                '7.2.0': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.2.3': True,
                                '7.2.4': True,
                                '7.4.0': True,
                                '7.4.1': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'scan-archive-contents': {
                            'required': False,
                            'revision': {
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.2.11': True,
                                '6.2.12': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.5': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '6.4.12': True,
                                '6.4.13': True,
                                '7.0.0': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.0.8': True,
                                '7.0.9': True,
                                '7.2.0': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.2.3': True,
                                '7.2.4': True,
                                '7.4.0': True,
                                '7.4.1': True
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
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.2.11': True,
                                '6.2.12': True,
                                '6.4.1': False,
                                '6.4.3': False,
                                '6.4.4': False,
                                '6.4.5': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '6.4.12': True,
                                '6.4.13': True,
                                '7.0.0': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.0.8': True,
                                '7.0.9': True,
                                '7.2.0': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.2.3': True,
                                '7.2.4': True,
                                '7.4.0': True,
                                '7.4.1': True
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

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'sshfilter_profile'),
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
