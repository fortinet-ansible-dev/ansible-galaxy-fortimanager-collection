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
    webfilter_profile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
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
                description: no description
                type: list
                choices:
                 - block-invalid-url
                 - jscript
                 - js
                 - vbs
                 - unknown
                 - wf-referer
                 - https-scan
                 - intrinsic
                 - wf-cookie
                 - per-user-bwl
                 - activexfilter
                 - cookiefilter
                 - https-url-scan
                 - javafilter
                 - rangeblock
                 - contenttype-check
            ovrd-perm:
                description: no description
                type: list
                choices:
                 - bannedword-override
                 - urlfilter-override
                 - fortiguard-wf-override
                 - contenttype-check-override
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
                description: no description
                type: list
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
                choices:
                    - 'disable'
                    - 'blacklist'
                    - 'whitelist'

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
    - name: Configure Web filter profiles.
      fmgr_webfilter_profile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         webfilter_profile:
            comment: <value of string>
            extended-log: <value in [disable, enable]>
            https-replacemsg: <value in [disable, enable]>
            inspection-mode: <value in [proxy, flow-based, dns]>
            log-all-url: <value in [disable, enable]>
            name: <value of string>
            options:
              - block-invalid-url
              - jscript
              - js
              - vbs
              - unknown
              - wf-referer
              - https-scan
              - intrinsic
              - wf-cookie
              - per-user-bwl
              - activexfilter
              - cookiefilter
              - https-url-scan
              - javafilter
              - rangeblock
              - contenttype-check
            ovrd-perm:
              - bannedword-override
              - urlfilter-override
              - fortiguard-wf-override
              - contenttype-check-override
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
        '/pm/config/adom/{adom}/obj/webfilter/profile',
        '/pm/config/global/obj/webfilter/profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}',
        '/pm/config/global/obj/webfilter/profile/{profile}'
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
        'webfilter_profile': {
            'required': False,
            'type': 'dict',
            'options': {
                'comment': {
                    'required': False,
                    'type': 'str'
                },
                'extended-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'https-replacemsg': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'inspection-mode': {
                    'required': False,
                    'choices': [
                        'proxy',
                        'flow-based',
                        'dns'
                    ],
                    'type': 'str'
                },
                'log-all-url': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'type': 'str'
                },
                'options': {
                    'required': False,
                    'type': 'list',
                    'choices': [
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
                },
                'ovrd-perm': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'bannedword-override',
                        'urlfilter-override',
                        'fortiguard-wf-override',
                        'contenttype-check-override'
                    ]
                },
                'post-action': {
                    'required': False,
                    'choices': [
                        'normal',
                        'comfort',
                        'block'
                    ],
                    'type': 'str'
                },
                'replacemsg-group': {
                    'required': False,
                    'type': 'str'
                },
                'web-content-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-extended-all-action-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-filter-activex-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-filter-applet-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-filter-command-block-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-filter-cookie-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-filter-cookie-removal-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-filter-js-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-filter-jscript-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-filter-referer-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-filter-unknown-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-filter-vbs-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-ftgd-err-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-ftgd-quota-usage': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-invalid-domain-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'web-url-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'wisp': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'wisp-algorithm': {
                    'required': False,
                    'choices': [
                        'auto-learning',
                        'primary-secondary',
                        'round-robin'
                    ],
                    'type': 'str'
                },
                'wisp-servers': {
                    'required': False,
                    'type': 'str'
                },
                'youtube-channel-filter': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'channel-id': {
                            'required': False,
                            'type': 'str'
                        },
                        'comment': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        }
                    }
                },
                'youtube-channel-status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'blacklist',
                        'whitelist'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile'),
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
