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
module: fmgr_webfilter_profile_ftgdwf
short_description: FortiGuard Web Filter settings.
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
    profile:
        description: the parameter (profile) in requested url
        type: str
        required: true
    webfilter_profile_ftgdwf:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            exempt-quota:
                type: str
                description: 'Do not stop quota for these categories.'
            filters:
                description: no description
                type: list
                suboptions:
                    action:
                        type: str
                        description: 'Action to take for matches.'
                        choices:
                            - 'block'
                            - 'monitor'
                            - 'warning'
                            - 'authenticate'
                    auth-usr-grp:
                        type: str
                        description: 'Groups with permission to authenticate.'
                    category:
                        type: str
                        description: 'Categories and groups the filter examines.'
                    id:
                        type: int
                        description: 'ID number.'
                    log:
                        type: str
                        description: 'Enable/disable logging.'
                        choices:
                            - 'disable'
                            - 'enable'
                    override-replacemsg:
                        type: str
                        description: 'Override replacement message.'
                    warn-duration:
                        type: str
                        description: 'Duration of warnings.'
                    warning-duration-type:
                        type: str
                        description: 'Re-display warning after closing browser or after a timeout.'
                        choices:
                            - 'session'
                            - 'timeout'
                    warning-prompt:
                        type: str
                        description: 'Warning prompts in each category or each domain.'
                        choices:
                            - 'per-domain'
                            - 'per-category'
            max-quota-timeout:
                type: int
                description: 'Maximum FortiGuard quota used by single page view in seconds (excludes streams).'
            options:
                description: no description
                type: list
                choices:
                 - error-allow
                 - http-err-detail
                 - rate-image-urls
                 - strict-blocking
                 - rate-server-ip
                 - redir-block
                 - connect-request-bypass
                 - log-all-url
                 - ftgd-disable
            ovrd:
                type: str
                description: 'Allow web filter profile overrides.'
            quota:
                description: no description
                type: list
                suboptions:
                    category:
                        type: str
                        description: 'FortiGuard categories to apply quota to (category action must be set to monitor).'
                    duration:
                        type: str
                        description: 'Duration of quota.'
                    id:
                        type: int
                        description: 'ID number.'
                    override-replacemsg:
                        type: str
                        description: 'Override replacement message.'
                    type:
                        type: str
                        description: 'Quota type.'
                        choices:
                            - 'time'
                            - 'traffic'
                    unit:
                        type: str
                        description: 'Traffic quota unit of measurement.'
                        choices:
                            - 'B'
                            - 'KB'
                            - 'MB'
                            - 'GB'
                    value:
                        type: int
                        description: 'Traffic quota value.'
            rate-crl-urls:
                type: str
                description: 'Enable/disable rating CRL by URL.'
                choices:
                    - 'disable'
                    - 'enable'
            rate-css-urls:
                type: str
                description: 'Enable/disable rating CSS by URL.'
                choices:
                    - 'disable'
                    - 'enable'
            rate-image-urls:
                type: str
                description: 'Enable/disable rating images by URL.'
                choices:
                    - 'disable'
                    - 'enable'
            rate-javascript-urls:
                type: str
                description: 'Enable/disable rating JavaScript by URL.'
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
    - name: FortiGuard Web Filter settings.
      fmgr_webfilter_profile_ftgdwf:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         profile: <your own value>
         webfilter_profile_ftgdwf:
            exempt-quota: <value of string>
            filters:
              -
                  action: <value in [block, monitor, warning, ...]>
                  auth-usr-grp: <value of string>
                  category: <value of string>
                  id: <value of integer>
                  log: <value in [disable, enable]>
                  override-replacemsg: <value of string>
                  warn-duration: <value of string>
                  warning-duration-type: <value in [session, timeout]>
                  warning-prompt: <value in [per-domain, per-category]>
            max-quota-timeout: <value of integer>
            options:
              - error-allow
              - http-err-detail
              - rate-image-urls
              - strict-blocking
              - rate-server-ip
              - redir-block
              - connect-request-bypass
              - log-all-url
              - ftgd-disable
            ovrd: <value of string>
            quota:
              -
                  category: <value of string>
                  duration: <value of string>
                  id: <value of integer>
                  override-replacemsg: <value of string>
                  type: <value in [time, traffic]>
                  unit: <value in [B, KB, MB, ...]>
                  value: <value of integer>
            rate-crl-urls: <value in [disable, enable]>
            rate-css-urls: <value in [disable, enable]>
            rate-image-urls: <value in [disable, enable]>
            rate-javascript-urls: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf',
        '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/{ftgd-wf}',
        '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/{ftgd-wf}'
    ]

    url_params = ['adom', 'profile']
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
        'profile': {
            'required': True,
            'type': 'str'
        },
        'webfilter_profile_ftgdwf': {
            'required': False,
            'type': 'dict',
            'options': {
                'exempt-quota': {
                    'required': False,
                    'type': 'str'
                },
                'filters': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'choices': [
                                'block',
                                'monitor',
                                'warning',
                                'authenticate'
                            ],
                            'type': 'str'
                        },
                        'auth-usr-grp': {
                            'required': False,
                            'type': 'str'
                        },
                        'category': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'log': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'override-replacemsg': {
                            'required': False,
                            'type': 'str'
                        },
                        'warn-duration': {
                            'required': False,
                            'type': 'str'
                        },
                        'warning-duration-type': {
                            'required': False,
                            'choices': [
                                'session',
                                'timeout'
                            ],
                            'type': 'str'
                        },
                        'warning-prompt': {
                            'required': False,
                            'choices': [
                                'per-domain',
                                'per-category'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'max-quota-timeout': {
                    'required': False,
                    'type': 'int'
                },
                'options': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'error-allow',
                        'http-err-detail',
                        'rate-image-urls',
                        'strict-blocking',
                        'rate-server-ip',
                        'redir-block',
                        'connect-request-bypass',
                        'log-all-url',
                        'ftgd-disable'
                    ]
                },
                'ovrd': {
                    'required': False,
                    'type': 'str'
                },
                'quota': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'category': {
                            'required': False,
                            'type': 'str'
                        },
                        'duration': {
                            'required': False,
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'type': 'int'
                        },
                        'override-replacemsg': {
                            'required': False,
                            'type': 'str'
                        },
                        'type': {
                            'required': False,
                            'choices': [
                                'time',
                                'traffic'
                            ],
                            'type': 'str'
                        },
                        'unit': {
                            'required': False,
                            'choices': [
                                'B',
                                'KB',
                                'MB',
                                'GB'
                            ],
                            'type': 'str'
                        },
                        'value': {
                            'required': False,
                            'type': 'int'
                        }
                    }
                },
                'rate-crl-urls': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rate-css-urls': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rate-image-urls': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rate-javascript-urls': {
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile_ftgdwf'),
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
