#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2021 Fortinet, Inc.
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
module: fmgr_pm_config_pblock_firewall_securitypolicy
short_description: no description
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: |
          only set to True when module schema diffs with FortiManager API structure,
           module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: |
          the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
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
    pblock:
        description: the parameter (pblock) in requested url
        type: str
        required: true
    pm_config_pblock_firewall_securitypolicy:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            _policy_block:
                type: int
                description: no description
            action:
                type: str
                description: no description
                choices:
                    - 'deny'
                    - 'accept'
            app-category:
                description: description
                type: str
            app-group:
                description: description
                type: str
            application:
                description: description
                type: int
            application-list:
                type: str
                description: no description
            av-profile:
                type: str
                description: no description
            cifs-profile:
                type: str
                description: no description
            comments:
                type: str
                description: no description
            dlp-profile:
                type: str
                description: no description
            dnsfilter-profile:
                type: str
                description: no description
            dstaddr:
                description: description
                type: str
            dstaddr-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6:
                description: description
                type: str
            dstintf:
                description: description
                type: str
            emailfilter-profile:
                type: str
                description: no description
            enforce-default-app-port:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            file-filter-profile:
                type: str
                description: no description
            fsso-groups:
                description: description
                type: str
            global-label:
                type: str
                description: no description
            groups:
                description: description
                type: str
            icap-profile:
                type: str
                description: no description
            internet-service:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-custom:
                description: description
                type: str
            internet-service-custom-group:
                description: description
                type: str
            internet-service-group:
                description: description
                type: str
            internet-service-name:
                description: description
                type: str
            internet-service-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src-custom:
                description: description
                type: str
            internet-service-src-custom-group:
                description: description
                type: str
            internet-service-src-group:
                description: description
                type: str
            internet-service-src-name:
                description: description
                type: str
            internet-service-src-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ips-sensor:
                type: str
                description: no description
            learning-mode:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'all'
                    - 'utm'
            name:
                type: str
                description: no description
            nat46:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            nat64:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            policyid:
                type: int
                description: no description
            profile-group:
                type: str
                description: no description
            profile-protocol-options:
                type: str
                description: no description
            profile-type:
                type: str
                description: no description
                choices:
                    - 'single'
                    - 'group'
            schedule:
                type: str
                description: no description
            sctp-filter-profile:
                type: str
                description: no description
            send-deny-packet:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            service:
                description: description
                type: str
            service-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr:
                description: description
                type: str
            srcaddr-negate:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr6:
                description: description
                type: str
            srcintf:
                description: description
                type: str
            ssh-filter-profile:
                type: str
                description: no description
            ssl-ssh-profile:
                type: str
                description: no description
            status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            url-category:
                description: description
                type: str
            users:
                description: description
                type: str
            utm-status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: no description
            videofilter-profile:
                type: str
                description: no description
            voip-profile:
                type: str
                description: no description
            webfilter-profile:
                type: str
                description: no description

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
    - name: no description
      fmgr_pm_config_pblock_firewall_securitypolicy:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         pblock: <your own value>
         state: <value in [present, absent]>
         pm_config_pblock_firewall_securitypolicy:
            _policy_block: <value of integer>
            action: <value in [deny, accept]>
            app-category: <value of string>
            app-group: <value of string>
            application: <value of integer>
            application-list: <value of string>
            av-profile: <value of string>
            cifs-profile: <value of string>
            comments: <value of string>
            dlp-profile: <value of string>
            dnsfilter-profile: <value of string>
            dstaddr: <value of string>
            dstaddr-negate: <value in [disable, enable]>
            dstaddr6: <value of string>
            dstintf: <value of string>
            emailfilter-profile: <value of string>
            enforce-default-app-port: <value in [disable, enable]>
            file-filter-profile: <value of string>
            fsso-groups: <value of string>
            global-label: <value of string>
            groups: <value of string>
            icap-profile: <value of string>
            internet-service: <value in [disable, enable]>
            internet-service-custom: <value of string>
            internet-service-custom-group: <value of string>
            internet-service-group: <value of string>
            internet-service-name: <value of string>
            internet-service-negate: <value in [disable, enable]>
            internet-service-src: <value in [disable, enable]>
            internet-service-src-custom: <value of string>
            internet-service-src-custom-group: <value of string>
            internet-service-src-group: <value of string>
            internet-service-src-name: <value of string>
            internet-service-src-negate: <value in [disable, enable]>
            ips-sensor: <value of string>
            learning-mode: <value in [disable, enable]>
            logtraffic: <value in [disable, all, utm]>
            name: <value of string>
            nat46: <value in [disable, enable]>
            nat64: <value in [disable, enable]>
            policyid: <value of integer>
            profile-group: <value of string>
            profile-protocol-options: <value of string>
            profile-type: <value in [single, group]>
            schedule: <value of string>
            sctp-filter-profile: <value of string>
            send-deny-packet: <value in [disable, enable]>
            service: <value of string>
            service-negate: <value in [disable, enable]>
            srcaddr: <value of string>
            srcaddr-negate: <value in [disable, enable]>
            srcaddr6: <value of string>
            srcintf: <value of string>
            ssh-filter-profile: <value of string>
            ssl-ssh-profile: <value of string>
            status: <value in [disable, enable]>
            url-category: <value of string>
            users: <value of string>
            utm-status: <value in [disable, enable]>
            uuid: <value of string>
            videofilter-profile: <value of string>
            voip-profile: <value of string>
            webfilter-profile: <value of string>

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
        '/pm/config/adom/{adom}/pblock/{pblock}/firewall/security-policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pblock/{pblock}/firewall/security-policy/{security-policy}'
    ]

    url_params = ['adom', 'pblock']
    module_primary_key = 'name'
    module_arg_spec = {
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
        'pblock': {
            'required': True,
            'type': 'str'
        },
        'pm_config_pblock_firewall_securitypolicy': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.2.0': True
            },
            'options': {
                '_policy_block': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'action': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'deny',
                        'accept'
                    ],
                    'type': 'str'
                },
                'app-category': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'app-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'application': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'application-list': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'av-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'cifs-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'comments': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dlp-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dnsfilter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dstaddr': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dstaddr-negate': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dstaddr6': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dstintf': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'emailfilter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'enforce-default-app-port': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'file-filter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'fsso-groups': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'global-label': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'groups': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'icap-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'internet-service-custom': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-custom-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-name': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-negate': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'internet-service-src': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'internet-service-src-custom': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-src-custom-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-src-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-src-name': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'internet-service-src-negate': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ips-sensor': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'learning-mode': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'logtraffic': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'all',
                        'utm'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'nat46': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'nat64': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'policyid': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'profile-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'profile-protocol-options': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'profile-type': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'single',
                        'group'
                    ],
                    'type': 'str'
                },
                'schedule': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sctp-filter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'send-deny-packet': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'service': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'service-negate': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'srcaddr': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'srcaddr-negate': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'srcaddr6': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'srcintf': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ssh-filter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'ssl-ssh-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'url-category': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'users': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'utm-status': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'uuid': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'videofilter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'voip-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'webfilter-profile': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pm_config_pblock_firewall_securitypolicy'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
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
