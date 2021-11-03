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
module: fmgr_system_alertevent
short_description: Alert events.
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
    system_alertevent:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            alert-destination:
                description: 'Alert-Destination.'
                type: list
                suboptions:
                    from:
                        type: str
                        description: 'Sender email address to use in alert emails.'
                    smtp-name:
                        type: str
                        description: 'SMTP server name.'
                    snmp-name:
                        type: str
                        description: 'SNMP trap name.'
                    syslog-name:
                        type: str
                        description: 'Syslog server name.'
                    to:
                        type: str
                        description: 'Recipient email address to use in alert emails.'
                    type:
                        type: str
                        default: 'mail'
                        description:
                         - 'Destination type.'
                         - 'mail - Send email alert.'
                         - 'snmp - Send SNMP trap.'
                         - 'syslog - Send syslog message.'
                        choices:
                            - 'mail'
                            - 'snmp'
                            - 'syslog'
            enable-generic-text:
                description: 'Enable/disable generic text match.'
                type: list
                choices:
                 - enable
                 - disable
            enable-severity-filter:
                description: 'Enable/disable alert severity filter.'
                type: list
                choices:
                 - enable
                 - disable
            event-time-period:
                type: str
                default: '0.5'
                description:
                 - 'Time period (hours).'
                 - '0.5 - 30 minutes.'
                 - '1 - 1 hour.'
                 - '3 - 3 hours.'
                 - '6 - 6 hours.'
                 - '12 - 12 hours.'
                 - '24 - 1 day.'
                 - '72 - 3 days.'
                 - '168 - 1 week.'
                choices:
                    - '0.5'
                    - '1'
                    - '3'
                    - '6'
                    - '12'
                    - '24'
                    - '72'
                    - '168'
            generic-text:
                type: str
                description: 'Text that must be contained in a log to trigger alert.'
            name:
                type: str
                description: 'Alert name.'
            num-events:
                type: str
                default: '1'
                description:
                 - 'Minimum number of events required within time period.'
                 - '1 - 1 event.'
                 - '5 - 5 events.'
                 - '10 - 10 events.'
                 - '50 - 50 events.'
                 - '100 - 100 events.'
                choices:
                    - '1'
                    - '5'
                    - '10'
                    - '50'
                    - '100'
            severity-filter:
                type: str
                default: 'high'
                description:
                 - 'Required log severity to trigger alert.'
                 - 'high - High level alert.'
                 - 'medium-high - Medium-high level alert.'
                 - 'medium - Medium level alert.'
                 - 'medium-low - Medium-low level alert.'
                 - 'low - Low level alert.'
                choices:
                    - 'high'
                    - 'medium-high'
                    - 'medium'
                    - 'medium-low'
                    - 'low'
            severity-level-comp:
                description: 'Log severity threshold comparison criterion.'
                type: list
                choices:
                 - >=
                 - =
                 - <=
            severity-level-logs:
                description: 'Log severity threshold level.'
                type: list
                choices:
                 - no-check
                 - information
                 - notify
                 - warning
                 - error
                 - critical
                 - alert
                 - emergency

'''

EXAMPLES = '''
 - hosts: fortimanager00
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Alert events.
      fmgr_system_alertevent:
         bypass_validation: False
         state: present
         system_alertevent:
            enable-generic-text:
              - enable
              - disable
            enable-severity-filter:
              - enable
              - disable
            event-time-period: 1 #<value in [0.5, 1, 3, ...]>
            name: ansible-test-sysalert
            num-events: 1 #<value in [1, 5, 10, ...]>
            severity-filter: high #<value in [high, medium-high, medium, ...]>
            #severity-level-comp:
            #  - <=
            severity-level-logs:
              - no-check
              - information
              - notify
              - warning
              - error
              - critical
              - alert
              - emergency

 - name: gathering fortimanager facts
   hosts: fortimanager00
   gather_facts: no
   connection: httpapi
   collections:
     - fortinet.fortimanager
   vars:
     ansible_httpapi_use_ssl: True
     ansible_httpapi_validate_certs: False
     ansible_httpapi_port: 443
   tasks:
    - name: retrieve all the alert events
      fmgr_fact:
        facts:
            selector: 'system_alertevent'
            params:
                alert-event: ''
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
        '/cli/global/system/alert-event'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/alert-event/{alert-event}'
    ]

    url_params = []
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
        'system_alertevent': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True
            },
            'options': {
                'alert-destination': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'from': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'smtp-name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'snmp-name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'syslog-name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'to': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'mail',
                                'snmp',
                                'syslog'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'enable-generic-text': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'enable',
                        'disable'
                    ]
                },
                'enable-severity-filter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'enable',
                        'disable'
                    ]
                },
                'event-time-period': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        '0.5',
                        '1',
                        '3',
                        '6',
                        '12',
                        '24',
                        '72',
                        '168'
                    ],
                    'type': 'str'
                },
                'generic-text': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'num-events': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        '1',
                        '5',
                        '10',
                        '50',
                        '100'
                    ],
                    'type': 'str'
                },
                'severity-filter': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'high',
                        'medium-high',
                        'medium',
                        'medium-low',
                        'low'
                    ],
                    'type': 'str'
                },
                'severity-level-comp': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        '>=',
                        '=',
                        '<='
                    ]
                },
                'severity-level-logs': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'no-check',
                        'information',
                        'notify',
                        'warning',
                        'error',
                        'critical',
                        'alert',
                        'emergency'
                    ]
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_alertevent'),
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
