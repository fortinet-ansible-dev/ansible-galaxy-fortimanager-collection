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
module: fmgr_extendercontroller_extenderprofile
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
    extendercontroller_extenderprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            allowaccess:
                description: description
                type: list
                choices:
                 - https
                 - ping
                 - ssh
                 - snmp
                 - http
                 - telnet
            bandwidth-limit:
                type: int
                description: no description
            cellular:
                description: no description
                type: dict
                required: false
                suboptions:
                    controller-report:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            interval:
                                type: int
                                description: no description
                            signal-threshold:
                                type: int
                                description: no description
                            status:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                    dataplan:
                        description: description
                        type: str
                    modem1:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            auto-switch:
                                description: no description
                                type: dict
                                required: false
                                suboptions:
                                    dataplan:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect-period:
                                        type: int
                                        description: no description
                                    disconnect-threshold:
                                        type: int
                                        description: no description
                                    signal:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    switch-back:
                                        description: description
                                        type: list
                                        choices:
                                         - time
                                         - timer
                                    switch-back-time:
                                        type: str
                                        description: no description
                                    switch-back-timer:
                                        type: int
                                        description: no description
                            conn-status:
                                type: int
                                description: no description
                            default-sim:
                                type: str
                                description: no description
                                choices:
                                    - 'sim1'
                                    - 'sim2'
                                    - 'carrier'
                                    - 'cost'
                            gps:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            modem-id:
                                type: int
                                description: no description
                            preferred-carrier:
                                type: str
                                description: no description
                            redundant-intf:
                                type: str
                                description: no description
                            redundant-mode:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1-pin:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1-pin-code:
                                description: description
                                type: str
                            sim2-pin:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim2-pin-code:
                                description: description
                                type: str
                    modem2:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            auto-switch:
                                description: no description
                                type: dict
                                required: false
                                suboptions:
                                    dataplan:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect-period:
                                        type: int
                                        description: no description
                                    disconnect-threshold:
                                        type: int
                                        description: no description
                                    signal:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    switch-back:
                                        description: description
                                        type: list
                                        choices:
                                         - time
                                         - timer
                                    switch-back-time:
                                        type: str
                                        description: no description
                                    switch-back-timer:
                                        type: int
                                        description: no description
                            conn-status:
                                type: int
                                description: no description
                            default-sim:
                                type: str
                                description: no description
                                choices:
                                    - 'sim1'
                                    - 'sim2'
                                    - 'carrier'
                                    - 'cost'
                            gps:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            modem-id:
                                type: int
                                description: no description
                            preferred-carrier:
                                type: str
                                description: no description
                            redundant-intf:
                                type: str
                                description: no description
                            redundant-mode:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1-pin:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1-pin-code:
                                description: description
                                type: str
                            sim2-pin:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim2-pin-code:
                                description: description
                                type: str
                    sms-notification:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            alert:
                                description: no description
                                type: dict
                                required: false
                                suboptions:
                                    data-exhausted:
                                        type: str
                                        description: no description
                                    fgt-backup-mode-switch:
                                        type: str
                                        description: no description
                                    low-signal-strength:
                                        type: str
                                        description: no description
                                    mode-switch:
                                        type: str
                                        description: no description
                                    os-image-fallback:
                                        type: str
                                        description: no description
                                    session-disconnect:
                                        type: str
                                        description: no description
                                    system-reboot:
                                        type: str
                                        description: no description
                            receiver:
                                description: description
                                type: list
                                suboptions:
                                    alert:
                                        description: description
                                        type: list
                                        choices:
                                         - system-reboot
                                         - data-exhausted
                                         - session-disconnect
                                         - low-signal-strength
                                         - mode-switch
                                         - os-image-fallback
                                         - fgt-backup-mode-switch
                                    name:
                                        type: str
                                        description: no description
                                    phone-number:
                                        type: str
                                        description: no description
                                    status:
                                        type: str
                                        description: no description
                                        choices:
                                            - 'disable'
                                            - 'enable'
                            status:
                                type: str
                                description: no description
                                choices:
                                    - 'disable'
                                    - 'enable'
            enforce-bandwidth:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            extension:
                type: str
                description: no description
                choices:
                    - 'wan-extension'
                    - 'lan-extension'
            id:
                type: int
                description: no description
            lan-extension:
                description: no description
                type: dict
                required: false
                suboptions:
                    backhaul:
                        description: description
                        type: list
                        suboptions:
                            name:
                                type: str
                                description: no description
                            port:
                                type: str
                                description: no description
                                choices:
                                    - 'wan'
                                    - 'lte1'
                                    - 'lte2'
                                    - 'port1'
                                    - 'port2'
                                    - 'port3'
                                    - 'port4'
                                    - 'port5'
                                    - 'sfp'
                            role:
                                type: str
                                description: no description
                                choices:
                                    - 'primary'
                                    - 'secondary'
                            weight:
                                type: int
                                description: no description
                    backhaul-interface:
                        type: str
                        description: no description
                    backhaul-ip:
                        type: str
                        description: no description
                    ipsec-tunnel:
                        type: str
                        description: no description
                    link-loadbalance:
                        type: str
                        description: no description
                        choices:
                            - 'activebackup'
                            - 'loadbalance'
            login-password:
                description: description
                type: str
            login-password-change:
                type: str
                description: no description
                choices:
                    - 'no'
                    - 'yes'
                    - 'default'
            model:
                type: str
                description: no description
                choices:
                    - 'FX201E'
                    - 'FX211E'
                    - 'FX200F'
                    - 'FXA11F'
                    - 'FXE11F'
                    - 'FXA21F'
                    - 'FXE21F'
                    - 'FXA22F'
                    - 'FXE22F'
                    - 'FX212F'
                    - 'FX311F'
                    - 'FX312F'
                    - 'FX511F'
                    - 'FVG21F'
                    - 'FVA21F'
                    - 'FVG22F'
                    - 'FVA22F'
                    - 'FX04DA'
            name:
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
      fmgr_extendercontroller_extenderprofile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         extendercontroller_extenderprofile:
            allowaccess:
              - https
              - ping
              - ssh
              - snmp
              - http
              - telnet
            bandwidth-limit: <value of integer>
            cellular:
               controller-report:
                  interval: <value of integer>
                  signal-threshold: <value of integer>
                  status: <value in [disable, enable]>
               dataplan: <value of string>
               modem1:
                  auto-switch:
                     dataplan: <value in [disable, enable]>
                     disconnect: <value in [disable, enable]>
                     disconnect-period: <value of integer>
                     disconnect-threshold: <value of integer>
                     signal: <value in [disable, enable]>
                     switch-back:
                       - time
                       - timer
                     switch-back-time: <value of string>
                     switch-back-timer: <value of integer>
                  conn-status: <value of integer>
                  default-sim: <value in [sim1, sim2, carrier, ...]>
                  gps: <value in [disable, enable]>
                  modem-id: <value of integer>
                  preferred-carrier: <value of string>
                  redundant-intf: <value of string>
                  redundant-mode: <value in [disable, enable]>
                  sim1-pin: <value in [disable, enable]>
                  sim1-pin-code: <value of string>
                  sim2-pin: <value in [disable, enable]>
                  sim2-pin-code: <value of string>
               modem2:
                  auto-switch:
                     dataplan: <value in [disable, enable]>
                     disconnect: <value in [disable, enable]>
                     disconnect-period: <value of integer>
                     disconnect-threshold: <value of integer>
                     signal: <value in [disable, enable]>
                     switch-back:
                       - time
                       - timer
                     switch-back-time: <value of string>
                     switch-back-timer: <value of integer>
                  conn-status: <value of integer>
                  default-sim: <value in [sim1, sim2, carrier, ...]>
                  gps: <value in [disable, enable]>
                  modem-id: <value of integer>
                  preferred-carrier: <value of string>
                  redundant-intf: <value of string>
                  redundant-mode: <value in [disable, enable]>
                  sim1-pin: <value in [disable, enable]>
                  sim1-pin-code: <value of string>
                  sim2-pin: <value in [disable, enable]>
                  sim2-pin-code: <value of string>
               sms-notification:
                  alert:
                     data-exhausted: <value of string>
                     fgt-backup-mode-switch: <value of string>
                     low-signal-strength: <value of string>
                     mode-switch: <value of string>
                     os-image-fallback: <value of string>
                     session-disconnect: <value of string>
                     system-reboot: <value of string>
                  receiver:
                    -
                        alert:
                          - system-reboot
                          - data-exhausted
                          - session-disconnect
                          - low-signal-strength
                          - mode-switch
                          - os-image-fallback
                          - fgt-backup-mode-switch
                        name: <value of string>
                        phone-number: <value of string>
                        status: <value in [disable, enable]>
                  status: <value in [disable, enable]>
            enforce-bandwidth: <value in [disable, enable]>
            extension: <value in [wan-extension, lan-extension]>
            id: <value of integer>
            lan-extension:
               backhaul:
                 -
                     name: <value of string>
                     port: <value in [wan, lte1, lte2, ...]>
                     role: <value in [primary, secondary]>
                     weight: <value of integer>
               backhaul-interface: <value of string>
               backhaul-ip: <value of string>
               ipsec-tunnel: <value of string>
               link-loadbalance: <value in [activebackup, loadbalance]>
            login-password: <value of string>
            login-password-change: <value in [no, yes, default]>
            model: <value in [FX201E, FX211E, FX200F, ...]>
            name: <value of string>

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
        '/pm/config/global/obj/extender-controller/extender-profile',
        '/pm/config/adom/{adom}/obj/extender-controller/extender-profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}',
        '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'id'
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
        'extendercontroller_extenderprofile': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.2.0': True
            },
            'options': {
                'allowaccess': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'https',
                        'ping',
                        'ssh',
                        'snmp',
                        'http',
                        'telnet'
                    ]
                },
                'bandwidth-limit': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'cellular': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'controller-report': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'interval': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'signal-threshold': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'int'
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
                                }
                            }
                        },
                        'dataplan': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'modem1': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'auto-switch': {
                                    'required': False,
                                    'type': 'dict',
                                    'options': {
                                        'dataplan': {
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
                                        'disconnect': {
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
                                        'disconnect-period': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'disconnect-threshold': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'signal': {
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
                                        'switch-back': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'time',
                                                'timer'
                                            ]
                                        },
                                        'switch-back-time': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'switch-back-timer': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        }
                                    }
                                },
                                'conn-status': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'default-sim': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'sim1',
                                        'sim2',
                                        'carrier',
                                        'cost'
                                    ],
                                    'type': 'str'
                                },
                                'gps': {
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
                                'modem-id': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'preferred-carrier': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'redundant-intf': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'redundant-mode': {
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
                                'sim1-pin': {
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
                                'sim1-pin-code': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'sim2-pin': {
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
                                'sim2-pin-code': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                }
                            }
                        },
                        'modem2': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'auto-switch': {
                                    'required': False,
                                    'type': 'dict',
                                    'options': {
                                        'dataplan': {
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
                                        'disconnect': {
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
                                        'disconnect-period': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'disconnect-threshold': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        },
                                        'signal': {
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
                                        'switch-back': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'time',
                                                'timer'
                                            ]
                                        },
                                        'switch-back-time': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'switch-back-timer': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'int'
                                        }
                                    }
                                },
                                'conn-status': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'default-sim': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'sim1',
                                        'sim2',
                                        'carrier',
                                        'cost'
                                    ],
                                    'type': 'str'
                                },
                                'gps': {
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
                                'modem-id': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                },
                                'preferred-carrier': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'redundant-intf': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'redundant-mode': {
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
                                'sim1-pin': {
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
                                'sim1-pin-code': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'sim2-pin': {
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
                                'sim2-pin-code': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                }
                            }
                        },
                        'sms-notification': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'alert': {
                                    'required': False,
                                    'type': 'dict',
                                    'options': {
                                        'data-exhausted': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'fgt-backup-mode-switch': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'low-signal-strength': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'mode-switch': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'os-image-fallback': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'session-disconnect': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'system-reboot': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        }
                                    }
                                },
                                'receiver': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'list',
                                    'options': {
                                        'alert': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'list',
                                            'choices': [
                                                'system-reboot',
                                                'data-exhausted',
                                                'session-disconnect',
                                                'low-signal-strength',
                                                'mode-switch',
                                                'os-image-fallback',
                                                'fgt-backup-mode-switch'
                                            ]
                                        },
                                        'name': {
                                            'required': False,
                                            'revision': {
                                                '7.2.0': True
                                            },
                                            'type': 'str'
                                        },
                                        'phone-number': {
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
                                        }
                                    }
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
                                }
                            }
                        }
                    }
                },
                'enforce-bandwidth': {
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
                'extension': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'wan-extension',
                        'lan-extension'
                    ],
                    'type': 'str'
                },
                'id': {
                    'required': True,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'lan-extension': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'backhaul': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'list',
                            'options': {
                                'name': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'str'
                                },
                                'port': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'wan',
                                        'lte1',
                                        'lte2',
                                        'port1',
                                        'port2',
                                        'port3',
                                        'port4',
                                        'port5',
                                        'sfp'
                                    ],
                                    'type': 'str'
                                },
                                'role': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'choices': [
                                        'primary',
                                        'secondary'
                                    ],
                                    'type': 'str'
                                },
                                'weight': {
                                    'required': False,
                                    'revision': {
                                        '7.2.0': True
                                    },
                                    'type': 'int'
                                }
                            }
                        },
                        'backhaul-interface': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'backhaul-ip': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'ipsec-tunnel': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'link-loadbalance': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'activebackup',
                                'loadbalance'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'login-password': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'login-password-change': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'no',
                        'yes',
                        'default'
                    ],
                    'type': 'str'
                },
                'model': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'FX201E',
                        'FX211E',
                        'FX200F',
                        'FXA11F',
                        'FXE11F',
                        'FXA21F',
                        'FXE21F',
                        'FXA22F',
                        'FXE22F',
                        'FX212F',
                        'FX311F',
                        'FX312F',
                        'FX511F',
                        'FVG21F',
                        'FVA21F',
                        'FVG22F',
                        'FVA22F',
                        'FX04DA'
                    ],
                    'type': 'str'
                },
                'name': {
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extendercontroller_extenderprofile'),
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
