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
module: fmgr_switchcontroller_lldpprofile
short_description: Configure FortiSwitch LLDP profiles.
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
    switchcontroller_lldpprofile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            802.1-tlvs:
                description: no description
                type: list
                choices:
                 - port-vlan-id
            802.3-tlvs:
                description: no description
                type: list
                choices:
                 - max-frame-size
            auto-isl:
                type: str
                description: 'Enable/disable auto inter-switch LAG.'
                choices:
                    - 'disable'
                    - 'enable'
            auto-isl-hello-timer:
                type: int
                description: 'Auto inter-switch LAG hello timer duration (1 - 30 sec, default = 3).'
            auto-isl-port-group:
                type: int
                description: 'Auto inter-switch LAG port group ID (0 - 9).'
            auto-isl-receive-timeout:
                type: int
                description: 'Auto inter-switch LAG timeout if no response is received (3 - 90 sec, default = 9).'
            custom-tlvs:
                description: no description
                type: list
                suboptions:
                    information-string:
                        type: str
                        description: 'Organizationally defined information string (0 - 507 hexadecimal bytes).'
                    name:
                        type: str
                        description: 'TLV name (not sent).'
                    oui:
                        type: str
                        description: 'Organizationally unique identifier (OUI), a 3-byte hexadecimal number, for this TLV.'
                    subtype:
                        type: int
                        description: 'Organizationally defined subtype (0 - 255).'
            med-network-policy:
                description: no description
                type: list
                suboptions:
                    dscp:
                        type: int
                        description: 'Advertised Differentiated Services Code Point (DSCP) value, a packet header value indicating the level of service requ...'
                    name:
                        type: str
                        description: 'Policy type name.'
                    priority:
                        type: int
                        description: 'Advertised Layer 2 priority (0 - 7; from lowest to highest priority).'
                    status:
                        type: str
                        description: 'Enable or disable this TLV.'
                        choices:
                            - 'disable'
                            - 'enable'
                    vlan:
                        type: int
                        description: 'ID of VLAN to advertise, if configured on port (0 - 4094, 0 = priority tag).'
            med-tlvs:
                description: no description
                type: list
                choices:
                 - inventory-management
                 - network-policy
                 - power-management
                 - location-identification
            name:
                type: str
                description: 'Profile name.'

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
    - name: Configure FortiSwitch LLDP profiles.
      fmgr_switchcontroller_lldpprofile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         switchcontroller_lldpprofile:
            802.1-tlvs:
              - port-vlan-id
            802.3-tlvs:
              - max-frame-size
            auto-isl: <value in [disable, enable]>
            auto-isl-hello-timer: <value of integer>
            auto-isl-port-group: <value of integer>
            auto-isl-receive-timeout: <value of integer>
            custom-tlvs:
              -
                  information-string: <value of string>
                  name: <value of string>
                  oui: <value of string>
                  subtype: <value of integer>
            med-network-policy:
              -
                  dscp: <value of integer>
                  name: <value of string>
                  priority: <value of integer>
                  status: <value in [disable, enable]>
                  vlan: <value of integer>
            med-tlvs:
              - inventory-management
              - network-policy
              - power-management
              - location-identification
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
        '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile',
        '/pm/config/global/obj/switch-controller/lldp-profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}',
        '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}'
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
        'switchcontroller_lldpprofile': {
            'required': False,
            'type': 'dict',
            'options': {
                '802.1-tlvs': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'port-vlan-id'
                    ]
                },
                '802.3-tlvs': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'max-frame-size'
                    ]
                },
                'auto-isl': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auto-isl-hello-timer': {
                    'required': False,
                    'type': 'int'
                },
                'auto-isl-port-group': {
                    'required': False,
                    'type': 'int'
                },
                'auto-isl-receive-timeout': {
                    'required': False,
                    'type': 'int'
                },
                'custom-tlvs': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'information-string': {
                            'required': False,
                            'type': 'str'
                        },
                        'name': {
                            'required': False,
                            'type': 'str'
                        },
                        'oui': {
                            'required': False,
                            'type': 'str'
                        },
                        'subtype': {
                            'required': False,
                            'type': 'int'
                        }
                    }
                },
                'med-network-policy': {
                    'required': False,
                    'type': 'list',
                    'options': {
                        'dscp': {
                            'required': False,
                            'type': 'int'
                        },
                        'name': {
                            'required': False,
                            'type': 'str'
                        },
                        'priority': {
                            'required': False,
                            'type': 'int'
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'vlan': {
                            'required': False,
                            'type': 'int'
                        }
                    }
                },
                'med-tlvs': {
                    'required': False,
                    'type': 'list',
                    'choices': [
                        'inventory-management',
                        'network-policy',
                        'power-management',
                        'location-identification'
                    ]
                },
                'name': {
                    'required': True,
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_lldpprofile'),
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
