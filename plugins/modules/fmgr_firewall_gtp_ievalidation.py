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
module: fmgr_firewall_gtp_ievalidation
short_description: IE validation.
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
    gtp:
        description: the parameter (gtp) in requested url
        type: str
        required: true
    firewall_gtp_ievalidation:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            apn-restriction:
                type: str
                description: 'Validate APN restriction.'
                choices:
                    - 'disable'
                    - 'enable'
            charging-ID:
                type: str
                description: 'Validate charging ID.'
                choices:
                    - 'disable'
                    - 'enable'
            charging-gateway-addr:
                type: str
                description: 'Validate charging gateway address.'
                choices:
                    - 'disable'
                    - 'enable'
            end-user-addr:
                type: str
                description: 'Validate end user address.'
                choices:
                    - 'disable'
                    - 'enable'
            gsn-addr:
                type: str
                description: 'Validate GSN address.'
                choices:
                    - 'disable'
                    - 'enable'
            imei:
                type: str
                description: 'Validate IMEI(SV).'
                choices:
                    - 'disable'
                    - 'enable'
            imsi:
                type: str
                description: 'Validate IMSI.'
                choices:
                    - 'disable'
                    - 'enable'
            mm-context:
                type: str
                description: 'Validate MM context.'
                choices:
                    - 'disable'
                    - 'enable'
            ms-tzone:
                type: str
                description: 'Validate MS time zone.'
                choices:
                    - 'disable'
                    - 'enable'
            ms-validated:
                type: str
                description: 'Validate MS validated.'
                choices:
                    - 'disable'
                    - 'enable'
            msisdn:
                type: str
                description: 'Validate MSISDN.'
                choices:
                    - 'disable'
                    - 'enable'
            nsapi:
                type: str
                description: 'Validate NSAPI.'
                choices:
                    - 'disable'
                    - 'enable'
            pdp-context:
                type: str
                description: 'Validate PDP context.'
                choices:
                    - 'disable'
                    - 'enable'
            qos-profile:
                type: str
                description: 'Validate Quality of Service(QoS) profile.'
                choices:
                    - 'disable'
                    - 'enable'
            rai:
                type: str
                description: 'Validate RAI.'
                choices:
                    - 'disable'
                    - 'enable'
            rat-type:
                type: str
                description: 'Validate RAT type.'
                choices:
                    - 'disable'
                    - 'enable'
            reordering-required:
                type: str
                description: 'Validate re-ordering required.'
                choices:
                    - 'disable'
                    - 'enable'
            selection-mode:
                type: str
                description: 'Validate selection mode.'
                choices:
                    - 'disable'
                    - 'enable'
            uli:
                type: str
                description: 'Validate user location information.'
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
    - name: IE validation.
      fmgr_firewall_gtp_ievalidation:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         gtp: <your own value>
         firewall_gtp_ievalidation:
            apn-restriction: <value in [disable, enable]>
            charging-ID: <value in [disable, enable]>
            charging-gateway-addr: <value in [disable, enable]>
            end-user-addr: <value in [disable, enable]>
            gsn-addr: <value in [disable, enable]>
            imei: <value in [disable, enable]>
            imsi: <value in [disable, enable]>
            mm-context: <value in [disable, enable]>
            ms-tzone: <value in [disable, enable]>
            ms-validated: <value in [disable, enable]>
            msisdn: <value in [disable, enable]>
            nsapi: <value in [disable, enable]>
            pdp-context: <value in [disable, enable]>
            qos-profile: <value in [disable, enable]>
            rai: <value in [disable, enable]>
            rat-type: <value in [disable, enable]>
            reordering-required: <value in [disable, enable]>
            selection-mode: <value in [disable, enable]>
            uli: <value in [disable, enable]>

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
        '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-validation',
        '/pm/config/global/obj/firewall/gtp/{gtp}/ie-validation'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-validation/{ie-validation}',
        '/pm/config/global/obj/firewall/gtp/{gtp}/ie-validation/{ie-validation}'
    ]

    url_params = ['adom', 'gtp']
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
        'gtp': {
            'required': True,
            'type': 'str'
        },
        'firewall_gtp_ievalidation': {
            'required': False,
            'type': 'dict',
            'options': {
                'apn-restriction': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'charging-ID': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'charging-gateway-addr': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'end-user-addr': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'gsn-addr': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'imei': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'imsi': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mm-context': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ms-tzone': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ms-validated': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'msisdn': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'nsapi': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'pdp-context': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'qos-profile': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rai': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'rat-type': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'reordering-required': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'selection-mode': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'uli': {
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_gtp_ievalidation'),
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
