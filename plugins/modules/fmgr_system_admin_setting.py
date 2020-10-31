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
module: fmgr_system_admin_setting
short_description: Admin setting.
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
    system_admin_setting:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            access-banner:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable access banner.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            admin-https-redirect:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable redirection of HTTP admin traffic to HTTPS.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            admin-login-max:
                type: int
                default: 256
                description: 'Maximum number admin users logged in at one time (1 - 256).'
            admin_server_cert:
                type: str
                default: 'server.crt'
                description: 'HTTPS & Web Service server certificate.'
            allow_register:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable allowance of register an unregistered device.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            auto-update:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable FortiGate automatic update.'
                 - 'disable - Disable device automatic update.'
                 - 'enable - Enable device automatic update.'
                choices:
                    - 'disable'
                    - 'enable'
            banner-message:
                type: str
                description: 'Banner message.'
            chassis-mgmt:
                type: str
                default: 'disable'
                description:
                 - 'Enable or disable chassis management.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            chassis-update-interval:
                type: int
                default: 15
                description: 'Chassis background update interval (4 - 1440 mins).'
            device_sync_status:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable device synchronization status indication.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            gui-theme:
                type: str
                default: 'blue'
                description:
                 - 'Color scheme to use for the administration GUI.'
                 - 'blue - Blueberry'
                 - 'green - Kiwi'
                 - 'red - Cherry'
                 - 'melongene - Plum'
                 - 'spring - Spring'
                 - 'summer - Summer'
                 - 'autumn - Autumn'
                 - 'winter - Winter'
                 - 'space - Space'
                 - 'calla-lily - Calla Lily'
                 - 'binary-tunnel - Binary Tunnel'
                 - 'diving - Diving'
                 - 'dreamy - Dreamy'
                 - 'technology - Technology'
                 - 'landscape - Landscape'
                 - 'twilight - Twilight'
                 - 'canyon - Canyon'
                 - 'northern-light - Northern Light'
                 - 'astronomy - Astronomy'
                 - 'fish - Fish'
                 - 'penguin - Penguin'
                 - 'panda - Panda'
                 - 'polar-bear - Polar Bear'
                 - 'parrot - Parrot'
                 - 'cave - Cave'
                choices:
                    - 'blue'
                    - 'green'
                    - 'red'
                    - 'melongene'
                    - 'spring'
                    - 'summer'
                    - 'autumn'
                    - 'winter'
                    - 'space'
                    - 'calla-lily'
                    - 'binary-tunnel'
                    - 'diving'
                    - 'dreamy'
                    - 'technology'
                    - 'landscape'
                    - 'twilight'
                    - 'canyon'
                    - 'northern-light'
                    - 'astronomy'
                    - 'fish'
                    - 'penguin'
                    - 'panda'
                    - 'polar-bear'
                    - 'parrot'
                    - 'cave'
            http_port:
                type: int
                default: 80
                description: 'HTTP port.'
            https_port:
                type: int
                default: 443
                description: 'HTTPS port.'
            idle_timeout:
                type: int
                default: 15
                description: 'Idle timeout (1 - 480 min).'
            install-ifpolicy-only:
                type: str
                default: 'disable'
                description:
                 - 'Allow install interface policy only.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            mgmt-addr:
                type: str
                description: 'IP of FortiManager used by FGFM.'
            mgmt-fqdn:
                type: str
                description: 'FQDN of FortiManager used by FGFM.'
            objects-force-deletion:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable used objects force deletion.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            offline_mode:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable offline mode.'
                 - 'disable - Disable offline mode.'
                 - 'enable - Enable offline mode.'
                choices:
                    - 'disable'
                    - 'enable'
            register_passwd:
                description: no description
                type: str
            sdwan-monitor-history:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable hostname display in the GUI login page.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            shell-access:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable shell access.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            shell-password:
                description: no description
                type: str
            show-add-multiple:
                type: str
                default: 'disable'
                description:
                 - 'Show add multiple button.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            show-adom-devman:
                type: str
                default: 'enable'
                description:
                 - 'Show ADOM device manager tools on GUI.'
                 - 'disable - Hide device manager tools on GUI.'
                 - 'enable - Show device manager tools on GUI.'
                choices:
                    - 'disable'
                    - 'enable'
            show-checkbox-in-table:
                type: str
                default: 'disable'
                description:
                 - 'Show checkboxs in tables on GUI.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            show-device-import-export:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable import/export of ADOM, device, and group lists.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            show-hostname:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable hostname display in the GUI login page.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            show_automatic_script:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable automatic script.'
                 - 'disable - Disable script option.'
                 - 'enable - Enable script option.'
                choices:
                    - 'disable'
                    - 'enable'
            show_grouping_script:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable grouping script.'
                 - 'disable - Disable script option.'
                 - 'enable - Enable script option.'
                choices:
                    - 'disable'
                    - 'enable'
            show_schedule_script:
                type: str
                default: 'disable'
                description:
                 - 'Enable or disable schedule script.'
                 - 'disable - Disable script option.'
                 - 'enable - Enable script option.'
                choices:
                    - 'disable'
                    - 'enable'
            show_tcl_script:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable TCL script.'
                 - 'disable - Disable script option.'
                 - 'enable - Enable script option.'
                choices:
                    - 'disable'
                    - 'enable'
            unreg_dev_opt:
                type: str
                default: 'add_allow_service'
                description:
                 - 'Action to take when unregistered device connects to FortiManager.'
                 - 'add_no_service - Add unregistered devices but deny service requests.'
                 - 'ignore - Ignore unregistered devices.'
                 - 'add_allow_service - Add unregistered devices and allow service requests.'
                choices:
                    - 'add_no_service'
                    - 'ignore'
                    - 'add_allow_service'
            webadmin_language:
                type: str
                default: 'auto_detect'
                description:
                 - 'Web admin language.'
                 - 'auto_detect - Automatically detect language.'
                 - 'english - English.'
                 - 'simplified_chinese - Simplified Chinese.'
                 - 'traditional_chinese - Traditional Chinese.'
                 - 'japanese - Japanese.'
                 - 'korean - Korean.'
                 - 'spanish - Spanish.'
                choices:
                    - 'auto_detect'
                    - 'english'
                    - 'simplified_chinese'
                    - 'traditional_chinese'
                    - 'japanese'
                    - 'korean'
                    - 'spanish'

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
    - name: Admin setting.
      fmgr_system_admin_setting:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         system_admin_setting:
            access-banner: <value in [disable, enable]>
            admin-https-redirect: <value in [disable, enable]>
            admin-login-max: <value of integer>
            admin_server_cert: <value of string>
            allow_register: <value in [disable, enable]>
            auto-update: <value in [disable, enable]>
            banner-message: <value of string>
            chassis-mgmt: <value in [disable, enable]>
            chassis-update-interval: <value of integer>
            device_sync_status: <value in [disable, enable]>
            gui-theme: <value in [blue, green, red, ...]>
            http_port: <value of integer>
            https_port: <value of integer>
            idle_timeout: <value of integer>
            install-ifpolicy-only: <value in [disable, enable]>
            mgmt-addr: <value of string>
            mgmt-fqdn: <value of string>
            objects-force-deletion: <value in [disable, enable]>
            offline_mode: <value in [disable, enable]>
            register_passwd: <value of string>
            sdwan-monitor-history: <value in [disable, enable]>
            shell-access: <value in [disable, enable]>
            shell-password: <value of string>
            show-add-multiple: <value in [disable, enable]>
            show-adom-devman: <value in [disable, enable]>
            show-checkbox-in-table: <value in [disable, enable]>
            show-device-import-export: <value in [disable, enable]>
            show-hostname: <value in [disable, enable]>
            show_automatic_script: <value in [disable, enable]>
            show_grouping_script: <value in [disable, enable]>
            show_schedule_script: <value in [disable, enable]>
            show_tcl_script: <value in [disable, enable]>
            unreg_dev_opt: <value in [add_no_service, ignore, add_allow_service]>
            webadmin_language: <value in [auto_detect, english, simplified_chinese, ...]>

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
        '/cli/global/system/admin/setting'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/admin/setting/{setting}'
    ]

    url_params = []
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
        'system_admin_setting': {
            'required': False,
            'type': 'dict',
            'options': {
                'access-banner': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'admin-https-redirect': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'admin-login-max': {
                    'required': False,
                    'type': 'int'
                },
                'admin_server_cert': {
                    'required': False,
                    'type': 'str'
                },
                'allow_register': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auto-update': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'banner-message': {
                    'required': False,
                    'type': 'str'
                },
                'chassis-mgmt': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'chassis-update-interval': {
                    'required': False,
                    'type': 'int'
                },
                'device_sync_status': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'gui-theme': {
                    'required': False,
                    'choices': [
                        'blue',
                        'green',
                        'red',
                        'melongene',
                        'spring',
                        'summer',
                        'autumn',
                        'winter',
                        'space',
                        'calla-lily',
                        'binary-tunnel',
                        'diving',
                        'dreamy',
                        'technology',
                        'landscape',
                        'twilight',
                        'canyon',
                        'northern-light',
                        'astronomy',
                        'fish',
                        'penguin',
                        'panda',
                        'polar-bear',
                        'parrot',
                        'cave'
                    ],
                    'type': 'str'
                },
                'http_port': {
                    'required': False,
                    'type': 'int'
                },
                'https_port': {
                    'required': False,
                    'type': 'int'
                },
                'idle_timeout': {
                    'required': False,
                    'type': 'int'
                },
                'install-ifpolicy-only': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'mgmt-addr': {
                    'required': False,
                    'type': 'str'
                },
                'mgmt-fqdn': {
                    'required': False,
                    'type': 'str'
                },
                'objects-force-deletion': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'offline_mode': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'register_passwd': {
                    'required': False,
                    'type': 'str'
                },
                'sdwan-monitor-history': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'shell-access': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'shell-password': {
                    'required': False,
                    'type': 'str'
                },
                'show-add-multiple': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'show-adom-devman': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'show-checkbox-in-table': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'show-device-import-export': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'show-hostname': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'show_automatic_script': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'show_grouping_script': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'show_schedule_script': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'show_tcl_script': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'unreg_dev_opt': {
                    'required': False,
                    'choices': [
                        'add_no_service',
                        'ignore',
                        'add_allow_service'
                    ],
                    'type': 'str'
                },
                'webadmin_language': {
                    'required': False,
                    'choices': [
                        'auto_detect',
                        'english',
                        'simplified_chinese',
                        'traditional_chinese',
                        'japanese',
                        'korean',
                        'spanish'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_setting'),
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
