#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_apcfgprofile
short_description: Configure AP local configuration profiles.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
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
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    apcfgprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ac_ip:
                aliases: ['ac-ip']
                type: str
                description: IP address of the validation controller that AP must be able to join after applying AP local configuration.
            ac_port:
                aliases: ['ac-port']
                type: int
                description: Port of the validation controller that AP must be able to join after applying AP local configuration
            ac_timer:
                aliases: ['ac-timer']
                type: int
                description: Maximum waiting time for the AP to join the validation controller after applying AP local configuration
            ac_type:
                aliases: ['ac-type']
                type: str
                description: Validation controller type
                choices:
                    - 'default'
                    - 'specify'
                    - 'apcfg'
            command_list:
                aliases: ['command-list']
                type: list
                elements: dict
                description: Command list.
                suboptions:
                    id:
                        type: int
                        description: Command ID.
                    name:
                        type: str
                        description: AP local configuration command name.
                    passwd_value:
                        aliases: ['passwd-value']
                        type: raw
                        description: (list) AP local configuration command password value.
                    type:
                        type: str
                        description: The command type
                        choices:
                            - 'non-password'
                            - 'password'
                    value:
                        type: str
                        description: AP local configuration command value.
            comment:
                type: str
                description: Comment.
            name:
                type: str
                description: AP local configuration profile name.
                required: true
            ap_family:
                aliases: ['ap-family']
                type: str
                description: FortiAP family type
                choices:
                    - 'fap'
                    - 'fap-u'
                    - 'fap-c'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure AP local configuration profiles.
      fortinet.fortimanager.fmgr_apcfgprofile:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        apcfgprofile:
          ac_ip: <string>
          ac_port: <integer>
          ac_timer: <integer>
          ac_type: <value in [default, specify, apcfg]>
          command_list:
            -
              id: <integer>
              name: <string>
              passwd_value: <list or string>
              type: <value in [non-password, password]>
              value: <string>
          comment: <string>
          name: <string>
          ap_family: <value in [fap, fap-u, fap-c]>
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile',
        '/pm/config/global/obj/wireless-controller/apcfg-profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'apcfgprofile': {
            'type': 'dict',
            'v_range': [['6.4.6', '']],
            'options': {
                'ac-ip': {'v_range': [['6.4.6', '']], 'type': 'str'},
                'ac-port': {'v_range': [['6.4.6', '']], 'type': 'int'},
                'ac-timer': {'v_range': [['6.4.6', '']], 'type': 'int'},
                'ac-type': {'v_range': [['6.4.6', '']], 'choices': ['default', 'specify', 'apcfg'], 'type': 'str'},
                'command-list': {
                    'v_range': [['6.4.6', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.4.6', '']], 'type': 'int'},
                        'name': {'v_range': [['6.4.6', '']], 'type': 'str'},
                        'passwd-value': {'v_range': [['6.4.6', '']], 'no_log': True, 'type': 'raw'},
                        'type': {'v_range': [['6.4.6', '']], 'choices': ['non-password', 'password'], 'type': 'str'},
                        'value': {'v_range': [['6.4.6', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'comment': {'v_range': [['6.4.6', '']], 'type': 'str'},
                'name': {'v_range': [['6.4.6', '']], 'required': True, 'type': 'str'},
                'ap-family': {'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']], 'choices': ['fap', 'fap-u', 'fap-c'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'apcfgprofile'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
