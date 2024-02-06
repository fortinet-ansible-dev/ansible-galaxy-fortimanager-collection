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
module: fmgr_user_device_dynamicmapping
short_description: Configure devices.
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
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    user_device_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _scope:
                type: list
                elements: dict
                description: No description.
                suboptions:
                    name:
                        type: str
                        description: No description.
                    vdom:
                        type: str
                        description: No description.
            avatar:
                type: str
                description: No description.
            category:
                type: str
                description: No description.
                choices:
                    - 'none'
                    - 'android-device'
                    - 'blackberry-device'
                    - 'fortinet-device'
                    - 'ios-device'
                    - 'windows-device'
                    - 'amazon-device'
            comment:
                type: str
                description: No description.
            mac:
                type: str
                description: No description.
            master-device:
                type: str
                description: Deprecated, please rename it to master_device.
            tags:
                type: raw
                description: (list or str) No description.
            type:
                type: str
                description: No description.
                choices:
                    - 'ipad'
                    - 'iphone'
                    - 'gaming-console'
                    - 'blackberry-phone'
                    - 'blackberry-playbook'
                    - 'linux-pc'
                    - 'mac'
                    - 'windows-pc'
                    - 'android-phone'
                    - 'android-tablet'
                    - 'media-streaming'
                    - 'windows-phone'
                    - 'fortinet-device'
                    - 'ip-phone'
                    - 'router-nat-device'
                    - 'other-network-device'
                    - 'windows-tablet'
                    - 'printer'
                    - 'forticam'
                    - 'fortifone'
                    - 'unknown'
            user:
                type: str
                description: No description.
            family:
                type: str
                description: No description.
            hardware-vendor:
                type: str
                description: Deprecated, please rename it to hardware_vendor.
            hardware-version:
                type: str
                description: Deprecated, please rename it to hardware_version.
            os:
                type: str
                description: No description.
            software-version:
                type: str
                description: Deprecated, please rename it to software_version.
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure dynamic mappings
      fortinet.fortimanager.fmgr_user_device_dynamicmapping:
        bypass_validation: false
        adom: ansible
        device: ansible-test-device # alias
        state: present
        user_device_dynamicmapping:
          _scope:
            - name: FGT_AWS # need a valid device name
              vdom: root # need a valid vdom name under the device
          category: none # <value in [none, android-device, blackberry-device, ...]>
          comment: ansible-comment
          mac: "00:11:22:33:44:55"
          type: iphone # <value in [ipad, iphone, gaming-console, ...]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the dynamic mappings
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "user_device_dynamicmapping"
          params:
            adom: "ansible"
            device: "ansible-test-device" # alias
            dynamic_mapping: "your_value"
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/user/device/{device}/dynamic_mapping',
        '/pm/config/global/obj/user/device/{device}/dynamic_mapping'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}',
        '/pm/config/global/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}'
    ]

    url_params = ['adom', 'device']
    module_primary_key = 'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'device': {'required': True, 'type': 'str'},
        'user_device_dynamicmapping': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                'avatar': {'type': 'str'},
                'category': {
                    'choices': ['none', 'android-device', 'blackberry-device', 'fortinet-device', 'ios-device', 'windows-device', 'amazon-device'],
                    'type': 'str'
                },
                'comment': {'type': 'str'},
                'mac': {'type': 'str'},
                'master-device': {'type': 'str'},
                'tags': {'type': 'raw'},
                'type': {
                    'choices': [
                        'ipad', 'iphone', 'gaming-console', 'blackberry-phone', 'blackberry-playbook', 'linux-pc', 'mac', 'windows-pc', 'android-phone',
                        'android-tablet', 'media-streaming', 'windows-phone', 'fortinet-device', 'ip-phone', 'router-nat-device', 'other-network-device',
                        'windows-tablet', 'printer', 'forticam', 'fortifone', 'unknown'
                    ],
                    'type': 'str'
                },
                'user': {'type': 'str'},
                'family': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'hardware-vendor': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'hardware-version': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'os': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'software-version': {'v_range': [['6.2.1', '']], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_device_dynamicmapping'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
