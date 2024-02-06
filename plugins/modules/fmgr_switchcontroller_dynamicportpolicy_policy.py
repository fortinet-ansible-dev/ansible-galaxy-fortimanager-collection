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
module: fmgr_switchcontroller_dynamicportpolicy_policy
short_description: Port policies with matching criteria and actions.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    dynamic-port-policy:
        description: Deprecated, please use "dynamic_port_policy"
        type: str
    dynamic_port_policy:
        description: The parameter (dynamic-port-policy) in requested url.
        type: str
    switchcontroller_dynamicportpolicy_policy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            802-1x:
                type: str
                description: Deprecated, please rename it to 802_1x. '802.'
            bounce-port-link:
                type: str
                description: Deprecated, please rename it to bounce_port_link. Enable/disable bouncing
                choices:
                    - 'disable'
                    - 'enable'
            category:
                type: str
                description: Category of Dynamic port policy.
                choices:
                    - 'device'
                    - 'interface-tag'
            description:
                type: str
                description: Description for the policy.
            family:
                type: str
                description: Match policy based on family.
            host:
                type: str
                description: Match policy based on host.
            hw-vendor:
                type: str
                description: Deprecated, please rename it to hw_vendor. Match policy based on hardware vendor.
            interface-tags:
                type: raw
                description: (list) Deprecated, please rename it to interface_tags.
            lldp-profile:
                type: str
                description: Deprecated, please rename it to lldp_profile. LLDP profile to be applied when using this policy.
            mac:
                type: str
                description: Match policy based on MAC address.
            name:
                type: str
                description: Policy name.
                required: true
            qos-policy:
                type: str
                description: Deprecated, please rename it to qos_policy. QoS policy to be applied when using this policy.
            status:
                type: str
                description: Enable/disable policy.
                choices:
                    - 'disable'
                    - 'enable'
            type:
                type: str
                description: Match policy based on type.
            vlan-policy:
                type: str
                description: Deprecated, please rename it to vlan_policy. VLAN policy to be applied when using this policy.
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
    - name: Port policies with matching criteria and actions.
      fortinet.fortimanager.fmgr_switchcontroller_dynamicportpolicy_policy:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        dynamic_port_policy: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_dynamicportpolicy_policy:
          802_1x: <string>
          bounce_port_link: <value in [disable, enable]>
          category: <value in [device, interface-tag]>
          description: <string>
          family: <string>
          host: <string>
          hw_vendor: <string>
          interface_tags: <list or string>
          lldp_profile: <string>
          mac: <string>
          name: <string>
          qos_policy: <string>
          status: <value in [disable, enable]>
          type: <string>
          vlan_policy: <string>
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
        '/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy',
        '/pm/config/global/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}',
        '/pm/config/global/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}'
    ]

    url_params = ['adom', 'dynamic-port-policy']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'dynamic-port-policy': {'type': 'str', 'api_name': 'dynamic_port_policy'},
        'dynamic_port_policy': {'type': 'str'},
        'switchcontroller_dynamicportpolicy_policy': {
            'type': 'dict',
            'v_range': [['7.2.1', '']],
            'options': {
                '802-1x': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'bounce-port-link': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'category': {'v_range': [['7.2.1', '']], 'choices': ['device', 'interface-tag'], 'type': 'str'},
                'description': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'family': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'host': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'hw-vendor': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'interface-tags': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'lldp-profile': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'mac': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.1', '']], 'required': True, 'type': 'str'},
                'qos-policy': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'status': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'vlan-policy': {'v_range': [['7.2.1', '']], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_dynamicportpolicy_policy'),
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
