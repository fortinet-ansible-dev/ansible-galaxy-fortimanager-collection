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
module: fmgr_fsp_vlan_dynamicmapping_dhcpserver_iprange
short_description: DHCP IP range configuration.
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
    vlan:
        description: The parameter (vlan) in requested url.
        type: str
        required: true
    dynamic_mapping:
        description: The parameter (dynamic_mapping) in requested url.
        type: str
        required: true
    fsp_vlan_dynamicmapping_dhcpserver_iprange:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            end-ip:
                type: str
                description: Deprecated, please rename it to end_ip.
            id:
                type: int
                description: No description.
                required: true
            start-ip:
                type: str
                description: Deprecated, please rename it to start_ip.
            vci-match:
                type: str
                description: Deprecated, please rename it to vci_match. Enable/disable vendor class identifier
                choices:
                    - 'disable'
                    - 'enable'
            vci-string:
                type: raw
                description: (list) Deprecated, please rename it to vci_string.
            lease-time:
                type: int
                description: Deprecated, please rename it to lease_time. Lease time in seconds, 0 means default lease time.
            uci-match:
                type: str
                description: Deprecated, please rename it to uci_match. Enable/disable user class identifier
                choices:
                    - 'disable'
                    - 'enable'
            uci-string:
                type: raw
                description: (list) Deprecated, please rename it to uci_string.
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
    - name: DHCP IP range configuration.
      fortinet.fortimanager.fmgr_fsp_vlan_dynamicmapping_dhcpserver_iprange:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        vlan: <your own value>
        dynamic_mapping: <your own value>
        state: present # <value in [present, absent]>
        fsp_vlan_dynamicmapping_dhcpserver_iprange:
          end_ip: <string>
          id: <integer>
          start_ip: <string>
          vci_match: <value in [disable, enable]>
          vci_string: <list or string>
          lease_time: <integer>
          uci_match: <value in [disable, enable]>
          uci_string: <list or string>
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
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}'
    ]

    url_params = ['adom', 'vlan', 'dynamic_mapping']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vlan': {'required': True, 'type': 'str'},
        'dynamic_mapping': {'required': True, 'type': 'str'},
        'fsp_vlan_dynamicmapping_dhcpserver_iprange': {
            'type': 'dict',
            'v_range': [['6.0.0', '7.4.0']],
            'options': {
                'end-ip': {'v_range': [['6.0.0', '7.4.0']], 'type': 'str'},
                'id': {'v_range': [['6.0.0', '7.4.0']], 'required': True, 'type': 'int'},
                'start-ip': {'v_range': [['6.0.0', '7.4.0']], 'type': 'str'},
                'vci-match': {'v_range': [['7.2.1', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vci-string': {'v_range': [['7.2.1', '7.4.0']], 'type': 'raw'},
                'lease-time': {'v_range': [['7.2.2', '7.4.0']], 'type': 'int'},
                'uci-match': {'v_range': [['7.2.2', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uci-string': {'v_range': [['7.2.2', '7.4.0']], 'type': 'raw'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_dynamicmapping_dhcpserver_iprange'),
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
