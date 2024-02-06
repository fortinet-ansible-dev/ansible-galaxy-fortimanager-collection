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
module: fmgr_qosprofile
short_description: Configure WiFi quality of service
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
    qosprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bandwidth-admission-control:
                type: str
                description: Deprecated, please rename it to bandwidth_admission_control. Enable/disable WMM bandwidth admission control.
                choices:
                    - 'disable'
                    - 'enable'
            bandwidth-capacity:
                type: int
                description: Deprecated, please rename it to bandwidth_capacity. Maximum bandwidth capacity allowed
            burst:
                type: str
                description: Enable/disable client rate burst.
                choices:
                    - 'disable'
                    - 'enable'
            call-admission-control:
                type: str
                description: Deprecated, please rename it to call_admission_control. Enable/disable WMM call admission control.
                choices:
                    - 'disable'
                    - 'enable'
            call-capacity:
                type: int
                description: Deprecated, please rename it to call_capacity. Maximum number of Voice over WLAN
            comment:
                type: str
                description: Comment.
            downlink:
                type: int
                description: Maximum downlink bandwidth for Virtual Access Points
            downlink-sta:
                type: int
                description: Deprecated, please rename it to downlink_sta. Maximum downlink bandwidth for clients
            dscp-wmm-be:
                type: raw
                description: (list) Deprecated, please rename it to dscp_wmm_be. DSCP mapping for best effort access
            dscp-wmm-bk:
                type: raw
                description: (list) Deprecated, please rename it to dscp_wmm_bk. DSCP mapping for background access
            dscp-wmm-mapping:
                type: str
                description: Deprecated, please rename it to dscp_wmm_mapping. Enable/disable Differentiated Services Code Point
                choices:
                    - 'disable'
                    - 'enable'
            dscp-wmm-vi:
                type: raw
                description: (list) Deprecated, please rename it to dscp_wmm_vi. DSCP mapping for video access
            dscp-wmm-vo:
                type: raw
                description: (list) Deprecated, please rename it to dscp_wmm_vo. DSCP mapping for voice access
            name:
                type: str
                description: WiFi QoS profile name.
                required: true
            uplink:
                type: int
                description: Maximum uplink bandwidth for Virtual Access Points
            uplink-sta:
                type: int
                description: Deprecated, please rename it to uplink_sta. Maximum uplink bandwidth for clients
            wmm:
                type: str
                description: Enable/disable WiFi multi-media
                choices:
                    - 'disable'
                    - 'enable'
            wmm-uapsd:
                type: str
                description: Deprecated, please rename it to wmm_uapsd. Enable/disable WMM Unscheduled Automatic Power Save Delivery
                choices:
                    - 'disable'
                    - 'enable'
            wmm-be-dscp:
                type: int
                description: Deprecated, please rename it to wmm_be_dscp. DSCP marking for best effort access
            wmm-bk-dscp:
                type: int
                description: Deprecated, please rename it to wmm_bk_dscp. DSCP marking for background access
            wmm-dscp-marking:
                type: str
                description: Deprecated, please rename it to wmm_dscp_marking. Enable/disable WMM Differentiated Services Code Point
                choices:
                    - 'disable'
                    - 'enable'
            wmm-vi-dscp:
                type: int
                description: Deprecated, please rename it to wmm_vi_dscp. DSCP marking for video access
            wmm-vo-dscp:
                type: int
                description: Deprecated, please rename it to wmm_vo_dscp. DSCP marking for voice access
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
    - name: Configure WiFi quality of service
      fortinet.fortimanager.fmgr_qosprofile:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        qosprofile:
          bandwidth_admission_control: <value in [disable, enable]>
          bandwidth_capacity: <integer>
          burst: <value in [disable, enable]>
          call_admission_control: <value in [disable, enable]>
          call_capacity: <integer>
          comment: <string>
          downlink: <integer>
          downlink_sta: <integer>
          dscp_wmm_be: <list or integer>
          dscp_wmm_bk: <list or integer>
          dscp_wmm_mapping: <value in [disable, enable]>
          dscp_wmm_vi: <list or integer>
          dscp_wmm_vo: <list or integer>
          name: <string>
          uplink: <integer>
          uplink_sta: <integer>
          wmm: <value in [disable, enable]>
          wmm_uapsd: <value in [disable, enable]>
          wmm_be_dscp: <integer>
          wmm_bk_dscp: <integer>
          wmm_dscp_marking: <value in [disable, enable]>
          wmm_vi_dscp: <integer>
          wmm_vo_dscp: <integer>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/qos-profile',
        '/pm/config/global/obj/wireless-controller/qos-profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/qos-profile/{qos-profile}',
        '/pm/config/global/obj/wireless-controller/qos-profile/{qos-profile}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'qosprofile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'bandwidth-admission-control': {'choices': ['disable', 'enable'], 'type': 'str'},
                'bandwidth-capacity': {'type': 'int'},
                'burst': {'choices': ['disable', 'enable'], 'type': 'str'},
                'call-admission-control': {'choices': ['disable', 'enable'], 'type': 'str'},
                'call-capacity': {'type': 'int'},
                'comment': {'type': 'str'},
                'downlink': {'type': 'int'},
                'downlink-sta': {'type': 'int'},
                'dscp-wmm-be': {'type': 'raw'},
                'dscp-wmm-bk': {'type': 'raw'},
                'dscp-wmm-mapping': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-wmm-vi': {'type': 'raw'},
                'dscp-wmm-vo': {'type': 'raw'},
                'name': {'required': True, 'type': 'str'},
                'uplink': {'type': 'int'},
                'uplink-sta': {'type': 'int'},
                'wmm': {'choices': ['disable', 'enable'], 'type': 'str'},
                'wmm-uapsd': {'choices': ['disable', 'enable'], 'type': 'str'},
                'wmm-be-dscp': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'wmm-bk-dscp': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'wmm-dscp-marking': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wmm-vi-dscp': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'wmm-vo-dscp': {'v_range': [['6.2.0', '']], 'type': 'int'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'qosprofile'),
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
