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
module: fmgr_switchcontroller_qos_queuepolicy
short_description: Configure FortiSwitch QoS egress queue policy.
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
    switchcontroller_qos_queuepolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cos-queue:
                type: list
                elements: dict
                description: Deprecated, please rename it to cos_queue. Cos-Queue.
                suboptions:
                    description:
                        type: str
                        description: Description of the COS queue.
                    drop-policy:
                        type: str
                        description: Deprecated, please rename it to drop_policy. COS queue drop policy.
                        choices:
                            - 'taildrop'
                            - 'weighted-random-early-detection'
                    max-rate:
                        type: int
                        description: Deprecated, please rename it to max_rate. Maximum rate
                    min-rate:
                        type: int
                        description: Deprecated, please rename it to min_rate. Minimum rate
                    name:
                        type: str
                        description: Cos queue ID.
                    weight:
                        type: int
                        description: Weight of weighted round robin scheduling.
                    max-rate-percent:
                        type: int
                        description: Deprecated, please rename it to max_rate_percent. Maximum rate
                    min-rate-percent:
                        type: int
                        description: Deprecated, please rename it to min_rate_percent. Minimum rate
                    ecn:
                        type: str
                        description: Enable/disable ECN packet marking to drop eligible packets.
                        choices:
                            - 'disable'
                            - 'enable'
            name:
                type: str
                description: QoS policy name
                required: true
            schedule:
                type: str
                description: COS queue scheduling.
                choices:
                    - 'strict'
                    - 'round-robin'
                    - 'weighted'
            rate-by:
                type: str
                description: Deprecated, please rename it to rate_by. COS queue rate by kbps or percent.
                choices:
                    - 'kbps'
                    - 'percent'
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
    - name: Configure FortiSwitch QoS egress queue policy.
      fortinet.fortimanager.fmgr_switchcontroller_qos_queuepolicy:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_qos_queuepolicy:
          cos_queue:
            -
              description: <string>
              drop_policy: <value in [taildrop, weighted-random-early-detection]>
              max_rate: <integer>
              min_rate: <integer>
              name: <string>
              weight: <integer>
              max_rate_percent: <integer>
              min_rate_percent: <integer>
              ecn: <value in [disable, enable]>
          name: <string>
          schedule: <value in [strict, round-robin, weighted]>
          rate_by: <value in [kbps, percent]>
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
        '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy',
        '/pm/config/global/obj/switch-controller/qos/queue-policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}',
        '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'switchcontroller_qos_queuepolicy': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'cos-queue': {
                    'type': 'list',
                    'options': {
                        'description': {'type': 'str'},
                        'drop-policy': {'choices': ['taildrop', 'weighted-random-early-detection'], 'type': 'str'},
                        'max-rate': {'type': 'int'},
                        'min-rate': {'type': 'int'},
                        'name': {'type': 'str'},
                        'weight': {'type': 'int'},
                        'max-rate-percent': {'v_range': [['6.2.0', '']], 'type': 'int'},
                        'min-rate-percent': {'v_range': [['6.2.0', '']], 'type': 'int'},
                        'ecn': {'v_range': [['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'required': True, 'type': 'str'},
                'schedule': {'choices': ['strict', 'round-robin', 'weighted'], 'type': 'str'},
                'rate-by': {'v_range': [['6.2.0', '']], 'choices': ['kbps', 'percent'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_qos_queuepolicy'),
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
