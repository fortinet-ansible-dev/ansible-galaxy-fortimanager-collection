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
module: fmgr_ips_baseline_sensor_entries
short_description: IPS sensor filter.
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
    sensor:
        description: The parameter (sensor) in requested url.
        type: str
        required: true
    ips_baseline_sensor_entries:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action taken with traffic in which signatures are detected.
                choices:
                    - 'pass'
                    - 'block'
                    - 'reset'
                    - 'default'
            application:
                type: raw
                description: (list) No description.
            cve:
                type: raw
                description: (list) No description.
            exempt-ip:
                type: list
                elements: dict
                description: Deprecated, please rename it to exempt_ip.
                suboptions:
                    dst-ip:
                        type: str
                        description: Deprecated, please rename it to dst_ip. Destination IP address and netmask.
                    id:
                        type: int
                        description: Exempt IP ID.
                    src-ip:
                        type: str
                        description: Deprecated, please rename it to src_ip. Source IP address and netmask.
            id:
                type: int
                description: Rule ID in IPS database
                required: true
            location:
                type: raw
                description: (list) No description.
            log:
                type: str
                description: Enable/disable logging of signatures included in filter.
                choices:
                    - 'disable'
                    - 'enable'
            log-attack-context:
                type: str
                description: Deprecated, please rename it to log_attack_context. Enable/disable logging of attack context
                choices:
                    - 'disable'
                    - 'enable'
            log-packet:
                type: str
                description: Deprecated, please rename it to log_packet. Enable/disable packet logging.
                choices:
                    - 'disable'
                    - 'enable'
            os:
                type: raw
                description: (list) No description.
            protocol:
                type: raw
                description: (list) No description.
            quarantine:
                type: str
                description: Quarantine method.
                choices:
                    - 'none'
                    - 'attacker'
                    - 'both'
                    - 'interface'
            quarantine-expiry:
                type: str
                description: Deprecated, please rename it to quarantine_expiry. Duration of quarantine.
            quarantine-log:
                type: str
                description: Deprecated, please rename it to quarantine_log. Enable/disable quarantine logging.
                choices:
                    - 'disable'
                    - 'enable'
            rate-count:
                type: int
                description: Deprecated, please rename it to rate_count. Count of the rate.
            rate-duration:
                type: int
                description: Deprecated, please rename it to rate_duration. Duration
            rate-mode:
                type: str
                description: Deprecated, please rename it to rate_mode. Rate limit mode.
                choices:
                    - 'periodical'
                    - 'continuous'
            rate-track:
                type: str
                description: Deprecated, please rename it to rate_track. Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
                    - 'dhcp-client-mac'
                    - 'dns-domain'
            rule:
                type: str
                description: Identifies the predefined or custom IPS signatures to add to the sensor.
            severity:
                type: raw
                description: (list) No description.
            status:
                type: str
                description: Status of the signatures included in filter.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'default'
            tags:
                type: str
                description: No description.
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
    - name: IPS sensor filter.
      fortinet.fortimanager.fmgr_ips_baseline_sensor_entries:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        sensor: <your own value>
        state: present # <value in [present, absent]>
        ips_baseline_sensor_entries:
          action: <value in [pass, block, reset, ...]>
          application: <list or string>
          cve: <list or string>
          exempt_ip:
            -
              dst_ip: <string>
              id: <integer>
              src_ip: <string>
          id: <integer>
          location: <list or string>
          log: <value in [disable, enable]>
          log_attack_context: <value in [disable, enable]>
          log_packet: <value in [disable, enable]>
          os: <list or string>
          protocol: <list or string>
          quarantine: <value in [none, attacker, both, ...]>
          quarantine_expiry: <string>
          quarantine_log: <value in [disable, enable]>
          rate_count: <integer>
          rate_duration: <integer>
          rate_mode: <value in [periodical, continuous]>
          rate_track: <value in [none, src-ip, dest-ip, ...]>
          rule: <string>
          severity: <list or string>
          status: <value in [disable, enable, default]>
          tags: <string>
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
        '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/entries',
        '/pm/config/global/obj/ips/baseline/sensor/{sensor}/entries'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/entries/{entries}',
        '/pm/config/global/obj/ips/baseline/sensor/{sensor}/entries/{entries}'
    ]

    url_params = ['adom', 'sensor']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'sensor': {'required': True, 'type': 'str'},
        'ips_baseline_sensor_entries': {
            'type': 'dict',
            'v_range': [['7.0.1', '7.0.2']],
            'options': {
                'action': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['pass', 'block', 'reset', 'default'], 'type': 'str'},
                'application': {'v_range': [['7.0.1', '7.0.2']], 'type': 'raw'},
                'cve': {'v_range': [['7.0.1', '7.0.2']], 'type': 'raw'},
                'exempt-ip': {
                    'v_range': [['7.0.1', '7.0.2']],
                    'type': 'list',
                    'options': {
                        'dst-ip': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'},
                        'id': {'v_range': [['7.0.1', '7.0.2']], 'type': 'int'},
                        'src-ip': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['7.0.1', '7.0.2']], 'required': True, 'type': 'int'},
                'location': {'v_range': [['7.0.1', '7.0.2']], 'type': 'raw'},
                'log': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-attack-context': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-packet': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'os': {'v_range': [['7.0.1', '7.0.2']], 'type': 'raw'},
                'protocol': {'v_range': [['7.0.1', '7.0.2']], 'type': 'raw'},
                'quarantine': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['none', 'attacker', 'both', 'interface'], 'type': 'str'},
                'quarantine-expiry': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'},
                'quarantine-log': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rate-count': {'v_range': [['7.0.1', '7.0.2']], 'type': 'int'},
                'rate-duration': {'v_range': [['7.0.1', '7.0.2']], 'type': 'int'},
                'rate-mode': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['periodical', 'continuous'], 'type': 'str'},
                'rate-track': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['none', 'src-ip', 'dest-ip', 'dhcp-client-mac', 'dns-domain'], 'type': 'str'},
                'rule': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'},
                'severity': {'v_range': [['7.0.1', '7.0.2']], 'type': 'raw'},
                'status': {'v_range': [['7.0.1', '7.0.2']], 'choices': ['disable', 'enable', 'default'], 'type': 'str'},
                'tags': {'v_range': [['7.0.1', '7.0.2']], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ips_baseline_sensor_entries'),
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
