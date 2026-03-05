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
module: fmgr_devprof_system_template_interface
short_description: System template system template interface
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "2.13.0"
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
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_system_template_interface:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action.
                choices:
                    - 'add-aggregate'
                    - 'add-loopback'
                    - 'add-vlan'
                    - 'add-zone'
                    - 'conf-intf'
                    - 'conf-dhcp-server'
                    - 'conf-monitor-bandwd'
                    - 'conf-vap-ssid'
            allowaccess:
                type: list
                elements: str
                description: Allowaccess.
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
                    - 'fgfm'
                    - 'radius-acct'
                    - 'probe-response'
                    - 'dnp'
                    - 'ftm'
                    - 'fabric'
                    - 'speed-test'
            dhcp_id:
                aliases: ['dhcp-id']
                type: int
                description: Support meta variable
            gateway:
                type: str
                description: Support meta variable
            interface:
                type: str
                description: Support meta variable
            interface_members:
                aliases: ['interface-members']
                type: list
                elements: str
                description: Support meta variable
            ip_range:
                aliases: ['ip-range']
                type: list
                elements: dict
                description: Ip range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description: End ip.
                    id:
                        type: int
                        description: Id.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Start ip.
            ipmask:
                type: list
                elements: str
                description: Support meta variable
            model:
                type: str
                description: Model.
            monitor_bandwidth:
                aliases: ['monitor-bandwidth']
                type: str
                description: Monitor bandwidth.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Support meta variable
                required: true
            netmask:
                type: str
                description: Support meta variable
            role:
                type: str
                description: Role.
                choices:
                    - 'lan'
                    - 'wan'
                    - 'dmz'
                    - 'undefined'
            seq:
                type: int
                description: Seq.
            vdom:
                type: str
                description: Support meta variable
            vlan_id:
                aliases: ['vlan-id']
                type: int
                description: Support meta variable
            wifi_key:
                aliases: ['wifi-key']
                type: list
                elements: str
                description: Wifi key.
            wifi_security:
                aliases: ['wifi-security']
                type: str
                description: Wifi security.
                choices:
                    - 'None'
                    - 'wep64'
                    - 'wep128'
                    - 'WPA_PSK'
                    - 'WPA_RADIUS'
                    - 'WPA'
                    - 'WPA2'
                    - 'WPA2_AUTO'
                    - 'open'
                    - 'wpa-personal'
                    - 'wpa-enterprise'
                    - 'captive-portal'
                    - 'wpa-only-personal'
                    - 'wpa-only-enterprise'
                    - 'wpa2-only-personal'
                    - 'wpa2-only-enterprise'
                    - 'wpa-personal+captive-portal'
                    - 'wpa-only-personal+captive-portal'
                    - 'wpa2-only-personal+captive-portal'
                    - 'osen'
                    - 'wpa3-enterprise'
                    - 'sae'
                    - 'sae-transition'
                    - 'owe'
                    - 'wpa3-sae'
                    - 'wpa3-sae-transition'
                    - 'wpa3-only-enterprise'
                    - 'wpa3-enterprise-transition'
            wifi_ssid:
                aliases: ['wifi-ssid']
                type: str
                description: Support meta variable
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: System template system template interface
      fortinet.fortimanager.fmgr_devprof_system_template_interface:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        devprof: <your own value>
        state: present # <value in [present, absent]>
        devprof_system_template_interface:
          name: "your value" # Required variable, string
          # action: <value in [add-aggregate, add-loopback, add-vlan, ...]>
          # allowaccess:
          #   - "https"
          #   - "ping"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          #   - "fgfm"
          #   - "radius-acct"
          #   - "probe-response"
          #   - "dnp"
          #   - "ftm"
          #   - "fabric"
          #   - "speed-test"
          # dhcp_id: <integer>
          # gateway: <string>
          # interface: <string>
          # interface_members: <list or string>
          # ip_range:
          #   - end_ip: <string>
          #     id: <integer>
          #     start_ip: <string>
          # ipmask: <list or string>
          # model: <string>
          # monitor_bandwidth: <value in [disable, enable]>
          # netmask: <string>
          # role: <value in [lan, wan, dmz, ...]>
          # seq: <integer>
          # vdom: <string>
          # vlan_id: <integer>
          # wifi_key: <list or string>
          # wifi_security: <value in [None, wep64, wep128, ...]>
          # wifi_ssid: <string>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/template/interface'
    ]
    url_params = ['adom', 'devprof']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_template_interface': {
            'type': 'dict',
            'v_range': [['7.6.5', '']],
            'options': {
                'action': {
                    'v_range': [['7.6.5', '']],
                    'choices': [
                        'add-aggregate', 'add-loopback', 'add-vlan', 'add-zone', 'conf-intf', 'conf-dhcp-server', 'conf-monitor-bandwd', 'conf-vap-ssid'
                    ],
                    'type': 'str'
                },
                'allowaccess': {
                    'v_range': [['7.6.5', '']],
                    'type': 'list',
                    'choices': [
                        'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'radius-acct', 'probe-response', 'dnp', 'ftm', 'fabric', 'speed-test'
                    ],
                    'elements': 'str'
                },
                'dhcp-id': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'gateway': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'interface': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'interface-members': {'v_range': [['7.6.5', '']], 'type': 'list', 'elements': 'str'},
                'ip-range': {
                    'v_range': [['7.6.5', '']],
                    'type': 'list',
                    'options': {
                        'end-ip': {'v_range': [['7.6.5', '']], 'type': 'str'},
                        'id': {'v_range': [['7.6.5', '']], 'type': 'int'},
                        'start-ip': {'v_range': [['7.6.5', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ipmask': {'v_range': [['7.6.5', '']], 'type': 'list', 'elements': 'str'},
                'model': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'monitor-bandwidth': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.6.5', '']], 'required': True, 'type': 'str'},
                'netmask': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'role': {'v_range': [['7.6.5', '']], 'choices': ['lan', 'wan', 'dmz', 'undefined'], 'type': 'str'},
                'seq': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'vdom': {'v_range': [['7.6.5', '']], 'type': 'str'},
                'vlan-id': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'wifi-key': {'v_range': [['7.6.5', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'wifi-security': {
                    'v_range': [['7.6.5', '']],
                    'choices': [
                        'None', 'wep64', 'wep128', 'WPA_PSK', 'WPA_RADIUS', 'WPA', 'WPA2', 'WPA2_AUTO', 'open', 'wpa-personal', 'wpa-enterprise',
                        'captive-portal', 'wpa-only-personal', 'wpa-only-enterprise', 'wpa2-only-personal', 'wpa2-only-enterprise',
                        'wpa-personal+captive-portal', 'wpa-only-personal+captive-portal', 'wpa2-only-personal+captive-portal', 'osen',
                        'wpa3-enterprise', 'sae', 'sae-transition', 'owe', 'wpa3-sae', 'wpa3-sae-transition', 'wpa3-only-enterprise',
                        'wpa3-enterprise-transition'
                    ],
                    'type': 'str'
                },
                'wifi-ssid': {'v_range': [['7.6.5', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_template_interface'),
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
