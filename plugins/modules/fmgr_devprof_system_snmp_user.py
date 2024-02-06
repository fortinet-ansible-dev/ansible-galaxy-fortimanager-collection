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
module: fmgr_devprof_system_snmp_user
short_description: SNMP user configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    devprof_system_snmp_user:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth-proto:
                type: str
                description: Deprecated, please rename it to auth_proto. Authentication protocol.
                choices:
                    - 'md5'
                    - 'sha'
                    - 'sha224'
                    - 'sha256'
                    - 'sha384'
                    - 'sha512'
            auth-pwd:
                type: raw
                description: (list) Deprecated, please rename it to auth_pwd.
            events:
                type: list
                elements: str
                description: No description.
                choices:
                    - 'cpu-high'
                    - 'mem-low'
                    - 'log-full'
                    - 'intf-ip'
                    - 'vpn-tun-up'
                    - 'vpn-tun-down'
                    - 'ha-switch'
                    - 'fm-conf-change'
                    - 'ips-signature'
                    - 'ips-anomaly'
                    - 'temperature-high'
                    - 'voltage-alert'
                    - 'av-virus'
                    - 'av-oversize'
                    - 'av-pattern'
                    - 'av-fragmented'
                    - 'ha-hb-failure'
                    - 'fan-failure'
                    - 'ha-member-up'
                    - 'ha-member-down'
                    - 'ent-conf-change'
                    - 'av-conserve'
                    - 'av-bypass'
                    - 'av-oversize-passed'
                    - 'av-oversize-blocked'
                    - 'ips-pkg-update'
                    - 'fm-if-change'
                    - 'power-supply-failure'
                    - 'amc-bypass'
                    - 'faz-disconnect'
                    - 'bgp-established'
                    - 'bgp-backward-transition'
                    - 'wc-ap-up'
                    - 'wc-ap-down'
                    - 'fswctl-session-up'
                    - 'fswctl-session-down'
                    - 'ips-fail-open'
                    - 'load-balance-real-server-down'
                    - 'device-new'
                    - 'enter-intf-bypass'
                    - 'exit-intf-bypass'
                    - 'per-cpu-high'
                    - 'power-blade-down'
                    - 'confsync_failure'
                    - 'dhcp'
                    - 'pool-usage'
                    - 'power-redundancy-degrade'
                    - 'power-redundancy-failure'
                    - 'ospf-nbr-state-change'
                    - 'ospf-virtnbr-state-change'
                    - 'disk-failure'
                    - 'disk-overload'
                    - 'faz-main-failover'
                    - 'faz-alt-failover'
                    - 'slbc'
                    - 'faz'
                    - 'power-supply'
            ha-direct:
                type: str
                description: Deprecated, please rename it to ha_direct. Enable/disable direct management of HA cluster members.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: SNMP user name.
                required: true
            notify-hosts:
                type: raw
                description: (list) Deprecated, please rename it to notify_hosts.
            notify-hosts6:
                type: str
                description: Deprecated, please rename it to notify_hosts6. IPv6 SNMP managers to send notifications
            priv-proto:
                type: str
                description: Deprecated, please rename it to priv_proto. Privacy
                choices:
                    - 'aes'
                    - 'des'
                    - 'aes256'
                    - 'aes256cisco'
            priv-pwd:
                type: raw
                description: (list) Deprecated, please rename it to priv_pwd.
            queries:
                type: str
                description: Enable/disable SNMP queries for this user.
                choices:
                    - 'disable'
                    - 'enable'
            query-port:
                type: int
                description: Deprecated, please rename it to query_port. SNMPv3 query port
            security-level:
                type: str
                description: Deprecated, please rename it to security_level. Security level for message authentication and encryption.
                choices:
                    - 'no-auth-no-priv'
                    - 'auth-no-priv'
                    - 'auth-priv'
            source-ip:
                type: str
                description: Deprecated, please rename it to source_ip. Source IP for SNMP trap.
            source-ipv6:
                type: str
                description: Deprecated, please rename it to source_ipv6. Source IPv6 for SNMP trap.
            status:
                type: str
                description: Enable/disable this SNMP user.
                choices:
                    - 'disable'
                    - 'enable'
            trap-lport:
                type: int
                description: Deprecated, please rename it to trap_lport. SNMPv3 local trap port
            trap-rport:
                type: int
                description: Deprecated, please rename it to trap_rport. SNMPv3 trap remote port
            trap-status:
                type: str
                description: Deprecated, please rename it to trap_status. Enable/disable traps for this SNMP user.
                choices:
                    - 'disable'
                    - 'enable'
            mib-view:
                type: str
                description: Deprecated, please rename it to mib_view. SNMP access control MIB view.
            vdoms:
                type: raw
                description: (list) No description.
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
    - name: SNMP user configuration.
      fortinet.fortimanager.fmgr_devprof_system_snmp_user:
        bypass_validation: false
        adom: ansible
        devprof: "ansible-test" # system template name, could find it in FortiManager UI: Device Manager --> Provisioning Templates --> System Templates
        state: present
        devprof_system_snmp_user:
          auth-proto: md5
          auth-pwd: "fortinet"
          events:
            - cpu-high
            - mem-low
            - log-full
            - intf-ip
            - vpn-tun-up
            - vpn-tun-down
            - ha-switch
            - fm-conf-change
            - ips-signature
            - ips-anomaly
            - temperature-high
            - voltage-alert
            - av-virus
            - av-oversize
            - av-pattern
            - av-fragmented
            - ha-hb-failure
            - fan-failure
            - ha-member-up
            - ha-member-down
            - ent-conf-change
            - av-conserve
            - av-bypass
            - av-oversize-passed
            - av-oversize-blocked
            - ips-pkg-update
            - fm-if-change
            - power-supply-failure
            - amc-bypass
            - faz-disconnect
            - bgp-established
            - bgp-backward-transition
            - wc-ap-up
            - wc-ap-down
            - fswctl-session-up
            - fswctl-session-down
            - ips-fail-open
            - load-balance-real-server-down
            - device-new
            - enter-intf-bypass
            - exit-intf-bypass
            - per-cpu-high
            - power-blade-down
            - confsync_failure
          ha-direct: disable
          name: "ansible-test"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the scripts
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "devprof_system_snmp_user"
          params:
            adom: "ansible"
            devprof: "ansible-test" # system template name, could find it in FortiManager UI: Device Manager --> Provisioning Templates --> System Templates
            user: "your_value"
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user/{user}'
    ]

    url_params = ['adom', 'devprof']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_snmp_user': {
            'type': 'dict',
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
            'options': {
                'auth-proto': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['md5', 'sha', 'sha224', 'sha256', 'sha384', 'sha512'],
                    'type': 'str'
                },
                'auth-pwd': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'raw'},
                'events': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'cpu-high', 'mem-low', 'log-full', 'intf-ip', 'vpn-tun-up', 'vpn-tun-down', 'ha-switch', 'fm-conf-change', 'ips-signature',
                        'ips-anomaly', 'temperature-high', 'voltage-alert', 'av-virus', 'av-oversize', 'av-pattern', 'av-fragmented', 'ha-hb-failure',
                        'fan-failure', 'ha-member-up', 'ha-member-down', 'ent-conf-change', 'av-conserve', 'av-bypass', 'av-oversize-passed',
                        'av-oversize-blocked', 'ips-pkg-update', 'fm-if-change', 'power-supply-failure', 'amc-bypass', 'faz-disconnect',
                        'bgp-established', 'bgp-backward-transition', 'wc-ap-up', 'wc-ap-down', 'fswctl-session-up', 'fswctl-session-down',
                        'ips-fail-open', 'load-balance-real-server-down', 'device-new', 'enter-intf-bypass', 'exit-intf-bypass', 'per-cpu-high',
                        'power-blade-down', 'confsync_failure', 'dhcp', 'pool-usage', 'power-redundancy-degrade', 'power-redundancy-failure',
                        'ospf-nbr-state-change', 'ospf-virtnbr-state-change', 'disk-failure', 'disk-overload', 'faz-main-failover', 'faz-alt-failover',
                        'slbc', 'faz', 'power-supply'
                    ],
                    'elements': 'str'
                },
                'ha-direct': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'required': True, 'type': 'str'},
                'notify-hosts': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'raw'},
                'notify-hosts6': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'priv-proto': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['aes', 'des', 'aes256', 'aes256cisco'],
                    'type': 'str'
                },
                'priv-pwd': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'raw'},
                'queries': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'query-port': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'security-level': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['no-auth-no-priv', 'auth-no-priv', 'auth-priv'],
                    'type': 'str'
                },
                'source-ip': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'source-ipv6': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'str'},
                'status': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trap-lport': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'trap-rport': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'trap-status': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mib-view': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'vdoms': {'v_range': [['7.2.0', '']], 'type': 'raw'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_snmp_user'),
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
