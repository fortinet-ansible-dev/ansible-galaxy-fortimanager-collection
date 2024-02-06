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
module: fmgr_system_interface
short_description: Interface configuration.
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
    system_interface:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            alias:
                type: str
                description: Alias.
            allowaccess:
                type: list
                elements: str
                description:
                    - Allow management access to interface.
                    - ping - PING access.
                    - https - HTTPS access.
                    - ssh - SSH access.
                    - snmp - SNMP access.
                    - http - HTTP access.
                    - webservice - Web service access.
                    - https-logging - Logging over HTTPS access.
                choices:
                    - 'ping'
                    - 'https'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'webservice'
                    - 'https-logging'
                    - 'soc-fabric'
                    - 'fabric'
            description:
                type: str
                description: Description.
            ip:
                type: str
                description: IP address of interface.
            ipv6:
                type: dict
                description: No description.
                suboptions:
                    ip6-address:
                        type: str
                        description: Deprecated, please rename it to ip6_address. IPv6 address/prefix of interface.
                    ip6-allowaccess:
                        type: list
                        elements: str
                        description:
                            - Deprecated, please rename it to ip6_allowaccess.
                            - Allow management access to interface.
                            - ping - PING access.
                            - https - HTTPS access.
                            - ssh - SSH access.
                            - snmp - SNMP access.
                            - http - HTTP access.
                            - webservice - Web service access.
                            - https-logging - Logging over HTTPS access.
                        choices:
                            - 'ping'
                            - 'https'
                            - 'ssh'
                            - 'snmp'
                            - 'http'
                            - 'webservice'
                            - 'https-logging'
                            - 'fabric'
                    ip6-autoconf:
                        type: str
                        description:
                            - Deprecated, please rename it to ip6_autoconf.
                            - Enable/disable address auto config
                            - disable - Disable setting.
                            - enable - Enable setting.
                        choices:
                            - 'disable'
                            - 'enable'
            mtu:
                type: int
                description: Maximum transportation unit
            name:
                type: str
                description: Interface name.
                required: true
            serviceaccess:
                type: list
                elements: str
                description:
                    - Allow service access to interface.
                    - fgtupdates - FortiGate updates access.
                    - fclupdates - FortiClient updates access.
                    - webfilter-antispam - Web filtering and antispam access.
                choices:
                    - 'fgtupdates'
                    - 'fclupdates'
                    - 'webfilter-antispam'
            speed:
                type: str
                description:
                    - Speed.
                    - auto - Auto adjust speed.
                    - 10full - 10M full-duplex.
                    - 10half - 10M half-duplex.
                    - 100full - 100M full-duplex.
                    - 100half - 100M half-duplex.
                    - 1000full - 1000M full-duplex.
                    - 10000full - 10000M full-duplex.
                choices:
                    - 'auto'
                    - '10full'
                    - '10half'
                    - '100full'
                    - '100half'
                    - '1000full'
                    - '10000full'
                    - '1g/full'
                    - '2.5g/full'
                    - '5g/full'
                    - '10g/full'
                    - '14g/full'
                    - '20g/full'
                    - '25g/full'
                    - '40g/full'
                    - '50g/full'
                    - '56g/full'
                    - '100g/full'
                    - '1g/half'
            status:
                type: str
                description:
                    - Interface status.
                    - down - Interface down.
                    - up - Interface up.
                choices:
                    - 'down'
                    - 'up'
                    - 'disable'
                    - 'enable'
            rating-service-ip:
                type: str
                description: Deprecated, please rename it to rating_service_ip. IP address for fgt rating service, must be same subnet with interface ip.
            update-service-ip:
                type: str
                description: Deprecated, please rename it to update_service_ip. IP address for fgt/fct update service, must be same subnet with interfa...
            aggregate:
                type: str
                description: Aggregate interface.
            interface:
                type: str
                description: Underlying interface name.
            lacp-mode:
                type: str
                description:
                    - Deprecated, please rename it to lacp_mode.
                    - LACP mode.
                    - active - Actively use LACP to negotiate 802.
                choices:
                    - 'active'
            lacp-speed:
                type: str
                description:
                    - Deprecated, please rename it to lacp_speed.
                    - How often the interface sends LACP messages.
                    - slow - Send LACP message every 30 seconds.
                    - fast - Send LACP message every second.
                choices:
                    - 'slow'
                    - 'fast'
            link-up-delay:
                type: int
                description: Deprecated, please rename it to link_up_delay. Number of milliseconds to wait before considering a link is up.
            member:
                type: list
                elements: dict
                description: No description.
                suboptions:
                    interface-name:
                        type: str
                        description: Deprecated, please rename it to interface_name. Physical interface name.
            min-links:
                type: int
                description: Deprecated, please rename it to min_links. Minimum number of aggregated ports that must be up.
            min-links-down:
                type: str
                description:
                    - Deprecated, please rename it to min_links_down.
                    - Action to take when less than the configured minimum number of links are active.
                    - operational - Set the aggregate operationally down.
                    - administrative - Set the aggregate administratively down.
                choices:
                    - 'operational'
                    - 'administrative'
            type:
                type: str
                description:
                    - Interface type.
                    - vlan - VLAN interface.
                    - physical - Physical interface.
                    - aggregate - Aggregate interface.
                choices:
                    - 'vlan'
                    - 'physical'
                    - 'aggregate'
            vlan-protocol:
                type: str
                description:
                    - Deprecated, please rename it to vlan_protocol.
                    - Ethernet protocol of VLAN.
                    - 8021q - IEEE 802.
                    - 8021ad - IEEE 802.
                choices:
                    - '8021q'
                    - '8021ad'
            vlanid:
                type: int
                description: VLAN ID
            lldp:
                type: str
                description:
                    - Enable/disable LLDP
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            defaultgw:
                type: str
                description:
                    - Enable/disable default gateway.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp-client-identifier:
                type: str
                description: Deprecated, please rename it to dhcp_client_identifier. DHCP client identifier.
            dns-server-override:
                type: str
                description:
                    - Deprecated, please rename it to dns_server_override.
                    - Enable/disable use DNS acquired by DHCP or PPPoE.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            mode:
                type: str
                description:
                    - Addressing mode
                    - static - Static setting.
                    - dhcp - External DHCP client mode.
                choices:
                    - 'static'
                    - 'dhcp'
            mtu-override:
                type: str
                description:
                    - Deprecated, please rename it to mtu_override.
                    - Enable/disable use MTU acquired by DHCP or PPPoE.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Interface configuration.
      fortinet.fortimanager.fmgr_system_interface:
        bypass_validation: false
        state: present
        system_interface:
          allowaccess:
            - ping
          ip: "222.222.22.2/24"
          mtu: 1500
          name: port4
          serviceaccess:
            - fgtupdates
          speed: auto # <value in [auto, 10full, 10half, ...]>
          status: up

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the interfaces
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_interface"
          params:
            interface: "your_value"
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
        '/cli/global/system/interface'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/interface/{interface}'
    ]

    url_params = []
    module_primary_key = 'name'
    module_arg_spec = {
        'system_interface': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'alias': {'type': 'str'},
                'allowaccess': {
                    'type': 'list',
                    'choices': ['ping', 'https', 'ssh', 'snmp', 'http', 'webservice', 'https-logging', 'soc-fabric', 'fabric'],
                    'elements': 'str'
                },
                'description': {'type': 'str'},
                'ip': {'type': 'str'},
                'ipv6': {
                    'type': 'dict',
                    'options': {
                        'ip6-address': {'type': 'str'},
                        'ip6-allowaccess': {
                            'type': 'list',
                            'choices': ['ping', 'https', 'ssh', 'snmp', 'http', 'webservice', 'https-logging', 'fabric'],
                            'elements': 'str'
                        },
                        'ip6-autoconf': {'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'mtu': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'serviceaccess': {'type': 'list', 'choices': ['fgtupdates', 'fclupdates', 'webfilter-antispam'], 'elements': 'str'},
                'speed': {
                    'choices': [
                        'auto', '10full', '10half', '100full', '100half', '1000full', '10000full', '1g/full', '2.5g/full', '5g/full', '10g/full',
                        '14g/full', '20g/full', '25g/full', '40g/full', '50g/full', '56g/full', '100g/full', '1g/half'
                    ],
                    'type': 'str'
                },
                'status': {'choices': ['down', 'up', 'disable', 'enable'], 'type': 'str'},
                'rating-service-ip': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'update-service-ip': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'aggregate': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'interface': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'lacp-mode': {'v_range': [['7.2.0', '']], 'choices': ['active'], 'type': 'str'},
                'lacp-speed': {'v_range': [['7.2.0', '']], 'choices': ['slow', 'fast'], 'type': 'str'},
                'link-up-delay': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'member': {
                    'v_range': [['7.2.0', '']],
                    'type': 'list',
                    'options': {'interface-name': {'v_range': [['7.2.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'min-links': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'min-links-down': {'v_range': [['7.2.0', '']], 'choices': ['operational', 'administrative'], 'type': 'str'},
                'type': {'v_range': [['7.2.0', '']], 'choices': ['vlan', 'physical', 'aggregate'], 'type': 'str'},
                'vlan-protocol': {'v_range': [['7.2.0', '']], 'choices': ['8021q', '8021ad'], 'type': 'str'},
                'vlanid': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'lldp': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'defaultgw': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-client-identifier': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'dns-server-override': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mode': {'v_range': [['7.4.2', '']], 'choices': ['static', 'dhcp'], 'type': 'str'},
                'mtu-override': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_interface'),
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
