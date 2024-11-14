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
module: fmgr_fsp_vlan_dynamicmapping_interface
short_description: Fsp vlan dynamic mapping interface
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
    fsp_vlan_dynamicmapping_interface:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ip:
                type: str
                description: Ip.
            vlanid:
                type: int
                description: Vlanid.
            dhcp_relay_agent_option:
                type: str
                description: Dhcp relay agent option.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_relay_ip:
                type: raw
                description: (list) Dhcp relay ip.
            dhcp_relay_service:
                type: str
                description: Dhcp relay service.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_relay_type:
                type: str
                description: Dhcp relay type.
                choices:
                    - 'regular'
                    - 'ipsec'
            ipv6:
                type: dict
                description: Ipv6.
                suboptions:
                    autoconf:
                        type: str
                        description: Autoconf.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp6_client_options:
                        type: list
                        elements: str
                        description: Dhcp6 client options.
                        choices:
                            - 'rapid'
                            - 'iapd'
                            - 'iana'
                            - 'dns'
                            - 'dnsname'
                    dhcp6_information_request:
                        type: str
                        description: Dhcp6 information request.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp6_prefix_delegation:
                        type: str
                        description: Dhcp6 prefix delegation.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp6_prefix_hint:
                        type: str
                        description: Dhcp6 prefix hint.
                    dhcp6_prefix_hint_plt:
                        type: int
                        description: Dhcp6 prefix hint plt.
                    dhcp6_prefix_hint_vlt:
                        type: int
                        description: Dhcp6 prefix hint vlt.
                    dhcp6_relay_ip:
                        type: str
                        description: Dhcp6 relay ip.
                    dhcp6_relay_service:
                        type: str
                        description: Dhcp6 relay service.
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp6_relay_type:
                        type: str
                        description: Dhcp6 relay type.
                        choices:
                            - 'regular'
                    ip6_address:
                        type: str
                        description: Ip6 address.
                    ip6_allowaccess:
                        type: list
                        elements: str
                        description: Ip6 allowaccess.
                        choices:
                            - 'https'
                            - 'ping'
                            - 'ssh'
                            - 'snmp'
                            - 'http'
                            - 'telnet'
                            - 'fgfm'
                            - 'capwap'
                            - 'fabric'
                    ip6_default_life:
                        type: int
                        description: Ip6 default life.
                    ip6_delegated_prefix_list:
                        type: list
                        elements: dict
                        description: Ip6 delegated prefix list.
                        suboptions:
                            autonomous_flag:
                                type: str
                                description: Autonomous flag.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            onlink_flag:
                                type: str
                                description: Onlink flag.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            prefix_id:
                                type: int
                                description: Prefix id.
                            rdnss:
                                type: raw
                                description: (list) Rdnss.
                            rdnss_service:
                                type: str
                                description: Rdnss service.
                                choices:
                                    - 'delegated'
                                    - 'default'
                                    - 'specify'
                            subnet:
                                type: str
                                description: Subnet.
                            upstream_interface:
                                type: str
                                description: Upstream interface.
                            delegated_prefix_iaid:
                                type: int
                                description: IAID of obtained delegated-prefix from the upstream interface.
                    ip6_dns_server_override:
                        type: str
                        description: Ip6 dns server override.
                        choices:
                            - 'disable'
                            - 'enable'
                    ip6_extra_addr:
                        type: list
                        elements: dict
                        description: Ip6 extra addr.
                        suboptions:
                            prefix:
                                type: str
                                description: Prefix.
                    ip6_hop_limit:
                        type: int
                        description: Ip6 hop limit.
                    ip6_link_mtu:
                        type: int
                        description: Ip6 link mtu.
                    ip6_manage_flag:
                        type: str
                        description: Ip6 manage flag.
                        choices:
                            - 'disable'
                            - 'enable'
                    ip6_max_interval:
                        type: int
                        description: Ip6 max interval.
                    ip6_min_interval:
                        type: int
                        description: Ip6 min interval.
                    ip6_mode:
                        type: str
                        description: Ip6 mode.
                        choices:
                            - 'static'
                            - 'dhcp'
                            - 'pppoe'
                            - 'delegated'
                    ip6_other_flag:
                        type: str
                        description: Ip6 other flag.
                        choices:
                            - 'disable'
                            - 'enable'
                    ip6_prefix_list:
                        type: list
                        elements: dict
                        description: Ip6 prefix list.
                        suboptions:
                            autonomous_flag:
                                type: str
                                description: Autonomous flag.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            dnssl:
                                type: raw
                                description: (list) Dnssl.
                            onlink_flag:
                                type: str
                                description: Onlink flag.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            preferred_life_time:
                                type: int
                                description: Preferred life time.
                            prefix:
                                type: str
                                description: Prefix.
                            rdnss:
                                type: raw
                                description: (list) Rdnss.
                            valid_life_time:
                                type: int
                                description: Valid life time.
                    ip6_reachable_time:
                        type: int
                        description: Ip6 reachable time.
                    ip6_retrans_time:
                        type: int
                        description: Ip6 retrans time.
                    ip6_send_adv:
                        type: str
                        description: Ip6 send adv.
                        choices:
                            - 'disable'
                            - 'enable'
                    ip6_subnet:
                        type: str
                        description: Ip6 subnet.
                    ip6_upstream_interface:
                        type: str
                        description: Ip6 upstream interface.
                    nd_cert:
                        type: str
                        description: Nd cert.
                    nd_cga_modifier:
                        type: str
                        description: Nd cga modifier.
                    nd_mode:
                        type: str
                        description: Nd mode.
                        choices:
                            - 'basic'
                            - 'SEND-compatible'
                    nd_security_level:
                        type: int
                        description: Nd security level.
                    nd_timestamp_delta:
                        type: int
                        description: Nd timestamp delta.
                    nd_timestamp_fuzz:
                        type: int
                        description: Nd timestamp fuzz.
                    vrip6_link_local:
                        type: str
                        description: Vrip6 link local.
                    vrrp_virtual_mac6:
                        type: str
                        description: Vrrp virtual mac6.
                        choices:
                            - 'disable'
                            - 'enable'
                    vrrp6:
                        type: list
                        elements: dict
                        description: Vrrp6.
                        suboptions:
                            accept_mode:
                                type: str
                                description: Accept mode.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            adv_interval:
                                type: int
                                description: Adv interval.
                            preempt:
                                type: str
                                description: Preempt.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            priority:
                                type: int
                                description: Priority.
                            start_time:
                                type: int
                                description: Start time.
                            status:
                                type: str
                                description: Status.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vrdst6:
                                type: str
                                description: Vrdst6.
                            vrgrp:
                                type: int
                                description: Vrgrp.
                            vrid:
                                type: int
                                description: Vrid.
                            vrip6:
                                type: str
                                description: Vrip6.
                    interface_identifier:
                        type: str
                        description: Interface identifier.
                    unique_autoconf_addr:
                        type: str
                        description: Unique autoconf addr.
                        choices:
                            - 'disable'
                            - 'enable'
                    icmp6_send_redirect:
                        type: str
                        description: Enable/disable sending of ICMPv6 redirects.
                        choices:
                            - 'disable'
                            - 'enable'
                    cli_conn6_status:
                        type: int
                        description: Cli conn6 status.
                    ip6_prefix_mode:
                        type: str
                        description: Assigning a prefix from DHCP or RA.
                        choices:
                            - 'dhcp6'
                            - 'ra'
                    ra_send_mtu:
                        type: str
                        description: Enable/disable sending link MTU in RA packet.
                        choices:
                            - 'disable'
                            - 'enable'
                    ip6_delegated_prefix_iaid:
                        type: int
                        description: IAID of obtained delegated-prefix from the upstream interface.
                    dhcp6_relay_source_interface:
                        type: str
                        description: Enable/disable use of address on this interface as the source address of the relay message.
                        choices:
                            - 'disable'
                            - 'enable'
            secondary_IP:
                type: str
                description: Secondary IP.
                choices:
                    - 'disable'
                    - 'enable'
            secondaryip:
                type: list
                elements: dict
                description: Secondaryip.
                suboptions:
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
                            - 'auto-ipsec'
                            - 'radius-acct'
                            - 'probe-response'
                            - 'capwap'
                            - 'dnp'
                            - 'ftm'
                            - 'fabric'
                            - 'speed-test'
                    detectprotocol:
                        type: list
                        elements: str
                        description: Detectprotocol.
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                    detectserver:
                        type: str
                        description: Detectserver.
                    gwdetect:
                        type: str
                        description: Gwdetect.
                        choices:
                            - 'disable'
                            - 'enable'
                    ha_priority:
                        type: int
                        description: Ha priority.
                    id:
                        type: int
                        description: Id.
                    ip:
                        type: str
                        description: Ip.
                    ping_serv_status:
                        type: int
                        description: Ping serv status.
                    seq:
                        type: int
                        description: Seq.
                    secip_relay_ip:
                        type: str
                        description: DHCP relay IP address.
            dhcp_relay_interface_select_method:
                type: str
                description: Dhcp relay interface select method.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            vrrp:
                type: list
                elements: dict
                description: Vrrp.
                suboptions:
                    accept_mode:
                        type: str
                        description: Enable/disable accept mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    adv_interval:
                        type: int
                        description: Advertisement interval
                    ignore_default_route:
                        type: str
                        description: Enable/disable ignoring of default route when checking destination.
                        choices:
                            - 'disable'
                            - 'enable'
                    preempt:
                        type: str
                        description: Enable/disable preempt mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    priority:
                        type: int
                        description: Priority of the virtual router
                    proxy_arp:
                        type: list
                        elements: dict
                        description: Proxy arp.
                        suboptions:
                            id:
                                type: int
                                description: ID.
                            ip:
                                type: str
                                description: Set IP addresses of proxy ARP.
                    start_time:
                        type: int
                        description: Startup time
                    status:
                        type: str
                        description: Enable/disable this VRRP configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    version:
                        type: str
                        description: VRRP version.
                        choices:
                            - '2'
                            - '3'
                    vrdst:
                        type: raw
                        description: (list) Monitor the route to this destination.
                    vrdst_priority:
                        type: int
                        description: Priority of the virtual router when the virtual router destination becomes unreachable
                    vrgrp:
                        type: int
                        description: VRRP group ID
                    vrid:
                        type: int
                        description: Virtual router identifier
                    vrip:
                        type: str
                        description: IP address of the virtual router.
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
    - name: Fsp vlan dynamic mapping interface
      fortinet.fortimanager.fmgr_fsp_vlan_dynamicmapping_interface:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        vlan: <your own value>
        dynamic_mapping: <your own value>
        fsp_vlan_dynamicmapping_interface:
          ip: <string>
          vlanid: <integer>
          dhcp_relay_agent_option: <value in [disable, enable]>
          dhcp_relay_ip: <list or string>
          dhcp_relay_service: <value in [disable, enable]>
          dhcp_relay_type: <value in [regular, ipsec]>
          ipv6:
            autoconf: <value in [disable, enable]>
            dhcp6_client_options:
              - "rapid"
              - "iapd"
              - "iana"
              - "dns"
              - "dnsname"
            dhcp6_information_request: <value in [disable, enable]>
            dhcp6_prefix_delegation: <value in [disable, enable]>
            dhcp6_prefix_hint: <string>
            dhcp6_prefix_hint_plt: <integer>
            dhcp6_prefix_hint_vlt: <integer>
            dhcp6_relay_ip: <string>
            dhcp6_relay_service: <value in [disable, enable]>
            dhcp6_relay_type: <value in [regular]>
            ip6_address: <string>
            ip6_allowaccess:
              - "https"
              - "ping"
              - "ssh"
              - "snmp"
              - "http"
              - "telnet"
              - "fgfm"
              - "capwap"
              - "fabric"
            ip6_default_life: <integer>
            ip6_delegated_prefix_list:
              -
                autonomous_flag: <value in [disable, enable]>
                onlink_flag: <value in [disable, enable]>
                prefix_id: <integer>
                rdnss: <list or string>
                rdnss_service: <value in [delegated, default, specify]>
                subnet: <string>
                upstream_interface: <string>
                delegated_prefix_iaid: <integer>
            ip6_dns_server_override: <value in [disable, enable]>
            ip6_extra_addr:
              -
                prefix: <string>
            ip6_hop_limit: <integer>
            ip6_link_mtu: <integer>
            ip6_manage_flag: <value in [disable, enable]>
            ip6_max_interval: <integer>
            ip6_min_interval: <integer>
            ip6_mode: <value in [static, dhcp, pppoe, ...]>
            ip6_other_flag: <value in [disable, enable]>
            ip6_prefix_list:
              -
                autonomous_flag: <value in [disable, enable]>
                dnssl: <list or string>
                onlink_flag: <value in [disable, enable]>
                preferred_life_time: <integer>
                prefix: <string>
                rdnss: <list or string>
                valid_life_time: <integer>
            ip6_reachable_time: <integer>
            ip6_retrans_time: <integer>
            ip6_send_adv: <value in [disable, enable]>
            ip6_subnet: <string>
            ip6_upstream_interface: <string>
            nd_cert: <string>
            nd_cga_modifier: <string>
            nd_mode: <value in [basic, SEND-compatible]>
            nd_security_level: <integer>
            nd_timestamp_delta: <integer>
            nd_timestamp_fuzz: <integer>
            vrip6_link_local: <string>
            vrrp_virtual_mac6: <value in [disable, enable]>
            vrrp6:
              -
                accept_mode: <value in [disable, enable]>
                adv_interval: <integer>
                preempt: <value in [disable, enable]>
                priority: <integer>
                start_time: <integer>
                status: <value in [disable, enable]>
                vrdst6: <string>
                vrgrp: <integer>
                vrid: <integer>
                vrip6: <string>
            interface_identifier: <string>
            unique_autoconf_addr: <value in [disable, enable]>
            icmp6_send_redirect: <value in [disable, enable]>
            cli_conn6_status: <integer>
            ip6_prefix_mode: <value in [dhcp6, ra]>
            ra_send_mtu: <value in [disable, enable]>
            ip6_delegated_prefix_iaid: <integer>
            dhcp6_relay_source_interface: <value in [disable, enable]>
          secondary_IP: <value in [disable, enable]>
          secondaryip:
            -
              allowaccess:
                - "https"
                - "ping"
                - "ssh"
                - "snmp"
                - "http"
                - "telnet"
                - "fgfm"
                - "auto-ipsec"
                - "radius-acct"
                - "probe-response"
                - "capwap"
                - "dnp"
                - "ftm"
                - "fabric"
                - "speed-test"
              detectprotocol:
                - "ping"
                - "tcp-echo"
                - "udp-echo"
              detectserver: <string>
              gwdetect: <value in [disable, enable]>
              ha_priority: <integer>
              id: <integer>
              ip: <string>
              ping_serv_status: <integer>
              seq: <integer>
              secip_relay_ip: <string>
          dhcp_relay_interface_select_method: <value in [auto, sdwan, specify]>
          vrrp:
            -
              accept_mode: <value in [disable, enable]>
              adv_interval: <integer>
              ignore_default_route: <value in [disable, enable]>
              preempt: <value in [disable, enable]>
              priority: <integer>
              proxy_arp:
                -
                  id: <integer>
                  ip: <string>
              start_time: <integer>
              status: <value in [disable, enable]>
              version: <value in [2, 3]>
              vrdst: <list or string>
              vrdst_priority: <integer>
              vrgrp: <integer>
              vrid: <integer>
              vrip: <string>
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
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface'
    ]
    url_params = ['adom', 'vlan', 'dynamic_mapping']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vlan': {'required': True, 'type': 'str'},
        'dynamic_mapping': {'required': True, 'type': 'str'},
        'fsp_vlan_dynamicmapping_interface': {
            'type': 'dict',
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']],
            'options': {
                'ip': {'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'vlanid': {'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'dhcp-relay-agent-option': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-relay-ip': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'raw'},
                'dhcp-relay-service': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-relay-type': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['regular', 'ipsec'], 'type': 'str'},
                'ipv6': {
                    'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
                    'type': 'dict',
                    'options': {
                        'autoconf': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp6-client-options': {
                            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
                            'type': 'list',
                            'choices': ['rapid', 'iapd', 'iana', 'dns', 'dnsname'],
                            'elements': 'str'
                        },
                        'dhcp6-information-request': {
                            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'dhcp6-prefix-delegation': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp6-prefix-hint': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                        'dhcp6-prefix-hint-plt': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'dhcp6-prefix-hint-vlt': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'dhcp6-relay-ip': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                        'dhcp6-relay-service': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp6-relay-type': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['regular'], 'type': 'str'},
                        'ip6-address': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                        'ip6-allowaccess': {
                            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
                            'type': 'list',
                            'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'capwap', 'fabric'],
                            'elements': 'str'
                        },
                        'ip6-default-life': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'ip6-delegated-prefix-list': {
                            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
                            'type': 'list',
                            'options': {
                                'autonomous-flag': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'onlink-flag': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'prefix-id': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                                'rdnss': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'raw'},
                                'rdnss-service': {
                                    'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
                                    'choices': ['delegated', 'default', 'specify'],
                                    'type': 'str'
                                },
                                'subnet': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                                'upstream-interface': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                                'delegated-prefix-iaid': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'ip6-dns-server-override': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ip6-extra-addr': {
                            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
                            'type': 'list',
                            'options': {'prefix': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'}},
                            'elements': 'dict'
                        },
                        'ip6-hop-limit': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'ip6-link-mtu': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'ip6-manage-flag': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ip6-max-interval': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'ip6-min-interval': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'ip6-mode': {
                            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
                            'choices': ['static', 'dhcp', 'pppoe', 'delegated'],
                            'type': 'str'
                        },
                        'ip6-other-flag': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ip6-prefix-list': {
                            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
                            'type': 'list',
                            'options': {
                                'autonomous-flag': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'dnssl': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'raw'},
                                'onlink-flag': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'preferred-life-time': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                                'prefix': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                                'rdnss': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'raw'},
                                'valid-life-time': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'ip6-reachable-time': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'ip6-retrans-time': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'ip6-send-adv': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ip6-subnet': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                        'ip6-upstream-interface': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                        'nd-cert': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                        'nd-cga-modifier': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                        'nd-mode': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['basic', 'SEND-compatible'], 'type': 'str'},
                        'nd-security-level': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'nd-timestamp-delta': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'nd-timestamp-fuzz': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'vrip6_link_local': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                        'vrrp-virtual-mac6': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vrrp6': {
                            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
                            'type': 'list',
                            'options': {
                                'accept-mode': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'adv-interval': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                                'preempt': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'priority': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                                'start-time': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                                'status': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'vrdst6': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                                'vrgrp': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                                'vrid': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                                'vrip6': {'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'interface-identifier': {'v_range': [['6.4.1', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                        'unique-autoconf-addr': {'v_range': [['6.4.1', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'icmp6-send-redirect': {'v_range': [['6.4.4', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cli-conn6-status': {'v_range': [['7.0.0', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'ip6-prefix-mode': {'v_range': [['7.0.0', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['dhcp6', 'ra'], 'type': 'str'},
                        'ra-send-mtu': {'v_range': [['6.4.6', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ip6-delegated-prefix-iaid': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'dhcp6-relay-source-interface': {
                            'v_range': [['7.2.2', '7.2.5'], ['7.4.0', '7.4.0']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        }
                    }
                },
                'secondary-IP': {'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'secondaryip': {
                    'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']],
                    'type': 'list',
                    'options': {
                        'allowaccess': {
                            'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']],
                            'type': 'list',
                            'choices': [
                                'https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'auto-ipsec', 'radius-acct', 'probe-response', 'capwap', 'dnp',
                                'ftm', 'fabric', 'speed-test'
                            ],
                            'elements': 'str'
                        },
                        'detectprotocol': {
                            'v_range': [['6.2.3', '7.2.0']],
                            'type': 'list',
                            'choices': ['ping', 'tcp-echo', 'udp-echo'],
                            'elements': 'str'
                        },
                        'detectserver': {'v_range': [['6.2.3', '7.2.0']], 'type': 'str'},
                        'gwdetect': {'v_range': [['6.2.3', '7.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ha-priority': {'v_range': [['6.2.3', '7.2.0']], 'type': 'int'},
                        'id': {'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'ip': {'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                        'ping-serv-status': {'v_range': [['6.2.3', '7.2.0']], 'type': 'int'},
                        'seq': {'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                        'secip-relay-ip': {'v_range': [['7.4.0', '7.4.0']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'dhcp-relay-interface-select-method': {
                    'v_range': [['6.4.8', '6.4.15'], ['7.0.4', '7.2.5'], ['7.4.0', '7.4.0']],
                    'choices': ['auto', 'sdwan', 'specify'],
                    'type': 'str'
                },
                'vrrp': {
                    'v_range': [['7.4.0', '7.4.0']],
                    'type': 'list',
                    'options': {
                        'accept-mode': {'v_range': [['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'adv-interval': {'v_range': [['7.4.0', '7.4.0']], 'type': 'int'},
                        'ignore-default-route': {'v_range': [['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'preempt': {'v_range': [['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'priority': {'v_range': [['7.4.0', '7.4.0']], 'type': 'int'},
                        'proxy-arp': {
                            'v_range': [['7.4.0', '7.4.0']],
                            'type': 'list',
                            'options': {'id': {'v_range': [['7.4.0', '7.4.0']], 'type': 'int'}, 'ip': {'v_range': [['7.4.0', '7.4.0']], 'type': 'str'}},
                            'elements': 'dict'
                        },
                        'start-time': {'v_range': [['7.4.0', '7.4.0']], 'type': 'int'},
                        'status': {'v_range': [['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'version': {'v_range': [['7.4.0', '7.4.0']], 'choices': ['2', '3'], 'type': 'str'},
                        'vrdst': {'v_range': [['7.4.0', '7.4.0']], 'type': 'raw'},
                        'vrdst-priority': {'v_range': [['7.4.0', '7.4.0']], 'type': 'int'},
                        'vrgrp': {'v_range': [['7.4.0', '7.4.0']], 'type': 'int'},
                        'vrid': {'v_range': [['7.4.0', '7.4.0']], 'type': 'int'},
                        'vrip': {'v_range': [['7.4.0', '7.4.0']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_dynamicmapping_interface'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
