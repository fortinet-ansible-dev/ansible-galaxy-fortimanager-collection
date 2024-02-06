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
module: fmgr_system_npu_fpanomaly
short_description: NP6Lite anomaly protection
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
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
    system_npu_fpanomaly:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            esp-minlen-err:
                type: str
                description: Deprecated, please rename it to esp_minlen_err. Invalid IPv4 ESP short packet anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            icmp-csum-err:
                type: str
                description: Deprecated, please rename it to icmp_csum_err. Invalid IPv4 ICMP packet checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            icmp-minlen-err:
                type: str
                description: Deprecated, please rename it to icmp_minlen_err. Invalid IPv4 ICMP short packet anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4-csum-err:
                type: str
                description: Deprecated, please rename it to ipv4_csum_err. Invalid IPv4 packet checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4-ihl-err:
                type: str
                description: Deprecated, please rename it to ipv4_ihl_err. Invalid IPv4 header length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4-len-err:
                type: str
                description: Deprecated, please rename it to ipv4_len_err. Invalid IPv4 packet length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4-opt-err:
                type: str
                description: Deprecated, please rename it to ipv4_opt_err. Invalid IPv4 option parsing anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4-ttlzero-err:
                type: str
                description: Deprecated, please rename it to ipv4_ttlzero_err. Invalid IPv4 TTL field zero anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4-ver-err:
                type: str
                description: Deprecated, please rename it to ipv4_ver_err. Invalid IPv4 header version anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv6-exthdr-len-err:
                type: str
                description: Deprecated, please rename it to ipv6_exthdr_len_err. Invalid IPv6 packet chain extension header total length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv6-exthdr-order-err:
                type: str
                description: Deprecated, please rename it to ipv6_exthdr_order_err. Invalid IPv6 packet extension header ordering anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv6-ihl-err:
                type: str
                description: Deprecated, please rename it to ipv6_ihl_err. Invalid IPv6 packet length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv6-plen-zero:
                type: str
                description: Deprecated, please rename it to ipv6_plen_zero. Invalid IPv6 packet payload length zero anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv6-ver-err:
                type: str
                description: Deprecated, please rename it to ipv6_ver_err. Invalid IPv6 packet version anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            tcp-csum-err:
                type: str
                description: Deprecated, please rename it to tcp_csum_err. Invalid IPv4 TCP packet checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            tcp-hlen-err:
                type: str
                description: Deprecated, please rename it to tcp_hlen_err. Invalid IPv4 TCP header length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            tcp-plen-err:
                type: str
                description: Deprecated, please rename it to tcp_plen_err. Invalid IPv4 TCP packet length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udp-csum-err:
                type: str
                description: Deprecated, please rename it to udp_csum_err. Invalid IPv4 UDP packet checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udp-hlen-err:
                type: str
                description: Deprecated, please rename it to udp_hlen_err. Invalid IPv4 UDP packet header length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udp-len-err:
                type: str
                description: Deprecated, please rename it to udp_len_err. Invalid IPv4 UDP packet length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udp-plen-err:
                type: str
                description: Deprecated, please rename it to udp_plen_err. Invalid IPv4 UDP packet minimum length anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udplite-cover-err:
                type: str
                description: Deprecated, please rename it to udplite_cover_err. Invalid IPv4 UDP-Lite packet coverage anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udplite-csum-err:
                type: str
                description: Deprecated, please rename it to udplite_csum_err. Invalid IPv4 UDP-Lite packet checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            unknproto-minlen-err:
                type: str
                description: Deprecated, please rename it to unknproto_minlen_err. Invalid IPv4 L4 unknown protocol short packet anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            tcp-fin-only:
                type: str
                description: Deprecated, please rename it to tcp_fin_only. TCP SYN flood with only FIN flag set anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4-optsecurity:
                type: str
                description: Deprecated, please rename it to ipv4_optsecurity. Security option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-optralert:
                type: str
                description: Deprecated, please rename it to ipv6_optralert. Router alert option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp-syn-fin:
                type: str
                description: Deprecated, please rename it to tcp_syn_fin. TCP SYN flood SYN/FIN flag set anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4-proto-err:
                type: str
                description: Deprecated, please rename it to ipv4_proto_err. Invalid layer 4 protocol anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-saddr-err:
                type: str
                description: Deprecated, please rename it to ipv6_saddr_err. Source address as multicast anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            icmp-frag:
                type: str
                description: Deprecated, please rename it to icmp_frag. Layer 3 fragmented packets that could be part of layer 4 ICMP anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4-optssrr:
                type: str
                description: Deprecated, please rename it to ipv4_optssrr. Strict source record route option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-opthomeaddr:
                type: str
                description: Deprecated, please rename it to ipv6_opthomeaddr. Home address option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            udp-land:
                type: str
                description: Deprecated, please rename it to udp_land. UDP land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-optinvld:
                type: str
                description: Deprecated, please rename it to ipv6_optinvld. Invalid option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp-fin-noack:
                type: str
                description: Deprecated, please rename it to tcp_fin_noack. TCP SYN flood with FIN flag set without ACK setting anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-proto-err:
                type: str
                description: Deprecated, please rename it to ipv6_proto_err. Layer 4 invalid protocol anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp-land:
                type: str
                description: Deprecated, please rename it to tcp_land. TCP land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4-unknopt:
                type: str
                description: Deprecated, please rename it to ipv4_unknopt. Unknown option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4-optstream:
                type: str
                description: Deprecated, please rename it to ipv4_optstream. Stream option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-optjumbo:
                type: str
                description: Deprecated, please rename it to ipv6_optjumbo. Jumbo options anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            icmp-land:
                type: str
                description: Deprecated, please rename it to icmp_land. ICMP land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp-winnuke:
                type: str
                description: Deprecated, please rename it to tcp_winnuke. TCP WinNuke anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-daddr-err:
                type: str
                description: Deprecated, please rename it to ipv6_daddr_err. Destination address as unspecified or loopback address anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4-land:
                type: str
                description: Deprecated, please rename it to ipv4_land. Land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-opttunnel:
                type: str
                description: Deprecated, please rename it to ipv6_opttunnel. Tunnel encapsulation limit option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp-no-flag:
                type: str
                description: Deprecated, please rename it to tcp_no_flag. TCP SYN flood with no flag set anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-land:
                type: str
                description: Deprecated, please rename it to ipv6_land. Land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4-optlsrr:
                type: str
                description: Deprecated, please rename it to ipv4_optlsrr. Loose source record route option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4-opttimestamp:
                type: str
                description: Deprecated, please rename it to ipv4_opttimestamp. Timestamp option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4-optrr:
                type: str
                description: Deprecated, please rename it to ipv4_optrr. Record route option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-optnsap:
                type: str
                description: Deprecated, please rename it to ipv6_optnsap. Network service access point address option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-unknopt:
                type: str
                description: Deprecated, please rename it to ipv6_unknopt. Unknown option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp-syn-data:
                type: str
                description: Deprecated, please rename it to tcp_syn_data. TCP SYN flood packets with data anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6-optendpid:
                type: str
                description: Deprecated, please rename it to ipv6_optendpid. End point identification anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            gtpu-plen-err:
                type: str
                description: Deprecated, please rename it to gtpu_plen_err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            vxlan-minlen-err:
                type: str
                description: Deprecated, please rename it to vxlan_minlen_err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            capwap-minlen-err:
                type: str
                description: Deprecated, please rename it to capwap_minlen_err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            gre-csum-err:
                type: str
                description: Deprecated, please rename it to gre_csum_err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            nvgre-minlen-err:
                type: str
                description: Deprecated, please rename it to nvgre_minlen_err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            sctp-l4len-err:
                type: str
                description: Deprecated, please rename it to sctp_l4len_err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            tcp-hlenvsl4len-err:
                type: str
                description: Deprecated, please rename it to tcp_hlenvsl4len_err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            sctp-crc-err:
                type: str
                description: Deprecated, please rename it to sctp_crc_err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            sctp-clen-err:
                type: str
                description: Deprecated, please rename it to sctp_clen_err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            uesp-minlen-err:
                type: str
                description: Deprecated, please rename it to uesp_minlen_err.
                choices:
                    - 'drop'
                    - 'trap-to-host'
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
    - name: NP6Lite anomaly protection
      fortinet.fortimanager.fmgr_system_npu_fpanomaly:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        system_npu_fpanomaly:
          esp_minlen_err: <value in [drop, trap-to-host]>
          icmp_csum_err: <value in [drop, trap-to-host]>
          icmp_minlen_err: <value in [drop, trap-to-host]>
          ipv4_csum_err: <value in [drop, trap-to-host]>
          ipv4_ihl_err: <value in [drop, trap-to-host]>
          ipv4_len_err: <value in [drop, trap-to-host]>
          ipv4_opt_err: <value in [drop, trap-to-host]>
          ipv4_ttlzero_err: <value in [drop, trap-to-host]>
          ipv4_ver_err: <value in [drop, trap-to-host]>
          ipv6_exthdr_len_err: <value in [drop, trap-to-host]>
          ipv6_exthdr_order_err: <value in [drop, trap-to-host]>
          ipv6_ihl_err: <value in [drop, trap-to-host]>
          ipv6_plen_zero: <value in [drop, trap-to-host]>
          ipv6_ver_err: <value in [drop, trap-to-host]>
          tcp_csum_err: <value in [drop, trap-to-host]>
          tcp_hlen_err: <value in [drop, trap-to-host]>
          tcp_plen_err: <value in [drop, trap-to-host]>
          udp_csum_err: <value in [drop, trap-to-host]>
          udp_hlen_err: <value in [drop, trap-to-host]>
          udp_len_err: <value in [drop, trap-to-host]>
          udp_plen_err: <value in [drop, trap-to-host]>
          udplite_cover_err: <value in [drop, trap-to-host]>
          udplite_csum_err: <value in [drop, trap-to-host]>
          unknproto_minlen_err: <value in [drop, trap-to-host]>
          tcp_fin_only: <value in [allow, drop, trap-to-host]>
          ipv4_optsecurity: <value in [allow, drop, trap-to-host]>
          ipv6_optralert: <value in [allow, drop, trap-to-host]>
          tcp_syn_fin: <value in [allow, drop, trap-to-host]>
          ipv4_proto_err: <value in [allow, drop, trap-to-host]>
          ipv6_saddr_err: <value in [allow, drop, trap-to-host]>
          icmp_frag: <value in [allow, drop, trap-to-host]>
          ipv4_optssrr: <value in [allow, drop, trap-to-host]>
          ipv6_opthomeaddr: <value in [allow, drop, trap-to-host]>
          udp_land: <value in [allow, drop, trap-to-host]>
          ipv6_optinvld: <value in [allow, drop, trap-to-host]>
          tcp_fin_noack: <value in [allow, drop, trap-to-host]>
          ipv6_proto_err: <value in [allow, drop, trap-to-host]>
          tcp_land: <value in [allow, drop, trap-to-host]>
          ipv4_unknopt: <value in [allow, drop, trap-to-host]>
          ipv4_optstream: <value in [allow, drop, trap-to-host]>
          ipv6_optjumbo: <value in [allow, drop, trap-to-host]>
          icmp_land: <value in [allow, drop, trap-to-host]>
          tcp_winnuke: <value in [allow, drop, trap-to-host]>
          ipv6_daddr_err: <value in [allow, drop, trap-to-host]>
          ipv4_land: <value in [allow, drop, trap-to-host]>
          ipv6_opttunnel: <value in [allow, drop, trap-to-host]>
          tcp_no_flag: <value in [allow, drop, trap-to-host]>
          ipv6_land: <value in [allow, drop, trap-to-host]>
          ipv4_optlsrr: <value in [allow, drop, trap-to-host]>
          ipv4_opttimestamp: <value in [allow, drop, trap-to-host]>
          ipv4_optrr: <value in [allow, drop, trap-to-host]>
          ipv6_optnsap: <value in [allow, drop, trap-to-host]>
          ipv6_unknopt: <value in [allow, drop, trap-to-host]>
          tcp_syn_data: <value in [allow, drop, trap-to-host]>
          ipv6_optendpid: <value in [allow, drop, trap-to-host]>
          gtpu_plen_err: <value in [drop, trap-to-host]>
          vxlan_minlen_err: <value in [drop, trap-to-host]>
          capwap_minlen_err: <value in [drop, trap-to-host]>
          gre_csum_err: <value in [drop, trap-to-host]>
          nvgre_minlen_err: <value in [drop, trap-to-host]>
          sctp_l4len_err: <value in [drop, trap-to-host]>
          tcp_hlenvsl4len_err: <value in [drop, trap-to-host]>
          sctp_crc_err: <value in [drop, trap-to-host]>
          sctp_clen_err: <value in [drop, trap-to-host]>
          uesp_minlen_err: <value in [drop, trap-to-host]>
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
        '/pm/config/adom/{adom}/obj/system/npu/fp-anomaly',
        '/pm/config/global/obj/system/npu/fp-anomaly'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/system/npu/fp-anomaly/{fp-anomaly}',
        '/pm/config/global/obj/system/npu/fp-anomaly/{fp-anomaly}'
    ]

    url_params = ['adom']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'system_npu_fpanomaly': {
            'type': 'dict',
            'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']],
            'options': {
                'esp-minlen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'icmp-csum-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'icmp-minlen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-csum-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-ihl-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-len-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-opt-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-ttlzero-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-ver-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-exthdr-len-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-exthdr-order-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-ihl-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-plen-zero': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-ver-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-csum-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-hlen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-plen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udp-csum-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udp-hlen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udp-len-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udp-plen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udplite-cover-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udplite-csum-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'unknproto-minlen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-fin-only': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optsecurity': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optralert': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-syn-fin': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-proto-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-saddr-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'icmp-frag': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optssrr': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-opthomeaddr': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'udp-land': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optinvld': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-fin-noack': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-proto-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-land': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-unknopt': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optstream': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optjumbo': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'icmp-land': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-winnuke': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-daddr-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-land': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-opttunnel': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-no-flag': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-land': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optlsrr': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-opttimestamp': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optrr': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optnsap': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-unknopt': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-syn-data': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optendpid': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'gtpu-plen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'vxlan-minlen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'capwap-minlen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'gre-csum-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'nvgre-minlen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'sctp-l4len-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-hlenvsl4len-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'sctp-crc-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'sctp-clen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'uesp-minlen-err': {'v_range': [['6.4.7', '6.4.13'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_fpanomaly'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
