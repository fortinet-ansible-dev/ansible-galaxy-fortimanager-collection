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
module: fmgr_firewall_profileprotocoloptions_http
short_description: Configure HTTP protocol options.
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
    profile-protocol-options:
        description: Deprecated, please use "profile_protocol_options"
        type: str
    profile_protocol_options:
        description: The parameter (profile-protocol-options) in requested url.
        type: str
    firewall_profileprotocoloptions_http:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            block-page-status-code:
                type: int
                description: Deprecated, please rename it to block_page_status_code. Code number returned for blocked HTTP pages
            comfort-amount:
                type: int
                description: Deprecated, please rename it to comfort_amount. Amount of data to send in a transmission for client comforting
            comfort-interval:
                type: int
                description: Deprecated, please rename it to comfort_interval. Period of time between start, or last transmission, and the next client ...
            fortinet-bar:
                type: str
                description: Deprecated, please rename it to fortinet_bar. Enable/disable Fortinet bar on HTML content.
                choices:
                    - 'disable'
                    - 'enable'
            fortinet-bar-port:
                type: int
                description: Deprecated, please rename it to fortinet_bar_port. Port for use by Fortinet Bar
            http-policy:
                type: str
                description: Deprecated, please rename it to http_policy. Enable/disable HTTP policy check.
                choices:
                    - 'disable'
                    - 'enable'
            inspect-all:
                type: str
                description: Deprecated, please rename it to inspect_all. Enable/disable the inspection of all ports for the protocol.
                choices:
                    - 'disable'
                    - 'enable'
            options:
                type: list
                elements: str
                description: No description.
                choices:
                    - 'oversize'
                    - 'chunkedbypass'
                    - 'clientcomfort'
                    - 'no-content-summary'
                    - 'servercomfort'
            oversize-limit:
                type: int
                description: Deprecated, please rename it to oversize_limit. Maximum in-memory file size that can be scanned
            ports:
                type: raw
                description: (list) No description.
            post-lang:
                type: list
                elements: str
                description: Deprecated, please rename it to post_lang.
                choices:
                    - 'jisx0201'
                    - 'jisx0208'
                    - 'jisx0212'
                    - 'gb2312'
                    - 'ksc5601-ex'
                    - 'euc-jp'
                    - 'sjis'
                    - 'iso2022-jp'
                    - 'iso2022-jp-1'
                    - 'iso2022-jp-2'
                    - 'euc-cn'
                    - 'ces-gbk'
                    - 'hz'
                    - 'ces-big5'
                    - 'euc-kr'
                    - 'iso2022-jp-3'
                    - 'iso8859-1'
                    - 'tis620'
                    - 'cp874'
                    - 'cp1252'
                    - 'cp1251'
            range-block:
                type: str
                description: Deprecated, please rename it to range_block. Enable/disable blocking of partial downloads.
                choices:
                    - 'disable'
                    - 'enable'
            retry-count:
                type: int
                description: Deprecated, please rename it to retry_count. Number of attempts to retry HTTP connection
            scan-bzip2:
                type: str
                description: Deprecated, please rename it to scan_bzip2. Enable/disable scanning of BZip2 compressed files.
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description: Enable/disable the active status of scanning for this protocol.
                choices:
                    - 'disable'
                    - 'enable'
            streaming-content-bypass:
                type: str
                description: Deprecated, please rename it to streaming_content_bypass. Enable/disable bypassing of streaming content from buffering.
                choices:
                    - 'disable'
                    - 'enable'
            strip-x-forwarded-for:
                type: str
                description: Deprecated, please rename it to strip_x_forwarded_for. Enable/disable stripping of HTTP X-Forwarded-For header.
                choices:
                    - 'disable'
                    - 'enable'
            switching-protocols:
                type: str
                description: Deprecated, please rename it to switching_protocols. Bypass from scanning, or block a connection that attempts to switch p...
                choices:
                    - 'bypass'
                    - 'block'
            uncompressed-nest-limit:
                type: int
                description: Deprecated, please rename it to uncompressed_nest_limit. Maximum nested levels of compression that can be uncompressed and...
            uncompressed-oversize-limit:
                type: int
                description: Deprecated, please rename it to uncompressed_oversize_limit. Maximum in-memory uncompressed file size that can be scanned
            tcp-window-maximum:
                type: int
                description: Deprecated, please rename it to tcp_window_maximum. Maximum dynamic TCP window size
            tcp-window-minimum:
                type: int
                description: Deprecated, please rename it to tcp_window_minimum. Minimum dynamic TCP window size
            tcp-window-size:
                type: int
                description: Deprecated, please rename it to tcp_window_size. Set TCP static window size
            tcp-window-type:
                type: str
                description: Deprecated, please rename it to tcp_window_type. Specify type of TCP window to use for this protocol.
                choices:
                    - 'system'
                    - 'static'
                    - 'dynamic'
                    - 'auto-tuning'
            ssl-offloaded:
                type: str
                description: Deprecated, please rename it to ssl_offloaded. SSL decryption and encryption performed by an external device.
                choices:
                    - 'no'
                    - 'yes'
            stream-based-uncompressed-limit:
                type: int
                description: Deprecated, please rename it to stream_based_uncompressed_limit. Maximum stream-based uncompressed data size that will be ...
            proxy-after-tcp-handshake:
                type: str
                description: Deprecated, please rename it to proxy_after_tcp_handshake. Proxy traffic after the TCP 3-way handshake has been established
                choices:
                    - 'disable'
                    - 'enable'
            tunnel-non-http:
                type: str
                description: Deprecated, please rename it to tunnel_non_http. Configure how to process non-HTTP traffic when a profile configured for H...
                choices:
                    - 'disable'
                    - 'enable'
            unknown-http-version:
                type: str
                description: Deprecated, please rename it to unknown_http_version. How to handle HTTP sessions that do not comply with HTTP 0.
                choices:
                    - 'best-effort'
                    - 'reject'
                    - 'tunnel'
            address-ip-rating:
                type: str
                description: Deprecated, please rename it to address_ip_rating. Enable/disable IP based URL rating.
                choices:
                    - 'disable'
                    - 'enable'
            h2c:
                type: str
                description: Enable/disable h2c HTTP connection upgrade.
                choices:
                    - 'disable'
                    - 'enable'
            verify-dns-for-policy-matching:
                type: str
                description: Deprecated, please rename it to verify_dns_for_policy_matching. Enable/disable verification of DNS for policy matching.
                choices:
                    - 'disable'
                    - 'enable'
            unknown-content-encoding:
                type: str
                description: Deprecated, please rename it to unknown_content_encoding. Configure the action the FortiGate unit will take on unknown con...
                choices:
                    - 'block'
                    - 'inspect'
                    - 'bypass'
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
    - name: Configure HTTP protocol options.
      fortinet.fortimanager.fmgr_firewall_profileprotocoloptions_http:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        profile_protocol_options: <your own value>
        firewall_profileprotocoloptions_http:
          block_page_status_code: <integer>
          comfort_amount: <integer>
          comfort_interval: <integer>
          fortinet_bar: <value in [disable, enable]>
          fortinet_bar_port: <integer>
          http_policy: <value in [disable, enable]>
          inspect_all: <value in [disable, enable]>
          options:
            - oversize
            - chunkedbypass
            - clientcomfort
            - no-content-summary
            - servercomfort
          oversize_limit: <integer>
          ports: <list or integer>
          post_lang:
            - jisx0201
            - jisx0208
            - jisx0212
            - gb2312
            - ksc5601-ex
            - euc-jp
            - sjis
            - iso2022-jp
            - iso2022-jp-1
            - iso2022-jp-2
            - euc-cn
            - ces-gbk
            - hz
            - ces-big5
            - euc-kr
            - iso2022-jp-3
            - iso8859-1
            - tis620
            - cp874
            - cp1252
            - cp1251
          range_block: <value in [disable, enable]>
          retry_count: <integer>
          scan_bzip2: <value in [disable, enable]>
          status: <value in [disable, enable]>
          streaming_content_bypass: <value in [disable, enable]>
          strip_x_forwarded_for: <value in [disable, enable]>
          switching_protocols: <value in [bypass, block]>
          uncompressed_nest_limit: <integer>
          uncompressed_oversize_limit: <integer>
          tcp_window_maximum: <integer>
          tcp_window_minimum: <integer>
          tcp_window_size: <integer>
          tcp_window_type: <value in [system, static, dynamic, ...]>
          ssl_offloaded: <value in [no, yes]>
          stream_based_uncompressed_limit: <integer>
          proxy_after_tcp_handshake: <value in [disable, enable]>
          tunnel_non_http: <value in [disable, enable]>
          unknown_http_version: <value in [best-effort, reject, tunnel]>
          address_ip_rating: <value in [disable, enable]>
          h2c: <value in [disable, enable]>
          verify_dns_for_policy_matching: <value in [disable, enable]>
          unknown_content_encoding: <value in [block, inspect, bypass]>
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
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/http',
        '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/http'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/http/{http}',
        '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/http/{http}'
    ]

    url_params = ['adom', 'profile-protocol-options']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile-protocol-options': {'type': 'str', 'api_name': 'profile_protocol_options'},
        'profile_protocol_options': {'type': 'str'},
        'firewall_profileprotocoloptions_http': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'block-page-status-code': {'type': 'int'},
                'comfort-amount': {'type': 'int'},
                'comfort-interval': {'type': 'int'},
                'fortinet-bar': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fortinet-bar-port': {'type': 'int'},
                'http-policy': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'inspect-all': {'choices': ['disable', 'enable'], 'type': 'str'},
                'options': {
                    'type': 'list',
                    'choices': ['oversize', 'chunkedbypass', 'clientcomfort', 'no-content-summary', 'servercomfort'],
                    'elements': 'str'
                },
                'oversize-limit': {'type': 'int'},
                'ports': {'type': 'raw'},
                'post-lang': {
                    'type': 'list',
                    'choices': [
                        'jisx0201', 'jisx0208', 'jisx0212', 'gb2312', 'ksc5601-ex', 'euc-jp', 'sjis', 'iso2022-jp', 'iso2022-jp-1', 'iso2022-jp-2',
                        'euc-cn', 'ces-gbk', 'hz', 'ces-big5', 'euc-kr', 'iso2022-jp-3', 'iso8859-1', 'tis620', 'cp874', 'cp1252', 'cp1251'
                    ],
                    'elements': 'str'
                },
                'range-block': {'choices': ['disable', 'enable'], 'type': 'str'},
                'retry-count': {'type': 'int'},
                'scan-bzip2': {'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'streaming-content-bypass': {'choices': ['disable', 'enable'], 'type': 'str'},
                'strip-x-forwarded-for': {'choices': ['disable', 'enable'], 'type': 'str'},
                'switching-protocols': {'choices': ['bypass', 'block'], 'type': 'str'},
                'uncompressed-nest-limit': {'type': 'int'},
                'uncompressed-oversize-limit': {'type': 'int'},
                'tcp-window-maximum': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'tcp-window-minimum': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'tcp-window-size': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'tcp-window-type': {'v_range': [['6.2.0', '']], 'choices': ['system', 'static', 'dynamic', 'auto-tuning'], 'type': 'str'},
                'ssl-offloaded': {'v_range': [['6.2.2', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'stream-based-uncompressed-limit': {'v_range': [['6.2.2', '']], 'type': 'int'},
                'proxy-after-tcp-handshake': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-non-http': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unknown-http-version': {'v_range': [['6.4.0', '']], 'choices': ['best-effort', 'reject', 'tunnel'], 'type': 'str'},
                'address-ip-rating': {'v_range': [['7.0.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h2c': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'verify-dns-for-policy-matching': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unknown-content-encoding': {'v_range': [['7.2.2', '']], 'choices': ['block', 'inspect', 'bypass'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profileprotocoloptions_http'),
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
