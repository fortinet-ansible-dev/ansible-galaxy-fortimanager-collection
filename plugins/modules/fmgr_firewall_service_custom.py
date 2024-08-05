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
module: fmgr_firewall_service_custom
short_description: Configure custom services.
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
    firewall_service_custom:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            app-category:
                type: raw
                description: (list) Deprecated, please rename it to app_category. Application category ID.
            app-service-type:
                type: str
                description: Deprecated, please rename it to app_service_type. Application service type.
                choices:
                    - 'disable'
                    - 'app-id'
                    - 'app-category'
            application:
                type: raw
                description: (list) Application ID.
            category:
                type: str
                description: Service category.
            check-reset-range:
                type: str
                description: Deprecated, please rename it to check_reset_range. Configure the type of ICMP error message verification.
                choices:
                    - 'disable'
                    - 'default'
                    - 'strict'
            color:
                type: int
                description: Color of icon on the GUI.
            comment:
                type: raw
                description: (dict or str) Comment.
            fqdn:
                type: str
                description: Fully qualified domain name.
            helper:
                type: str
                description: Helper name.
                choices:
                    - 'disable'
                    - 'auto'
                    - 'ftp'
                    - 'tftp'
                    - 'ras'
                    - 'h323'
                    - 'tns'
                    - 'mms'
                    - 'sip'
                    - 'pptp'
                    - 'rtsp'
                    - 'dns-udp'
                    - 'dns-tcp'
                    - 'pmap'
                    - 'rsh'
                    - 'dcerpc'
                    - 'mgcp'
                    - 'gtp-c'
                    - 'gtp-u'
                    - 'gtp-b'
                    - 'pfcp'
            icmpcode:
                type: int
                description: ICMP code.
            icmptype:
                type: int
                description: ICMP type.
            iprange:
                type: str
                description: Start and end of the IP range associated with service.
            name:
                type: str
                description: Custom service name.
                required: true
            protocol:
                type: str
                description: Protocol type based on IANA numbers.
                choices:
                    - 'ICMP'
                    - 'IP'
                    - 'TCP/UDP/SCTP'
                    - 'ICMP6'
                    - 'HTTP'
                    - 'FTP'
                    - 'CONNECT'
                    - 'SOCKS'
                    - 'ALL'
                    - 'SOCKS-TCP'
                    - 'SOCKS-UDP'
            protocol-number:
                type: int
                description: Deprecated, please rename it to protocol_number. IP protocol number.
            proxy:
                type: str
                description: Enable/disable web proxy service.
                choices:
                    - 'disable'
                    - 'enable'
            sctp-portrange:
                type: str
                description: Deprecated, please rename it to sctp_portrange. Multiple SCTP port ranges.
            session-ttl:
                type: raw
                description: (int or str) Deprecated, please rename it to session_ttl. Session TTL
            tcp-halfclose-timer:
                type: int
                description: Deprecated, please rename it to tcp_halfclose_timer. Wait time to close a TCP session waiting for an unanswered FIN packet
            tcp-halfopen-timer:
                type: int
                description: Deprecated, please rename it to tcp_halfopen_timer. Wait time to close a TCP session waiting for an unanswered open sessio...
            tcp-portrange:
                type: str
                description: Deprecated, please rename it to tcp_portrange. Multiple TCP port ranges.
            tcp-timewait-timer:
                type: int
                description: Deprecated, please rename it to tcp_timewait_timer. Set the length of the TCP TIME-WAIT state in seconds
            udp-idle-timer:
                type: int
                description: Deprecated, please rename it to udp_idle_timer. UDP half close timeout
            udp-portrange:
                type: str
                description: Deprecated, please rename it to udp_portrange. Multiple UDP port ranges.
            visibility:
                type: str
                description: Enable/disable the visibility of the service on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            explicit-proxy:
                type: str
                description: Deprecated, please rename it to explicit_proxy. Enable/disable explicit web proxy service.
                choices:
                    - 'disable'
                    - 'enable'
            global-object:
                type: int
                description: Deprecated, please rename it to global_object. Global Object.
            fabric-object:
                type: str
                description: Deprecated, please rename it to fabric_object. Security Fabric global object setting.
                choices:
                    - 'disable'
                    - 'enable'
            tcp-rst-timer:
                type: int
                description: Deprecated, please rename it to tcp_rst_timer. Set the length of the TCP CLOSE state in seconds
            uuid:
                type: str
                description: Universally Unique Identifier
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
    - name: Configure custom services.
      fortinet.fortimanager.fmgr_firewall_service_custom:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_service_custom:
          app-service-type: disable # <value in [disable, app-id, app-category]>
          color: 1
          comment: "comment"
          helper: auto # <value in [disable, auto, ftp, ...]>
          name: "ansible-test"
          protocol: ALL # <value in [ICMP, IP, TCP/UDP/SCTP, ...]>
          proxy: enable # <value in [disable, enable]>
          visibility: enable # <value in [disable, enable]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the custom services
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_service_custom"
          params:
            adom: "ansible"
            custom: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/service/custom',
        '/pm/config/global/obj/firewall/service/custom'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/service/custom/{custom}',
        '/pm/config/global/obj/firewall/service/custom/{custom}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'firewall_service_custom': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'app-category': {'type': 'raw'},
                'app-service-type': {'choices': ['disable', 'app-id', 'app-category'], 'type': 'str'},
                'application': {'type': 'raw'},
                'category': {'type': 'str'},
                'check-reset-range': {'choices': ['disable', 'default', 'strict'], 'type': 'str'},
                'color': {'type': 'int'},
                'comment': {'type': 'raw'},
                'fqdn': {'type': 'str'},
                'helper': {
                    'choices': [
                        'disable', 'auto', 'ftp', 'tftp', 'ras', 'h323', 'tns', 'mms', 'sip', 'pptp', 'rtsp', 'dns-udp', 'dns-tcp', 'pmap', 'rsh',
                        'dcerpc', 'mgcp', 'gtp-c', 'gtp-u', 'gtp-b', 'pfcp'
                    ],
                    'type': 'str'
                },
                'icmpcode': {'type': 'int'},
                'icmptype': {'type': 'int'},
                'iprange': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'protocol': {
                    'choices': ['ICMP', 'IP', 'TCP/UDP/SCTP', 'ICMP6', 'HTTP', 'FTP', 'CONNECT', 'SOCKS', 'ALL', 'SOCKS-TCP', 'SOCKS-UDP'],
                    'type': 'str'
                },
                'protocol-number': {'type': 'int'},
                'proxy': {'choices': ['disable', 'enable'], 'type': 'str'},
                'sctp-portrange': {'type': 'str'},
                'session-ttl': {'type': 'raw'},
                'tcp-halfclose-timer': {'type': 'int'},
                'tcp-halfopen-timer': {'type': 'int'},
                'tcp-portrange': {'type': 'str'},
                'tcp-timewait-timer': {'type': 'int'},
                'udp-idle-timer': {'type': 'int'},
                'udp-portrange': {'type': 'str'},
                'visibility': {'choices': ['disable', 'enable'], 'type': 'str'},
                'explicit-proxy': {'v_range': [['6.2.0', '6.2.12']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'global-object': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'fabric-object': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-rst-timer': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'uuid': {'v_range': [['7.4.2', '']], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_service_custom'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
