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
module: fmgr_webproxy_explicitproxy
short_description: Web proxy explicit proxy
description:
    - This module is able to configure a FortiManager device (FortiProxy).
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "2.12.0"
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
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
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
    webproxy_explicitproxy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            detect_https_in_http_request:
                aliases: ['detect-https-in-http-request']
                type: str
                description: Detect https in http request.
                choices:
                    - 'disable'
                    - 'enable'
            dns_mode:
                aliases: ['dns-mode']
                type: str
                description: Dns mode.
                choices:
                    - 'recursive'
                    - 'non-recursive'
                    - 'forward-only'
            dstport_from_incoming:
                aliases: ['dstport-from-incoming']
                type: str
                description: Dstport from incoming.
                choices:
                    - 'disable'
                    - 'enable'
            ftp_incoming_port:
                aliases: ['ftp-incoming-port']
                type: list
                elements: str
                description: Ftp incoming port.
            ftp_over_http:
                aliases: ['ftp-over-http']
                type: str
                description: Ftp over http.
                choices:
                    - 'disable'
                    - 'enable'
            header_proxy_agent:
                aliases: ['header-proxy-agent']
                type: str
                description: Header proxy agent.
                choices:
                    - 'disable'
                    - 'enable'
            http:
                type: str
                description: Http.
                choices:
                    - 'disable'
                    - 'enable'
            http_connection_mode:
                aliases: ['http-connection-mode']
                type: str
                description: Http connection mode.
                choices:
                    - 'static'
                    - 'multiplex'
                    - 'serverpool'
            http_incoming_port:
                aliases: ['http-incoming-port']
                type: list
                elements: str
                description: Http incoming port.
            https_incoming_port:
                aliases: ['https-incoming-port']
                type: list
                elements: str
                description: Https incoming port.
            incoming_ip6:
                aliases: ['incoming-ip6']
                type: str
                description: Incoming ip6.
            interface:
                type: list
                elements: str
                description: Interface.
            ipv6_status:
                aliases: ['ipv6-status']
                type: str
                description: Ipv6 status.
                choices:
                    - 'disable'
                    - 'enable'
            learn_dst_from_sni:
                aliases: ['learn-dst-from-sni']
                type: str
                description: Learn dst from sni.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Name.
                required: true
            pac_file_data:
                aliases: ['pac-file-data']
                type: str
                description: Pac file data.
            pac_file_name:
                aliases: ['pac-file-name']
                type: str
                description: Pac file name.
            pac_file_server_port:
                aliases: ['pac-file-server-port']
                type: str
                description: Pac file server port.
            pac_file_server_status:
                aliases: ['pac-file-server-status']
                type: str
                description: Pac file server status.
                choices:
                    - 'disable'
                    - 'enable'
            pac_file_through_https:
                aliases: ['pac-file-through-https']
                type: str
                description: Pac file through https.
                choices:
                    - 'disable'
                    - 'enable'
            pac_file_url:
                aliases: ['pac-file-url']
                type: str
                description: Pac file url.
            pref_dns_result:
                aliases: ['pref-dns-result']
                type: str
                description: Pref dns result.
                choices:
                    - 'ipv4'
                    - 'ipv6'
                    - 'ipv4-strict'
                    - 'ipv6-strict'
            realm:
                type: str
                description: Realm.
            return_to_sender:
                aliases: ['return-to-sender']
                type: str
                description: Return to sender.
                choices:
                    - 'disable'
                    - 'enable'
            sec_default_action:
                aliases: ['sec-default-action']
                type: str
                description: Sec default action.
                choices:
                    - 'deny'
                    - 'accept'
            secure_web_proxy:
                aliases: ['secure-web-proxy']
                type: str
                description: Secure web proxy.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'secure'
            secure_web_proxy_cert:
                aliases: ['secure-web-proxy-cert']
                type: list
                elements: str
                description: Secure web proxy cert.
            socks:
                type: str
                description: Socks.
                choices:
                    - 'disable'
                    - 'enable'
            socks_incoming_port:
                aliases: ['socks-incoming-port']
                type: list
                elements: str
                description: Socks incoming port.
            ssl_algorithm:
                aliases: ['ssl-algorithm']
                type: str
                description: Ssl algorithm.
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
            ssl_dh_bits:
                aliases: ['ssl-dh-bits']
                type: str
                description: Ssl dh bits.
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
            status:
                type: str
                description: Status.
                choices:
                    - 'disable'
                    - 'enable'
            unknown_http_version:
                aliases: ['unknown-http-version']
                type: str
                description: Unknown http version.
                choices:
                    - 'best-effort'
                    - 'reject'
            incoming_ip:
                aliases: ['incoming-ip']
                type: str
                description: Incoming ip.
            client_cert:
                aliases: ['client-cert']
                type: str
                description: Client cert.
                choices:
                    - 'disable'
                    - 'enable'
            empty_cert_action:
                aliases: ['empty-cert-action']
                type: str
                description: Empty cert action.
                choices:
                    - 'block'
                    - 'accept'
                    - 'accept-unmanageable'
            user_agent_detect:
                aliases: ['user-agent-detect']
                type: str
                description: User agent detect.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Web proxy explicit proxy
      fortinet.fortimanager.fmgr_webproxy_explicitproxy:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        webproxy_explicitproxy:
          name: "your value" # Required variable, string
          # detect_https_in_http_request: <value in [disable, enable]>
          # dns_mode: <value in [recursive, non-recursive, forward-only]>
          # dstport_from_incoming: <value in [disable, enable]>
          # ftp_incoming_port: <list or string>
          # ftp_over_http: <value in [disable, enable]>
          # header_proxy_agent: <value in [disable, enable]>
          # http: <value in [disable, enable]>
          # http_connection_mode: <value in [static, multiplex, serverpool]>
          # http_incoming_port: <list or string>
          # https_incoming_port: <list or string>
          # incoming_ip6: <string>
          # interface: <list or string>
          # ipv6_status: <value in [disable, enable]>
          # learn_dst_from_sni: <value in [disable, enable]>
          # pac_file_data: <string>
          # pac_file_name: <string>
          # pac_file_server_port: <string>
          # pac_file_server_status: <value in [disable, enable]>
          # pac_file_through_https: <value in [disable, enable]>
          # pac_file_url: <string>
          # pref_dns_result: <value in [ipv4, ipv6, ipv4-strict, ...]>
          # realm: <string>
          # return_to_sender: <value in [disable, enable]>
          # sec_default_action: <value in [deny, accept]>
          # secure_web_proxy: <value in [disable, enable, secure]>
          # secure_web_proxy_cert: <list or string>
          # socks: <value in [disable, enable]>
          # socks_incoming_port: <list or string>
          # ssl_algorithm: <value in [high, low, medium]>
          # ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          # status: <value in [disable, enable]>
          # unknown_http_version: <value in [best-effort, reject]>
          # incoming_ip: <string>
          # client_cert: <value in [disable, enable]>
          # empty_cert_action: <value in [block, accept, accept-unmanageable]>
          # user_agent_detect: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/web-proxy/explicit-proxy',
        '/pm/config/global/obj/web-proxy/explicit-proxy'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'webproxy_explicitproxy': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']],
            'options': {
                'detect-https-in-http-request': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dns-mode': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['recursive', 'non-recursive', 'forward-only'], 'type': 'str'},
                'dstport-from-incoming': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ftp-incoming-port': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ftp-over-http': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'header-proxy-agent': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-connection-mode': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['static', 'multiplex', 'serverpool'], 'type': 'str'},
                'http-incoming-port': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'https-incoming-port': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'incoming-ip6': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'str'},
                'interface': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ipv6-status': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'learn-dst-from-sni': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'pac-file-data': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'str'},
                'pac-file-name': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'str'},
                'pac-file-server-port': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'str'},
                'pac-file-server-status': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pac-file-through-https': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pac-file-url': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'str'},
                'pref-dns-result': {
                    'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']],
                    'choices': ['ipv4', 'ipv6', 'ipv4-strict', 'ipv6-strict'],
                    'type': 'str'
                },
                'realm': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'str'},
                'return-to-sender': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sec-default-action': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'secure-web-proxy': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable', 'secure'], 'type': 'str'},
                'secure-web-proxy-cert': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'socks': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'socks-incoming-port': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-algorithm': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['high', 'low', 'medium'], 'type': 'str'},
                'ssl-dh-bits': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['768', '1024', '1536', '2048'], 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unknown-http-version': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'choices': ['best-effort', 'reject'], 'type': 'str'},
                'incoming-ip': {'v_range': [['7.4.8', '7.4.8'], ['7.6.4', '']], 'type': 'str'},
                'client-cert': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'empty-cert-action': {'v_range': [['7.6.4', '']], 'choices': ['block', 'accept', 'accept-unmanageable'], 'type': 'str'},
                'user-agent-detect': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webproxy_explicitproxy'),
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
