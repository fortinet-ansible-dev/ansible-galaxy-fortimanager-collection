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
module: fmgr_ztna_webproxy_apigateway_realservers
short_description: Select the real servers that this Access Proxy will distribute traffic to.
description:
    - This module is able to configure a FortiManager device.
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
    web-proxy:
        description: Deprecated, please use "web_proxy"
        type: str
    web_proxy:
        description: The parameter (web-proxy) in requested url.
        type: str
    api-gateway:
        description: Deprecated, please use "api_gateway"
        type: str
    api_gateway:
        description: The parameter (api-gateway) in requested url.
        type: str
    ztna_webproxy_apigateway_realservers:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            addr_type:
                aliases: ['addr-type']
                type: str
                description: Type of address.
                choices:
                    - 'fqdn'
                    - 'ip'
            address:
                type: list
                elements: str
                description: Address or address group of the real server.
            health_check:
                aliases: ['health-check']
                type: str
                description: Enable to check the responsiveness of the real server before forwarding traffic.
                choices:
                    - 'disable'
                    - 'enable'
            health_check_proto:
                aliases: ['health-check-proto']
                type: str
                description: Protocol of the health check monitor to use when polling to determine servers connectivity status.
                choices:
                    - 'ping'
                    - 'http'
                    - 'tcp-connect'
            holddown_interval:
                aliases: ['holddown-interval']
                type: str
                description: Enable/disable holddown timer.
                choices:
                    - 'disable'
                    - 'enable'
            http_host:
                aliases: ['http-host']
                type: str
                description: HTTP server domain name in HTTP header.
            id:
                type: int
                description: Real server ID.
                required: true
            ip:
                type: str
                description: IP address of the real server.
            port:
                type: int
                description: Port for communicating with the real server.
            status:
                type: str
                description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is sent.
                choices:
                    - 'active'
                    - 'standby'
                    - 'disable'
            translate_host:
                aliases: ['translate-host']
                type: str
                description: Enable/disable translation of hostname/IP from virtual server to real server.
                choices:
                    - 'disable'
                    - 'enable'
            verify_cert:
                aliases: ['verify-cert']
                type: str
                description: Enable/disable certificate verification of the real server.
                choices:
                    - 'disable'
                    - 'enable'
            weight:
                type: int
                description: Weight of the real server.
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
    - name: Select the real servers that this Access Proxy will distribute traffic to.
      fortinet.fortimanager.fmgr_ztna_webproxy_apigateway_realservers:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        web_proxy: <your own value>
        api_gateway: <your own value>
        state: present # <value in [present, absent]>
        ztna_webproxy_apigateway_realservers:
          id: 0 # Required variable, integer
          # addr_type: <value in [fqdn, ip]>
          # address: <list or string>
          # health_check: <value in [disable, enable]>
          # health_check_proto: <value in [ping, http, tcp-connect]>
          # holddown_interval: <value in [disable, enable]>
          # http_host: <string>
          # ip: <string>
          # port: <integer>
          # status: <value in [active, standby, disable]>
          # translate_host: <value in [disable, enable]>
          # verify_cert: <value in [disable, enable]>
          # weight: <integer>
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
        '/pm/config/adom/{adom}/obj/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}/realservers',
        '/pm/config/global/obj/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}/realservers'
    ]
    url_params = ['adom', 'web-proxy', 'api-gateway']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'web-proxy': {'type': 'str', 'api_name': 'web_proxy'},
        'web_proxy': {'type': 'str'},
        'api-gateway': {'type': 'str', 'api_name': 'api_gateway'},
        'api_gateway': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'ztna_webproxy_apigateway_realservers': {
            'type': 'dict',
            'v_range': [['7.6.4', '']],
            'options': {
                'addr-type': {'v_range': [['7.6.4', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                'address': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'health-check': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'health-check-proto': {'v_range': [['7.6.4', '']], 'choices': ['ping', 'http', 'tcp-connect'], 'type': 'str'},
                'holddown-interval': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-host': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'id': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'int'},
                'ip': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'port': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'status': {'v_range': [['7.6.4', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                'translate-host': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'verify-cert': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'weight': {'v_range': [['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ztna_webproxy_apigateway_realservers'),
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
