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
module: fmgr_hotspot20_h2qpconncapability
short_description: Configure connection capability.
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
    hotspot20_h2qpconncapability:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            esp-port:
                type: str
                description: Deprecated, please rename it to esp_port. Set ESP port service
                choices:
                    - 'closed'
                    - 'open'
                    - 'unknown'
            ftp-port:
                type: str
                description: Deprecated, please rename it to ftp_port. Set FTP port service status.
                choices:
                    - 'closed'
                    - 'open'
                    - 'unknown'
            http-port:
                type: str
                description: Deprecated, please rename it to http_port. Set HTTP port service status.
                choices:
                    - 'closed'
                    - 'open'
                    - 'unknown'
            icmp-port:
                type: str
                description: Deprecated, please rename it to icmp_port. Set ICMP port service status.
                choices:
                    - 'closed'
                    - 'open'
                    - 'unknown'
            ikev2-port:
                type: str
                description: Deprecated, please rename it to ikev2_port. Set IKEv2 port service for IPsec VPN status.
                choices:
                    - 'closed'
                    - 'open'
                    - 'unknown'
            ikev2-xx-port:
                type: str
                description: Deprecated, please rename it to ikev2_xx_port. Set UDP port 4500
                choices:
                    - 'closed'
                    - 'open'
                    - 'unknown'
            name:
                type: str
                description: Connection capability name.
                required: true
            pptp-vpn-port:
                type: str
                description: Deprecated, please rename it to pptp_vpn_port. Set Point to Point Tunneling Protocol
                choices:
                    - 'closed'
                    - 'open'
                    - 'unknown'
            ssh-port:
                type: str
                description: Deprecated, please rename it to ssh_port. Set SSH port service status.
                choices:
                    - 'closed'
                    - 'open'
                    - 'unknown'
            tls-port:
                type: str
                description: Deprecated, please rename it to tls_port. Set TLS VPN
                choices:
                    - 'closed'
                    - 'open'
                    - 'unknown'
            voip-tcp-port:
                type: str
                description: Deprecated, please rename it to voip_tcp_port. Set VoIP TCP port service status.
                choices:
                    - 'closed'
                    - 'open'
                    - 'unknown'
            voip-udp-port:
                type: str
                description: Deprecated, please rename it to voip_udp_port. Set VoIP UDP port service status.
                choices:
                    - 'closed'
                    - 'open'
                    - 'unknown'
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
    - name: Configure connection capability.
      fortinet.fortimanager.fmgr_hotspot20_h2qpconncapability:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        hotspot20_h2qpconncapability:
          esp_port: <value in [closed, open, unknown]>
          ftp_port: <value in [closed, open, unknown]>
          http_port: <value in [closed, open, unknown]>
          icmp_port: <value in [closed, open, unknown]>
          ikev2_port: <value in [closed, open, unknown]>
          ikev2_xx_port: <value in [closed, open, unknown]>
          name: <string>
          pptp_vpn_port: <value in [closed, open, unknown]>
          ssh_port: <value in [closed, open, unknown]>
          tls_port: <value in [closed, open, unknown]>
          voip_tcp_port: <value in [closed, open, unknown]>
          voip_udp_port: <value in [closed, open, unknown]>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-conn-capability',
        '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-conn-capability'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}',
        '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'hotspot20_h2qpconncapability': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'esp-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'ftp-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'http-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'icmp-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'ikev2-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'ikev2-xx-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'pptp-vpn-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'ssh-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'tls-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'voip-tcp-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'},
                'voip-udp-port': {'choices': ['closed', 'open', 'unknown'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'hotspot20_h2qpconncapability'),
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
