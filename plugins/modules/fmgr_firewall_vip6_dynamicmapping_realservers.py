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
module: fmgr_firewall_vip6_dynamicmapping_realservers
short_description: Select the real servers that this server load balancing VIP will distribute traffic to.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    vip6:
        description: The parameter (vip6) in requested url.
        type: str
        required: true
    dynamic_mapping:
        description: The parameter (dynamic_mapping) in requested url.
        type: str
        required: true
    firewall_vip6_dynamicmapping_realservers:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            client_ip:
                aliases: ['client-ip']
                type: str
                description: Only clients in this IP range can connect to this real server.
            healthcheck:
                type: str
                description: Enable to check the responsiveness of the real server before forwarding traffic.
                choices: ['disable', 'enable', 'vip']
            holddown_interval:
                aliases: ['holddown-interval']
                type: int
                description: Time in seconds that the health check monitor continues to monitor an unresponsive server that should be active.
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
            max_connections:
                aliases: ['max-connections']
                type: int
                description: Max number of active connections that can directed to the real server.
            monitor:
                type: raw
                description: (list or str) Name of the health check monitor to use when polling to determine a virtual servers connectivity status.
            port:
                type: int
                description: Port for communicating with the real server.
            status:
                type: str
                description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is sent.
                choices: ['active', 'standby', 'disable']
            weight:
                type: int
                description: Weight of the real server.
            translate_host:
                aliases: ['translate-host']
                type: str
                description: Enable/disable translation of hostname/IP from virtual server to real server.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Select the real servers that this server load balancing VIP will distribute traffic to.
      fortinet.fortimanager.fmgr_firewall_vip6_dynamicmapping_realservers:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        vip6: <your own value>
        dynamic_mapping: <your own value>
        state: present # <value in [present, absent]>
        firewall_vip6_dynamicmapping_realservers:
          id: 0 # Required variable, integer
          # client_ip: <string>
          # healthcheck: <value in [disable, enable, vip]>
          # holddown_interval: <integer>
          # http_host: <string>
          # ip: <string>
          # max_connections: <integer>
          # monitor: <list or string>
          # port: <integer>
          # status: <value in [active, standby, disable]>
          # weight: <integer>
          # translate_host: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers',
        '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vip6': {'required': True, 'type': 'str'},
        'dynamic_mapping': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_vip6_dynamicmapping_realservers': {
            'type': 'dict', 'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']],
            'options': {
                'client-ip': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'healthcheck': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable', 'vip'], 'type': 'str'},
                'holddown-interval': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'http-host': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'id': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'required': True, 'type': 'int'},
                'ip': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'str'},
                'max-connections': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'monitor': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'raw'},
                'port': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'status': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                'weight': {'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']], 'type': 'int'},
                'translate-host': {'v_range': [['7.2.2', '7.2.5'], ['7.4.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip6_dynamicmapping_realservers'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
