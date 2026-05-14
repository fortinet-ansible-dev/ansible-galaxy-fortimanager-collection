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
module: fmgr_firewall_vip6_realservers
short_description: Select the real servers that this server load balancing VIP will distribute traffic to.
version_added: "2.0.0"
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
    firewall_vip6_realservers:
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
                description: IPv6 address of the real server.
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
            verify_cert:
                aliases: ['verify-cert']
                type: str
                description: Enable/disable certificate verification of the real server.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Select the real servers that this server load balancing VIP will distribute traffic to.
      fortinet.fortimanager.fmgr_firewall_vip6_realservers:
        bypass_validation: false
        adom: ansible
        vip6: "ansible-test-vip6" # name
        state: present
        firewall_vip6_realservers:
          healthcheck: disable # <value in [disable, enable, vip]>
          id: 1
          status: active # <value in [active, standby, disable]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the real servers of virtual IP for IPv6
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_vip6_realservers"
          params:
            adom: "ansible"
            vip6: "ansible-test-vip6" # name
            realservers: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/realservers',
        '/pm/config/global/obj/firewall/vip6/{vip6}/realservers'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vip6': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_vip6_realservers': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'client-ip': {'type': 'str'},
                'healthcheck': {'choices': ['disable', 'enable', 'vip'], 'type': 'str'},
                'holddown-interval': {'type': 'int'},
                'http-host': {'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'ip': {'type': 'str'},
                'max-connections': {'type': 'int'},
                'monitor': {'type': 'raw'},
                'port': {'type': 'int'},
                'status': {'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                'weight': {'type': 'int'},
                'translate-host': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'verify-cert': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip6_realservers'),
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
