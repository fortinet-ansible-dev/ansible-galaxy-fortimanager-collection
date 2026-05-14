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
module: fmgr_firewall_vip46_realservers
short_description: Real servers.
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
    vip46:
        description: The parameter (vip46) in requested url.
        type: str
        required: true
    firewall_vip46_realservers:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            client_ip:
                aliases: ['client-ip']
                type: str
                description: Restrict server to a client IP in this range.
            healthcheck:
                type: str
                description: Per server health check.
                choices: ['disable', 'enable', 'vip']
            holddown_interval:
                aliases: ['holddown-interval']
                type: int
                description: Hold down interval.
            id:
                type: int
                description: Real server ID.
                required: true
            ip:
                type: str
                description: Mapped server IPv6.
            max_connections:
                aliases: ['max-connections']
                type: int
                description: Maximum number of connections allowed to server.
            monitor:
                type: raw
                description: (list or str) Health monitors.
            port:
                type: int
                description: Mapped server port.
            status:
                type: str
                description: Server administrative status.
                choices: ['active', 'standby', 'disable']
            weight:
                type: int
                description: Weight.
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
    - name: Real servers.
      fortinet.fortimanager.fmgr_firewall_vip46_realservers:
        bypass_validation: false
        adom: ansible
        vip46: "ansible-test-vip46" # name
        state: present
        firewall_vip46_realservers:
          healthcheck: disable
          id: 1

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the real servers of IPv4 to IPv6 virtual IP
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_vip46_realservers"
          params:
            adom: "ansible"
            vip46: "ansible-test-vip46" # name
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
        '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/realservers',
        '/pm/config/global/obj/firewall/vip46/{vip46}/realservers'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vip46': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_vip46_realservers': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'client-ip': {'type': 'str'},
                'healthcheck': {'choices': ['disable', 'enable', 'vip'], 'type': 'str'},
                'holddown-interval': {'type': 'int'},
                'id': {'required': True, 'type': 'int'},
                'ip': {'type': 'str'},
                'max-connections': {'type': 'int'},
                'monitor': {'type': 'raw'},
                'port': {'type': 'int'},
                'status': {'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                'weight': {'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip46_realservers'),
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
