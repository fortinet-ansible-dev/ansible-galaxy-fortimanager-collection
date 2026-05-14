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
module: fmgr_system_geoipoverride
short_description: Configure geographical location mapping for IP address
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
    system_geoipoverride:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            description:
                type: str
                description: Description.
            ip_range:
                aliases: ['ip-range']
                type: list
                elements: dict
                description: Ip range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description: Final IP address, inclusive, of the address range
                    id:
                        type: int
                        description: ID number for individual entry in the IP-Range table.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Starting IP address, inclusive, of the address range
            name:
                type: str
                description: Location name.
                required: true
            ip6_range:
                aliases: ['ip6-range']
                type: list
                elements: dict
                description: Ip6 range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description: Ending IP address, inclusive, of the address range
                    id:
                        type: int
                        description: ID of individual entry in the IPv6 range table.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Starting IP address, inclusive, of the address range
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
    - name: Create the geoip
      fortinet.fortimanager.fmgr_system_geoipoverride:
        adom: ansible
        state: present
        system_geoipoverride:
          name: ansible-test-geoipoverride

    - name: Table of IP ranges assigned to country.
      fortinet.fortimanager.fmgr_system_geoipoverride_iprange:
        bypass_validation: false
        adom: ansible
        geoip_override: ansible-test-geoipoverride # name
        state: present
        system_geoipoverride_iprange:
          end_ip: 222.222.222.25
          id: 1
          start_ip: 222.222.222.2
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
        '/pm/config/adom/{adom}/obj/system/geoip-override',
        '/pm/config/global/obj/system/geoip-override'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_geoipoverride': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'description': {'type': 'str'},
                'ip-range': {
                    'type': 'list',
                    'options': {'end-ip': {'type': 'str'}, 'id': {'type': 'int'}, 'start-ip': {'type': 'str'}},
                    'elements': 'dict'
                },
                'name': {'required': True, 'type': 'str'},
                'ip6-range': {
                    'v_range': [['6.4.0', '']],
                    'type': 'list',
                    'options': {
                        'end-ip': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'id': {'v_range': [['6.4.0', '']], 'type': 'int'},
                        'start-ip': {'v_range': [['6.4.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_geoipoverride'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
