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
module: fmgr_application_internetservicecustom
short_description: Configure custom Internet service applications.
version_added: "2.2.0"
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
    application_internetservicecustom:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            disable_entry:
                aliases: ['disable-entry']
                type: list
                elements: dict
                description: Disable entry.
                suboptions:
                    id:
                        type: int
                        description: Disable entry ID.
                    ip_range:
                        aliases: ['ip-range']
                        type: list
                        elements: dict
                        description: Ip range.
                        suboptions:
                            end_ip:
                                aliases: ['end-ip']
                                type: str
                                description: End IP address.
                            id:
                                type: int
                                description: Disable entry range ID.
                            start_ip:
                                aliases: ['start-ip']
                                type: str
                                description: Start IP address.
                    port:
                        type: raw
                        description: (list) Port.
                    protocol:
                        type: int
                        description: Protocol number.
            entry:
                type: list
                elements: dict
                description: Entry.
                suboptions:
                    dst:
                        type: str
                        description: Destination address name.
                    id:
                        type: int
                        description: Entry ID
                    port_range:
                        aliases: ['port-range']
                        type: list
                        elements: dict
                        description: Port range.
                        suboptions:
                            end_port:
                                aliases: ['end-port']
                                type: int
                                description: End destination port number
                            id:
                                type: int
                                description: Custom entry port range ID.
                            start_port:
                                aliases: ['start-port']
                                type: int
                                description: Start destination port number
                    protocol:
                        type: int
                        description: Protocol number.
            master_service_id:
                aliases: ['master-service-id']
                type: str
                description: Internet service database application ID.
            name:
                type: str
                description: Application name.
                required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure custom Internet service applications.
      fortinet.fortimanager.fmgr_application_internetservicecustom:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        application_internetservicecustom:
          name: "your value" # Required variable, string
          # comment: <string>
          # disable_entry:
          #   - id: <integer>
          #     ip_range:
          #       - end_ip: <string>
          #         id: <integer>
          #         start_ip: <string>
          #     port: <list or integer>
          #     protocol: <integer>
          # entry:
          #   - dst: <string>
          #     id: <integer>
          #     port_range:
          #       - end_port: <integer>
          #         id: <integer>
          #         start_port: <integer>
          #     protocol: <integer>
          # master_service_id: <string>
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
        '/pm/config/adom/{adom}/obj/application/internet-service-custom',
        '/pm/config/global/obj/application/internet-service-custom'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'application_internetservicecustom': {
            'type': 'dict', 'v_range': [['6.2.0', '6.2.13']],
            'options': {
                'comment': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'disable-entry': {
                    'v_range': [['6.2.0', '6.2.13']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'},
                        'ip-range': {
                            'v_range': [['6.2.0', '6.2.13']],
                            'type': 'list',
                            'options': {
                                'end-ip': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                                'id': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'},
                                'start-ip': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'port': {'v_range': [['6.2.0', '6.2.13']], 'type': 'raw'},
                        'protocol': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'entry': {
                    'v_range': [['6.2.0', '6.2.13']],
                    'type': 'list',
                    'options': {
                        'dst': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'id': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'},
                        'port-range': {
                            'v_range': [['6.2.0', '6.2.13']],
                            'type': 'list',
                            'options': {
                                'end-port': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'},
                                'id': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'},
                                'start-port': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'protocol': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'master-service-id': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'name': {'v_range': [['6.2.0', '6.2.13']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'application_internetservicecustom'),
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
