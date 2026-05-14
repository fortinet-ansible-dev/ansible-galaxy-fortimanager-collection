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
module: fmgr_user_externalidentityprovider
short_description: Configure external identity provider.
version_added: "2.6.0"
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
    user_externalidentityprovider:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            group_attr_name:
                aliases: ['group-attr-name']
                type: str
                description: Group attribute name in authentication query.
            interface:
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices: ['auto', 'sdwan', 'specify']
            name:
                type: str
                description: External identity provider name.
                required: true
            port:
                type: int
                description: External identity provider service port number
            server_identity_check:
                aliases: ['server-identity-check']
                type: str
                description: Enable/disable servers identity check against its certificate and subject alternative name
                choices: ['disable', 'enable']
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Use this IPv4/v6 address to connect to the external identity provider.
            timeout:
                type: int
                description: Connection timeout value in seconds
            type:
                type: str
                description: External identity provider type.
                choices: ['ms-graph']
            url:
                type: str
                description: Url.
            user_attr_name:
                aliases: ['user-attr-name']
                type: str
                description: User attribute name in authentication query.
            version:
                type: str
                description: External identity API version.
                choices: ['beta', 'v1.0']
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure external identity provider.
      fortinet.fortimanager.fmgr_user_externalidentityprovider:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        user_externalidentityprovider:
          name: "your value" # Required variable, string
          # group_attr_name: <string>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # port: <integer>
          # server_identity_check: <value in [disable, enable]>
          # source_ip: <string>
          # timeout: <integer>
          # type: <value in [ms-graph]>
          # url: <string>
          # user_attr_name: <string>
          # version: <value in [beta, v1.0]>
          # vrf_select: <integer>
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
        '/pm/config/adom/{adom}/obj/user/external-identity-provider',
        '/pm/config/global/obj/user/external-identity-provider'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'user_externalidentityprovider': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'group-attr-name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'server-identity-check': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'timeout': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['ms-graph'], 'type': 'str'},
                'url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'user-attr-name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'version': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['beta', 'v1.0'], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_externalidentityprovider'),
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
