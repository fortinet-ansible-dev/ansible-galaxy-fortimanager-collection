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
module: fmgr_firewall_accessproxy_realservers
short_description: Select the SSL real servers that this Access Proxy will distribute traffic to.
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
    access-proxy:
        description: Deprecated, please use "access_proxy"
        type: str
    access_proxy:
        description: The parameter (access-proxy) in requested url.
        type: str
    firewall_accessproxy_realservers:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
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
                choices: ['active', 'standby', 'disable']
            weight:
                type: int
                description: Weight of the real server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Select the SSL real servers that this Access Proxy will distribute traffic to.
      fortinet.fortimanager.fmgr_firewall_accessproxy_realservers:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        access_proxy: <your own value>
        state: present # <value in [present, absent]>
        firewall_accessproxy_realservers:
          id: 0 # Required variable, integer
          # ip: <string>
          # port: <integer>
          # status: <value in [active, standby, disable]>
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
        '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/realservers',
        '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/realservers'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'access-proxy': {'type': 'str', 'api_name': 'access_proxy'},
        'access_proxy': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_accessproxy_realservers': {
            'type': 'dict', 'v_range': [['7.0.0', '']],
            'options': {
                'id': {'v_range': [['7.0.0', '']], 'required': True, 'type': 'int'},
                'ip': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'port': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'status': {'v_range': [['7.0.0', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                'weight': {'v_range': [['7.0.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_accessproxy_realservers'),
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
