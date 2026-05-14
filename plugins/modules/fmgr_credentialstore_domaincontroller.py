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
module: fmgr_credentialstore_domaincontroller
short_description: Define known domain controller servers.
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
    credentialstore_domaincontroller:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            domain_name:
                aliases: ['domain-name']
                type: str
                description: Fully qualified domain name
            ip:
                type: str
                description: IPv4 server address.
            ip6:
                type: str
                description: IPv6 server address.
            password:
                type: raw
                description: (list) Password for specified username.
            port:
                type: int
                description: Port number of service.
            server_name:
                aliases: ['server-name']
                type: str
                description: Name of the server to connect to.
            username:
                type: str
                description: User name to sign in with.
            hostname:
                type: str
                description: Hostname of the server to connect to.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Define known domain controller servers.
      fortinet.fortimanager.fmgr_credentialstore_domaincontroller:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        credentialstore_domaincontroller:
          # domain_name: <string>
          # ip: <string>
          # ip6: <string>
          # password: <list or string>
          # port: <integer>
          # server_name: <string>
          # username: <string>
          # hostname: <string>
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
        '/pm/config/adom/{adom}/obj/credential-store/domain-controller',
        '/pm/config/global/obj/credential-store/domain-controller'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'credentialstore_domaincontroller': {
            'type': 'dict', 'v_range': [['6.4.0', '']],
            'options': {
                'domain-name': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'ip': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'ip6': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'password': {'v_range': [['6.4.0', '']], 'no_log': True, 'type': 'raw'},
                'port': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'server-name': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'username': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'hostname': {'v_range': [['6.4.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'credentialstore_domaincontroller'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
