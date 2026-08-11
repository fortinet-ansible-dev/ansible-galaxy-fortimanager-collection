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
module: fmgr_ztna_destination
short_description: Configure ZTNA destination.
version_added: "2.15.0"
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
  ztna_destination:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      address:
        type: list
        elements: str
        description: Address or address group of the ZTNA destination.
      conn_type:
        aliases: ['conn-type']
        type: str
        description: Connection type.
        choices: ['traffic-forwarding', 'ssh']
      domain:
        type: str
        description: Wildcard domain name of the ZTNA destination.
      external_auth:
        aliases: ['external-auth']
        type: str
        description: Enable/disable use of external browser as user-agent for SAML user authentication.
        choices: ['disable', 'enable']
      mappedport:
        type: str
        description: Port for communicating with the real server.
      name:
        type: str
        description: Destination name.
        required: true
      protocol:
        type: str
        description: Protocol type based on IANA numbers.
        choices: ['TCP', 'UDP', 'ALL']
      saas_application:
        aliases: ['saas-application']
        type: list
        elements: str
        description: SaaS application controlled by this ZTNA destination.
      ssh_client_cert:
        aliases: ['ssh-client-cert']
        type: list
        elements: str
        description: Configure access-proxy SSH client certificate profile.
      ssh_host_key:
        aliases: ['ssh-host-key']
        type: list
        elements: str
        description: Configure host keys
      ssh_host_key_validation:
        aliases: ['ssh-host-key-validation']
        type: str
        description: Enable/disable SSH host key validation.
        choices: ['disable', 'enable']
      tunnel_encryption:
        aliases: ['tunnel-encryption']
        type: str
        description: Tunnel encryption.
        choices: ['disable', 'enable']
      type:
        type: str
        description: ZTNA destination type.
        choices: ['on-premise', 'saas']
      uuid:
        type: str
        description: Universally Unique Identifier
'''

EXAMPLES = '''
- name: Test ZTNA destinations
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create a ZTNA destination
      fortinet.fortimanager.fmgr_ztna_destination:
        enable_log: true
        adom: root
        state: present
        ztna_destination:
          name: test_destination
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
        '/pm/config/adom/{adom}/obj/ztna/destination',
        '/pm/config/global/obj/ztna/destination'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'ztna_destination': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'address': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'conn-type': {'v_range': [['8.0.0', '']], 'choices': ['traffic-forwarding', 'ssh'], 'type': 'str'},
                'domain': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'external-auth': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mappedport': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'name': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'str'},
                'protocol': {'v_range': [['8.0.0', '']], 'choices': ['TCP', 'UDP', 'ALL'], 'type': 'str'},
                'saas-application': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'ssh-client-cert': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'ssh-host-key': {'v_range': [['8.0.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ssh-host-key-validation': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-encryption': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['8.0.0', '']], 'choices': ['on-premise', 'saas'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ztna_destination'),
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
