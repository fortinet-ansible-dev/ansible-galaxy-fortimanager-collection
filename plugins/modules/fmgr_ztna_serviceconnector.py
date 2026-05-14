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
module: fmgr_ztna_serviceconnector
short_description: Ztna service connector
version_added: "2.12.0"
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
    ztna_serviceconnector:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            certificate:
                type: list
                elements: str
                description: Certificate.
            connection_mode:
                aliases: ['connection-mode']
                type: str
                description: Connection mode.
                choices: ['forward', 'reverse']
            encryption:
                type: str
                description: Encryption.
                choices: ['disable', 'enable']
            forward_address:
                aliases: ['forward-address']
                type: str
                description: Forward address.
            forward_destination_cn:
                aliases: ['forward-destination-cn']
                type: str
                description: Forward destination cn.
            forward_port:
                aliases: ['forward-port']
                type: int
                description: Forward port.
            health_check_interval:
                aliases: ['health-check-interval']
                type: int
                description: Health check interval.
            log:
                type: str
                description: Log.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Name.
                required: true
            relay_dev_info:
                aliases: ['relay-dev-info']
                type: str
                description: Relay dev info.
                choices: ['disable', 'enable']
            relay_user_info:
                aliases: ['relay-user-info']
                type: str
                description: Relay user info.
                choices: ['disable', 'enable']
            ssl_max_version:
                aliases: ['ssl-max-version']
                type: str
                description: Ssl max version.
                choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
            ssl_min_version:
                aliases: ['ssl-min-version']
                type: str
                description: Ssl min version.
                choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
            status:
                type: str
                description: Status.
                choices: ['disable', 'enable']
            trusted_ca:
                aliases: ['trusted-ca']
                type: list
                elements: str
                description: Trusted ca.
            url_map:
                aliases: ['url-map']
                type: str
                description: Url map.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Ztna service connector
      fortinet.fortimanager.fmgr_ztna_serviceconnector:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        ztna_serviceconnector:
          name: "your value" # Required variable, string
          # certificate: <list or string>
          # connection_mode: <value in [forward, reverse]>
          # encryption: <value in [disable, enable]>
          # forward_address: <string>
          # forward_destination_cn: <string>
          # forward_port: <integer>
          # health_check_interval: <integer>
          # log: <value in [disable, enable]>
          # relay_dev_info: <value in [disable, enable]>
          # relay_user_info: <value in [disable, enable]>
          # ssl_max_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_min_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # status: <value in [disable, enable]>
          # trusted_ca: <list or string>
          # url_map: <string>
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
        '/pm/config/adom/{adom}/obj/ztna/service-connector',
        '/pm/config/global/obj/ztna/service-connector'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'ztna_serviceconnector': {
            'type': 'dict', 'v_range': [['7.6.4', '']],
            'options': {
                'certificate': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'connection-mode': {'v_range': [['7.6.4', '']], 'choices': ['forward', 'reverse'], 'type': 'str'},
                'encryption': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forward-address': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'forward-destination-cn': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'forward-port': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'health-check-interval': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'log': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'str'},
                'relay-dev-info': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'relay-user-info': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-max-version': {'v_range': [['7.6.4', '']], 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-min-version': {'v_range': [['7.6.4', '']], 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'status': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trusted-ca': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'url-map': {'v_range': [['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ztna_serviceconnector'),
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
