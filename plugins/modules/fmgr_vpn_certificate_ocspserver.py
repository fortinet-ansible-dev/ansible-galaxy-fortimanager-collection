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
module: fmgr_vpn_certificate_ocspserver
short_description: OCSP server configuration.
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
    vpn_certificate_ocspserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cert:
                type: str
                description: OCSP server certificate.
            name:
                type: str
                description: OCSP server entry name.
                required: true
            secondary_cert:
                aliases: ['secondary-cert']
                type: str
                description: Secondary OCSP server certificate.
            secondary_url:
                aliases: ['secondary-url']
                type: str
                description: Secondary OCSP server URL.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IP address for communications to the OCSP server.
            unavail_action:
                aliases: ['unavail-action']
                type: str
                description: Action when server is unavailable
                choices: ['revoke', 'ignore']
            url:
                type: str
                description: OCSP server URL.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: OCSP server configuration.
      fortinet.fortimanager.fmgr_vpn_certificate_ocspserver:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        vpn_certificate_ocspserver:
          name: "your value" # Required variable, string
          # cert: <string>
          # secondary_cert: <string>
          # secondary_url: <string>
          # source_ip: <string>
          # unavail_action: <value in [revoke, ignore]>
          # url: <string>
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
        '/pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server',
        '/pm/config/global/obj/vpn/certificate/ocsp-server'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vpn_certificate_ocspserver': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'cert': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'secondary-cert': {'type': 'str'},
                'secondary-url': {'type': 'str'},
                'source-ip': {'type': 'str'},
                'unavail-action': {'choices': ['revoke', 'ignore'], 'type': 'str'},
                'url': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_certificate_ocspserver'),
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
