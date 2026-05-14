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
module: fmgr_system_certificate_oftp
short_description: OFTP certificates and keys.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_certificate_oftp:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            certificate:
                type: raw
                description: (list) PEM format certificate.
            comment:
                type: str
                description: OFTP certificate comment.
            custom:
                type: str
                description:
                    - Enable/disable custom certificate.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            password:
                type: raw
                description: (list) Password for encrypted private-key, unset for non-encrypted.
            private_key:
                aliases: ['private-key']
                type: raw
                description: (list) PEM format private key.
            local:
                type: str
                description: Choose from a local certificates.
            mode:
                type: str
                description:
                    - Mode of certificates used by oftpd.
                    - default - Default mode.
                    - custom - Use custom certificate.
                    - local - Use a local certificate.
                choices: ['default', 'custom', 'local']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: OFTP certificates and keys.
      fortinet.fortimanager.fmgr_system_certificate_oftp:
        # workspace_locking_adom: <global or your adom name>
        system_certificate_oftp:
          # certificate: <list or string>
          # comment: <string>
          # custom: <value in [disable, enable]>
          # password: <list or string>
          # private_key: <list or string>
          # local: <string>
          # mode: <value in [default, custom, local]>
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
        '/cli/global/system/certificate/oftp'
    ]
    module_arg_spec = {
        'system_certificate_oftp': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'certificate': {'type': 'raw'},
                'comment': {'type': 'str'},
                'custom': {'v_range': [['6.0.0', '6.2.3'], ['6.4.0', '6.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'password': {'no_log': True, 'type': 'raw'},
                'private-key': {'no_log': True, 'type': 'raw'},
                'local': {'v_range': [['6.2.5', '6.2.13'], ['6.4.1', '']], 'type': 'str'},
                'mode': {'v_range': [['6.2.5', '6.2.13'], ['6.4.1', '']], 'choices': ['default', 'custom', 'local'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_certificate_oftp'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
