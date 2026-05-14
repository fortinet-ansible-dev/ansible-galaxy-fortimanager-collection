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
module: fmgr_fmupdate_fdssetting_pushoverridetoclient
short_description: Enable/disable push updates, and override the default IP address and port used by FortiGuard to send antivirus and IPS push messages...
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    fmupdate_fdssetting_pushoverridetoclient:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            announce_ip:
                aliases: ['announce-ip']
                type: list
                elements: dict
                description: Announce ip.
                suboptions:
                    id:
                        type: int
                        description: ID of the announce IP address
                    ip:
                        type: str
                        description: Announce IPv4 address.
                    port:
                        type: int
                        description: Announce IP port
            status:
                type: str
                description:
                    - Enable/disable push updates
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Enable/disable push updates, and override the default IP address and port used by FortiGuard to send antivirus and IPS push messages...
      fortinet.fortimanager.fmgr_fmupdate_fdssetting_pushoverridetoclient:
        # workspace_locking_adom: <global or your adom name>
        fmupdate_fdssetting_pushoverridetoclient:
          # announce_ip:
          #   - id: <integer>
          #     ip: <string>
          #     port: <integer>
          # status: <value in [disable, enable]>
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
        '/cli/global/fmupdate/fds-setting/push-override-to-client'
    ]
    module_arg_spec = {
        'fmupdate_fdssetting_pushoverridetoclient': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'announce-ip': {'type': 'list', 'options': {'id': {'type': 'int'}, 'ip': {'type': 'str'}, 'port': {'type': 'int'}}, 'elements': 'dict'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmupdate_fdssetting_pushoverridetoclient'),
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
