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
module: fmgr_utmprofile
short_description: Configure UTM
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
    utmprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            antivirus_profile:
                aliases: ['antivirus-profile']
                type: str
                description: AntiVirus profile name.
            application_list:
                aliases: ['application-list']
                type: str
                description: Application control list name.
            comment:
                type: str
                description: Comment.
            ips_sensor:
                aliases: ['ips-sensor']
                type: str
                description: IPS sensor name.
            name:
                type: str
                description: UTM profile name.
                required: true
            scan_botnet_connections:
                aliases: ['scan-botnet-connections']
                type: str
                description: Block or monitor connections to Botnet servers or disable Botnet scanning.
                choices: ['disable', 'block', 'monitor']
            utm_log:
                aliases: ['utm-log']
                type: str
                description: Enable/disable UTM logging.
                choices: ['disable', 'enable']
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: str
                description: WebFilter profile name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure UTM
      fortinet.fortimanager.fmgr_utmprofile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        utmprofile:
          name: "your value" # Required variable, string
          # antivirus_profile: <string>
          # application_list: <string>
          # comment: <string>
          # ips_sensor: <string>
          # scan_botnet_connections: <value in [disable, block, monitor]>
          # utm_log: <value in [disable, enable]>
          # webfilter_profile: <string>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/utm-profile',
        '/pm/config/global/obj/wireless-controller/utm-profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'utmprofile': {
            'type': 'dict', 'v_range': [['6.2.2', '']],
            'options': {
                'antivirus-profile': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'application-list': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'comment': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'ips-sensor': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'name': {'v_range': [['6.2.2', '']], 'required': True, 'type': 'str'},
                'scan-botnet-connections': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'utm-log': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webfilter-profile': {'v_range': [['6.2.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'utmprofile'),
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
