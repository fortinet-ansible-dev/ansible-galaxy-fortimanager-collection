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
module: fmgr_system_sql_customskipidx
short_description: List of aditional SQL skip index fields.
version_added: "2.1.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_sql_customskipidx:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            device_type:
                aliases: ['device-type']
                type: str
                description:
                    - Device type.
                    - FortiGate - Set device type to FortiGate.
                    - FortiManager - Set device type to FortiManager
                    - FortiClient - Set device type to FortiClient.
                    - FortiMail - Set device type to FortiMail.
                    - FortiWeb - Set device type to FortiWeb.
                    - FortiSandbox - Set device type to FortiSandbox
                    - FortiProxy - Set device type to FortiProxy
                choices: ['FortiGate', 'FortiManager', 'FortiClient', 'FortiMail', 'FortiWeb',
                          'FortiSandbox', 'FortiProxy']
            id:
                type: int
                description: Add or Edit log index fields.
                required: true
            index_field:
                aliases: ['index-field']
                type: str
                description: Field to be added to skip index.
            log_type:
                aliases: ['log-type']
                type: str
                description:
                    - Log type.
                    - app-ctrl
                    - attack
                    - content
                    - dlp
                    - emailfilter
                    - event
                    - generic
                    - history
                    - traffic
                    - virus
                    - voip
                    - webfilter
                    - netscan
                    - fct-event
                    - fct-traffic
                    - fct-netscan
                    - waf
                    - gtp
                    - dns
                    - ssh
                    - ssl
                    - file-filter
                    - asset
                choices: ['app-ctrl', 'attack', 'content', 'dlp', 'emailfilter', 'event',
                          'generic', 'history', 'traffic', 'virus', 'voip', 'webfilter',
                          'netscan', 'fct-event', 'fct-traffic', 'fct-netscan', 'waf', 'gtp',
                          'dns', 'ssh', 'ssl', 'file-filter', 'asset', 'protocol', 'siem', 'ztna',
                          'security']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: List of aditional SQL skip index fields.
      fortinet.fortimanager.fmgr_system_sql_customskipidx:
        # workspace_locking_adom: <global or your adom name>
        state: present # <value in [present, absent]>
        system_sql_customskipidx:
          id: 0 # Required variable, integer
          # device_type: <value in [FortiGate, FortiManager, FortiClient, ...]>
          # index_field: <string>
          # log_type: <value in [app-ctrl, attack, content, ...]>
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
        '/cli/global/system/sql/custom-skipidx'
    ]
    module_arg_spec = {
        'system_sql_customskipidx': {
            'type': 'dict', 'v_range': [['6.2.3', '']],
            'options': {
                'device-type': {
                    'v_range': [['6.2.3', '']],
                    'choices': ['FortiGate', 'FortiManager', 'FortiClient', 'FortiMail', 'FortiWeb', 'FortiSandbox', 'FortiProxy'],
                    'type': 'str'
                },
                'id': {'v_range': [['6.2.3', '']], 'required': True, 'type': 'int'},
                'index-field': {'v_range': [['6.2.3', '']], 'type': 'str'},
                'log-type': {
                    'v_range': [['6.2.3', '']],
                    'choices': [
                        'app-ctrl', 'attack', 'content', 'dlp', 'emailfilter', 'event', 'generic', 'history', 'traffic', 'virus', 'voip', 'webfilter',
                        'netscan', 'fct-event', 'fct-traffic', 'fct-netscan', 'waf', 'gtp', 'dns', 'ssh', 'ssl', 'file-filter', 'asset', 'protocol',
                        'siem', 'ztna', 'security'
                    ],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sql_customskipidx'),
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
