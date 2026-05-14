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
module: fmgr_system_sql_customindex
short_description: List of SQL index fields.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    system_sql_customindex:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            case_sensitive:
                aliases: ['case-sensitive']
                type: str
                description:
                    - Disable/Enable case sensitive index.
                    - disable - Build a case insensitive index.
                    - enable - Build a case sensitive index.
                choices: ['disable', 'enable']
            device_type:
                aliases: ['device-type']
                type: str
                description:
                    - Device type.
                    - FortiGate - Device type to FortiGate.
                    - FortiManager - Set device type to FortiManager
                    - FortiClient - Set device type to FortiClient
                    - FortiMail - Device type to FortiMail.
                    - FortiWeb - Device type to FortiWeb.
                    - FortiCache - Set device type to FortiCache
                    - FortiSandbox - Set device type to FortiSandbox
                    - FortiDDoS - Set device type to FortiDDoS
                    - FortiAuthenticator - Set device type to FortiAuthenticator
                    - FortiProxy - Set device type to FortiProxy
                choices: ['FortiGate', 'FortiManager', 'FortiClient', 'FortiMail', 'FortiWeb',
                          'FortiCache', 'FortiSandbox', 'FortiDDoS', 'FortiAuthenticator',
                          'FortiProxy']
            id:
                type: int
                description: Add or Edit log index fields.
                required: true
            index_field:
                aliases: ['index-field']
                type: str
                description: Log field name to be indexed.
            log_type:
                aliases: ['log-type']
                type: str
                description:
                    - Log type.
                    - none - none
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
                choices: ['none', 'app-ctrl', 'attack', 'content', 'dlp', 'emailfilter', 'event',
                          'generic', 'history', 'traffic', 'virus', 'voip', 'webfilter',
                          'netscan', 'fct-event', 'fct-traffic', 'fct-netscan', 'waf', 'gtp',
                          'dns', 'ssh', 'ssl', 'file-filter', 'asset', 'protocol', 'siem', 'ztna',
                          'security']
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: List of SQL index fields.
      fortinet.fortimanager.fmgr_system_sql_customindex:
        bypass_validation: false
        state: present
        system_sql_customindex:
          case_sensitive: disable
          device_type: FortiGate # <value in [FortiGate, FortiManager, FortiClient, ...]>
          id: 1
          index_field: srcip
          log_type: attack # <value in [none, app-ctrl, attack, ...]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the SQL index fields
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_sql_customindex"
          params:
            custom_index: "your_value"
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
        '/cli/global/system/sql/custom-index'
    ]
    module_arg_spec = {
        'system_sql_customindex': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'case-sensitive': {'choices': ['disable', 'enable'], 'type': 'str'},
                'device-type': {
                    'choices': [
                        'FortiGate', 'FortiManager', 'FortiClient', 'FortiMail', 'FortiWeb', 'FortiCache', 'FortiSandbox', 'FortiDDoS',
                        'FortiAuthenticator', 'FortiProxy'
                    ],
                    'type': 'str'
                },
                'id': {'required': True, 'type': 'int'},
                'index-field': {'type': 'str'},
                'log-type': {
                    'choices': [
                        'none', 'app-ctrl', 'attack', 'content', 'dlp', 'emailfilter', 'event', 'generic', 'history', 'traffic', 'virus', 'voip',
                        'webfilter', 'netscan', 'fct-event', 'fct-traffic', 'fct-netscan', 'waf', 'gtp', 'dns', 'ssh', 'ssl', 'file-filter', 'asset',
                        'protocol', 'siem', 'ztna', 'security'
                    ],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sql_customindex'),
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
