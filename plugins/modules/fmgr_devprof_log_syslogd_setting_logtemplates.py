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
module: fmgr_devprof_log_syslogd_setting_logtemplates
short_description: System template log syslogd setting log templates
version_added: "2.12.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.full_crud
options:
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_log_syslogd_setting_logtemplates:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            category:
                type: str
                description: Category.
                choices: ['app-ctrl', 'attack', 'dlp', 'event', 'traffic', 'virus', 'voip',
                          'webfilter', 'spam', 'anomaly', 'waf', 'dns', 'ssh', 'ssl',
                          'file-filter', 'icap', 'virtual-patch']
            empty_value_indicator:
                aliases: ['empty-value-indicator']
                type: str
                description: Empty value indicator.
            id:
                type: int
                description: Id.
                required: true
            template:
                type: str
                description: Template.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: System template log syslogd setting log templates
      fortinet.fortimanager.fmgr_devprof_log_syslogd_setting_logtemplates:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        devprof: <your own value>
        state: present # <value in [present, absent]>
        devprof_log_syslogd_setting_logtemplates:
          id: 0 # Required variable, integer
          # category: <value in [app-ctrl, attack, dlp, ...]>
          # empty_value_indicator: <string>
          # template: <string>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/setting/log-templates'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_log_syslogd_setting_logtemplates': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'category': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': [
                        'app-ctrl', 'attack', 'dlp', 'event', 'traffic', 'virus', 'voip', 'webfilter', 'spam', 'anomaly', 'waf', 'dns', 'ssh', 'ssl',
                        'file-filter', 'icap', 'virtual-patch'
                    ],
                    'type': 'str'
                },
                'empty-value-indicator': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'template': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_log_syslogd_setting_logtemplates'),
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
