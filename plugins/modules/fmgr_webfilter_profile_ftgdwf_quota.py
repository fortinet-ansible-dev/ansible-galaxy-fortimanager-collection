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
module: fmgr_webfilter_profile_ftgdwf_quota
short_description: FortiGuard traffic quota settings.
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    webfilter_profile_ftgdwf_quota:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            category:
                type: raw
                description: (list or str) FortiGuard categories to apply quota to
            duration:
                type: str
                description: Duration of quota.
            id:
                type: int
                description: ID number.
                required: true
            override_replacemsg:
                aliases: ['override-replacemsg']
                type: str
                description: Override replacement message.
            type:
                type: str
                description: Quota type.
                choices: ['time', 'traffic']
            unit:
                type: str
                description: Traffic quota unit of measurement.
                choices: ['B', 'KB', 'MB', 'GB']
            value:
                type: int
                description: Traffic quota value.
            reset_frequency:
                aliases: ['reset-frequency']
                type: str
                description: Quota reset frequency
                choices: ['daily', 'weekly', 'monthly']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: FortiGuard traffic quota settings.
      fortinet.fortimanager.fmgr_webfilter_profile_ftgdwf_quota:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        state: present # <value in [present, absent]>
        webfilter_profile_ftgdwf_quota:
          id: 0 # Required variable, integer
          # category: <list or string>
          # duration: <string>
          # override_replacemsg: <string>
          # type: <value in [time, traffic]>
          # unit: <value in [B, KB, MB, ...]>
          # value: <integer>
          # reset_frequency: <value in [daily, weekly, monthly]>
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
        '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/quota',
        '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/quota'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'webfilter_profile_ftgdwf_quota': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'category': {'type': 'raw'},
                'duration': {'type': 'str'},
                'id': {'required': True, 'type': 'int'},
                'override-replacemsg': {'type': 'str'},
                'type': {'choices': ['time', 'traffic'], 'type': 'str'},
                'unit': {'choices': ['B', 'KB', 'MB', 'GB'], 'type': 'str'},
                'value': {'type': 'int'},
                'reset-frequency': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['daily', 'weekly', 'monthly'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile_ftgdwf_quota'),
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
