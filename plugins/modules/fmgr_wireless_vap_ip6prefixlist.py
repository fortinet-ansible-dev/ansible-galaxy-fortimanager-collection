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
module: fmgr_wireless_vap_ip6prefixlist
short_description: Advertised prefix list.
version_added: "2.10.0"
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
    vap:
        description: The parameter (vap) in requested url.
        type: str
        required: true
    wireless_vap_ip6prefixlist:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            autonomous_flag:
                aliases: ['autonomous-flag']
                type: str
                description: Autonomous flag.
                choices: ['disable', 'enable']
            dnssl:
                type: list
                elements: str
                description: Dnssl.
            onlink_flag:
                aliases: ['onlink-flag']
                type: str
                description: Onlink flag.
                choices: ['disable', 'enable']
            preferred_life_time:
                aliases: ['preferred-life-time']
                type: int
                description: Preferred life time.
            prefix:
                type: str
                description: Prefix.
            rdnss:
                type: list
                elements: str
                description: Rdnss.
            valid_life_time:
                aliases: ['valid-life-time']
                type: int
                description: Valid life time.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Advertised prefix list.
      fortinet.fortimanager.fmgr_wireless_vap_ip6prefixlist:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        vap: <your own value>
        state: present # <value in [present, absent]>
        wireless_vap_ip6prefixlist:
          # autonomous_flag: <value in [disable, enable]>
          # dnssl: <list or string>
          # onlink_flag: <value in [disable, enable]>
          # preferred_life_time: <integer>
          # prefix: <string>
          # rdnss: <list or string>
          # valid_life_time: <integer>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/ip6-prefix-list'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vap': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'wireless_vap_ip6prefixlist': {
            'type': 'dict', 'v_range': [['7.2.10', '7.2.12'], ['7.4.7', '7.4.10'], ['7.6.3', '']],
            'options': {
                'autonomous-flag': {
                    'v_range': [['7.2.10', '7.2.12'], ['7.4.7', '7.4.10'], ['7.6.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'dnssl': {'v_range': [['7.2.10', '7.2.12'], ['7.4.7', '7.4.10'], ['7.6.3', '']], 'type': 'list', 'elements': 'str'},
                'onlink-flag': {'v_range': [['7.2.10', '7.2.12'], ['7.4.7', '7.4.10'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'preferred-life-time': {'v_range': [['7.2.10', '7.2.12'], ['7.4.7', '7.4.10'], ['7.6.3', '']], 'type': 'int'},
                'prefix': {'v_range': [['7.2.10', '7.2.12'], ['7.4.7', '7.4.10'], ['7.6.3', '']], 'type': 'str'},
                'rdnss': {'v_range': [['7.2.10', '7.2.12'], ['7.4.7', '7.4.10'], ['7.6.3', '']], 'type': 'list', 'elements': 'str'},
                'valid-life-time': {'v_range': [['7.2.10', '7.2.12'], ['7.4.7', '7.4.10'], ['7.6.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_vap_ip6prefixlist'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
