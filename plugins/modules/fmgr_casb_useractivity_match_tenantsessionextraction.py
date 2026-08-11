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
module: fmgr_casb_useractivity_match_tenantsessionextraction
short_description: CASB user activity tenant session extraction.
version_added: "2.15.0"
extends_documentation_fragment:
  - fortinet.fortimanager.general
  - fortinet.fortimanager.general.partial_crud
options:
  revision_note:
    description: The change note that can be specified when an object is created or updated.
    type: str
  adom:
    description: The parameter (adom) in requested url.
    type: str
    required: true
  user-activity:
    description: Deprecated, please use "user_activity"
    type: str
  user_activity:
    description: The parameter (user-activity) in requested url.
    type: str
  match:
    description: The parameter (match) in requested url.
    type: str
    required: true
  casb_useractivity_match_tenantsessionextraction:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      filters:
        type: list
        elements: dict
        description: Filters.
        suboptions:
          body_type:
            aliases: ['body-type']
            type: str
            description: CASB content extraction filter body type.
            choices: ['json', 'form']
          cookie_name:
            aliases: ['cookie-name']
            type: str
            description: CASB content extraction filter cookie name.
          direction:
            type: str
            description: CASB content extraction filter direction.
            choices: ['request', 'response']
          header_name:
            aliases: ['header-name']
            type: str
            description: CASB content extraction filter header name.
          id:
            type: int
            description: CASB content extraction filter ID.
          place:
            type: str
            description: CASB content extraction filter place type.
            choices: ['header', 'path', 'body', 'cookie']
      jq:
        type: str
        description: CASB user activity session extraction jq script.
      session_match:
        aliases: ['session-match']
        type: str
        description: CASB user activity session match name.
      session_source:
        aliases: ['session-source']
        type: str
        description: Enable/disable CASB session extraction source flag.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable CASB session extraction.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Test CASB tenant session extraction
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create the parent CASB user activity
      fortinet.fortimanager.fmgr_casb_useractivity:
        enable_log: true
        adom: root
        state: present
        casb_useractivity:
          name: test_user_activity

    - name: Create the parent CASB user activity match
      fortinet.fortimanager.fmgr_casb_useractivity_match:
        enable_log: true
        adom: root
        user_activity: test_user_activity
        state: present
        casb_useractivity_match:
          id: 1

    - name: Configure CASB tenant session extraction
      fortinet.fortimanager.fmgr_casb_useractivity_match_tenantsessionextraction:
        enable_log: true
        adom: root
        user_activity: test_user_activity
        match: "1"
        casb_useractivity_match_tenantsessionextraction:
          status: disable

- name: Test CASB tenant session extraction filters
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create the parent CASB user activity
      fortinet.fortimanager.fmgr_casb_useractivity:
        enable_log: true
        adom: root
        state: present
        casb_useractivity:
          name: test_user_activity

    - name: Create the parent CASB user activity match
      fortinet.fortimanager.fmgr_casb_useractivity_match:
        enable_log: true
        adom: root
        user_activity: test_user_activity
        state: present
        casb_useractivity_match:
          id: 1

    - name: Configure the parent CASB tenant session extraction
      fortinet.fortimanager.fmgr_casb_useractivity_match_tenantsessionextraction:
        enable_log: true
        adom: root
        user_activity: test_user_activity
        match: "1"
        casb_useractivity_match_tenantsessionextraction:
          status: enable

    - name: Configure a CASB tenant session extraction filter
      fortinet.fortimanager.fmgr_casb_useractivity_match_tenantsessionextraction_filters:
        enable_log: true
        adom: root
        user_activity: test_user_activity
        match: "1"
        state: present
        casb_useractivity_match_tenantsessionextraction_filters:
          id: 1
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
        '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}/tenant-session-extraction',
        '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}/tenant-session-extraction'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'user-activity': {'type': 'str', 'api_name': 'user_activity'},
        'user_activity': {'type': 'str'},
        'match': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'casb_useractivity_match_tenantsessionextraction': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'filters': {
                    'v_range': [['8.0.0', '']],
                    'type': 'list',
                    'options': {
                        'body-type': {'v_range': [['8.0.0', '']], 'choices': ['json', 'form'], 'type': 'str'},
                        'cookie-name': {'v_range': [['8.0.0', '']], 'type': 'str'},
                        'direction': {'v_range': [['8.0.0', '']], 'choices': ['request', 'response'], 'type': 'str'},
                        'header-name': {'v_range': [['8.0.0', '']], 'type': 'str'},
                        'id': {'v_range': [['8.0.0', '']], 'type': 'int'},
                        'place': {'v_range': [['8.0.0', '']], 'choices': ['header', 'path', 'body', 'cookie'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'jq': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'session-match': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'session-source': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_useractivity_match_tenantsessionextraction'),
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
