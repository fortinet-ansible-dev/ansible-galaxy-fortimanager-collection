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
module: fmgr_casb_useractivity
short_description: Configure CASB user activity.
version_added: "2.3.0"
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
  casb_useractivity:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      application:
        type: str
        description: CASB SaaS application name.
      casb_name:
        aliases: ['casb-name']
        type: str
        description: CASB user activity signature name.
      category:
        type: str
        description: CASB user activity category.
        choices: ['activity-control', 'tenant-control', 'domain-control', 'safe-search-control',
                  'other', 'advanced-tenant-control']
      control_options:
        aliases: ['control-options']
        type: list
        elements: dict
        description: Control options.
        suboptions:
          name:
            type: str
            description: CASB control option name.
          operations:
            type: list
            elements: dict
            description: Operations.
            suboptions:
              action:
                type: str
                description: CASB operation action.
                choices: ['append', 'prepend', 'replace', 'new', 'new-on-not-found', 'delete']
              case_sensitive:
                aliases: ['case-sensitive']
                type: str
                description: CASB operation search case sensitive.
                choices: ['disable', 'enable']
              direction:
                type: str
                description: CASB operation direction.
                choices: ['request', 'response']
              header_name:
                aliases: ['header-name']
                type: str
                description: CASB operation header name to search.
              name:
                type: str
                description: CASB control option operation name.
              search_key:
                aliases: ['search-key']
                type: str
                description: CASB operation key to search.
              search_pattern:
                aliases: ['search-pattern']
                type: str
                description: CASB operation search pattern.
                choices: ['simple', 'substr', 'regexp']
              target:
                type: str
                description: CASB operation target.
                choices: ['header', 'path', 'body']
              value_from_input:
                aliases: ['value-from-input']
                type: str
                description: Enable/disable value from user input.
                choices: ['disable', 'enable']
              values:
                type: list
                elements: str
                description: CASB operation new values.
              value_name_from_input:
                aliases: ['value-name-from-input']
                type: str
                description: CASB operation value name from user input.
          status:
            type: str
            description: CASB control option status.
            choices: ['disable', 'enable']
      description:
        type: str
        description: CASB user activity description.
      match:
        type: list
        elements: dict
        description: Match.
        suboptions:
          id:
            type: int
            description: CASB user activity match rules ID.
          rules:
            type: list
            elements: dict
            description: Rules.
            suboptions:
              case_sensitive:
                aliases: ['case-sensitive']
                type: str
                description: CASB user activity match case sensitive.
                choices: ['disable', 'enable']
              domains:
                type: list
                elements: str
                description: CASB user activity domain list.
              header_name:
                aliases: ['header-name']
                type: str
                description: CASB user activity rule header name.
              id:
                type: int
                description: CASB user activity rule ID.
              match_pattern:
                aliases: ['match-pattern']
                type: str
                description: CASB user activity rule match pattern.
                choices: ['simple', 'substr', 'regexp']
              match_value:
                aliases: ['match-value']
                type: str
                description: CASB user activity rule match value.
              methods:
                type: list
                elements: str
                description: CASB user activity method list.
              negate:
                type: str
                description: Enable/disable what the matching strategy must not be.
                choices: ['disable', 'enable']
              type:
                type: str
                description: CASB user activity rule type.
                choices: ['domains', 'host', 'path', 'header', 'header-value', 'method', 'body']
              body_type:
                aliases: ['body-type']
                type: str
                description: CASB user activity match rule body type.
                choices: ['json', 'form']
              jq:
                type: str
                description: CASB user activity rule match jq script.
          strategy:
            type: str
            description: CASB user activity rules strategy.
            choices: ['or', 'and']
          tenant_extraction:
            aliases: ['tenant-extraction']
            type: dict
            description: Tenant extraction.
            suboptions:
              filters:
                type: list
                elements: dict
                description: Filters.
                suboptions:
                  body_type:
                    aliases: ['body-type']
                    type: str
                    description: CASB tenant extraction filter body type.
                    choices: ['json', 'form']
                  direction:
                    type: str
                    description: CASB tenant extraction filter direction.
                    choices: ['request', 'response']
                  header_name:
                    aliases: ['header-name']
                    type: str
                    description: CASB tenant extraction filter header name.
                  id:
                    type: int
                    description: CASB tenant extraction filter ID.
                  place:
                    type: str
                    description: CASB tenant extraction filter place type.
                    choices: ['path', 'header', 'body']
              jq:
                type: str
                description: CASB user activity tenant extraction jq script.
              status:
                type: str
                description: Enable/disable CASB tenant extraction.
                choices: ['disable', 'enable']
              type:
                type: str
                description: CASB user activity tenant extraction type.
                choices: ['json-query']
          tenant_session_extraction:
            aliases: ['tenant-session-extraction']
            type: dict
            description: Tenant session extraction.
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
      match_strategy:
        aliases: ['match-strategy']
        type: str
        description: CASB user activity match strategy.
        choices: ['or', 'and']
      name:
        type: str
        description: CASB user activity name.
        required: true
      type:
        type: str
        description: CASB user activity type.
        choices: ['built-in', 'customized']
      uuid:
        type: str
        description: Universally Unique Identifier
      status:
        type: str
        description: CASB user activity status.
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
        '/pm/config/adom/{adom}/obj/casb/user-activity',
        '/pm/config/global/obj/casb/user-activity'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'casb_useractivity': {
            'type': 'dict', 'v_range': [['7.4.1', '']],
            'options': {
                'application': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'casb-name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'category': {
                    'v_range': [['7.4.1', '']],
                    'choices': ['activity-control', 'tenant-control', 'domain-control', 'safe-search-control', 'other', 'advanced-tenant-control'],
                    'type': 'str'
                },
                'control-options': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'operations': {
                            'v_range': [['7.4.1', '']],
                            'type': 'list',
                            'options': {
                                'action': {
                                    'v_range': [['7.4.1', '']],
                                    'choices': ['append', 'prepend', 'replace', 'new', 'new-on-not-found', 'delete'],
                                    'type': 'str'
                                },
                                'case-sensitive': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'direction': {'v_range': [['7.4.1', '']], 'choices': ['request', 'response'], 'type': 'str'},
                                'header-name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                                'name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                                'search-key': {'v_range': [['7.4.1', '']], 'no_log': True, 'type': 'str'},
                                'search-pattern': {'v_range': [['7.4.1', '']], 'choices': ['simple', 'substr', 'regexp'], 'type': 'str'},
                                'target': {'v_range': [['7.4.1', '']], 'choices': ['header', 'path', 'body'], 'type': 'str'},
                                'value-from-input': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'values': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'str'},
                                'value-name-from-input': {'v_range': [['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'status': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'description': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'match': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'rules': {
                            'v_range': [['7.4.1', '']],
                            'type': 'list',
                            'options': {
                                'case-sensitive': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'domains': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'str'},
                                'header-name': {'v_range': [['7.4.1', '']], 'type': 'str'},
                                'id': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'match-pattern': {'v_range': [['7.4.1', '']], 'choices': ['simple', 'substr', 'regexp'], 'type': 'str'},
                                'match-value': {'v_range': [['7.4.1', '']], 'type': 'str'},
                                'methods': {'v_range': [['7.4.1', '']], 'type': 'list', 'elements': 'str'},
                                'negate': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'type': {
                                    'v_range': [['7.4.1', '']],
                                    'choices': ['domains', 'host', 'path', 'header', 'header-value', 'method', 'body'],
                                    'type': 'str'
                                },
                                'body-type': {'v_range': [['7.6.2', '']], 'choices': ['json', 'form'], 'type': 'str'},
                                'jq': {'v_range': [['7.6.2', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'strategy': {'v_range': [['7.4.1', '']], 'choices': ['or', 'and'], 'type': 'str'},
                        'tenant-extraction': {
                            'v_range': [['7.6.2', '']],
                            'type': 'dict',
                            'options': {
                                'filters': {
                                    'v_range': [['7.6.2', '']],
                                    'type': 'list',
                                    'options': {
                                        'body-type': {'v_range': [['7.6.2', '']], 'choices': ['json', 'form'], 'type': 'str'},
                                        'direction': {'v_range': [['7.6.2', '']], 'choices': ['request', 'response'], 'type': 'str'},
                                        'header-name': {'v_range': [['7.6.2', '']], 'type': 'str'},
                                        'id': {'v_range': [['7.6.2', '']], 'type': 'int'},
                                        'place': {'v_range': [['7.6.2', '']], 'choices': ['path', 'header', 'body'], 'type': 'str'}
                                    },
                                    'elements': 'dict'
                                },
                                'jq': {'v_range': [['7.6.2', '']], 'type': 'str'},
                                'status': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'type': {'v_range': [['7.6.2', '']], 'choices': ['json-query'], 'type': 'str'}
                            }
                        },
                        'tenant-session-extraction': {
                            'v_range': [['8.0.0', '']],
                            'type': 'dict',
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
                    },
                    'elements': 'dict'
                },
                'match-strategy': {'v_range': [['7.4.1', '']], 'choices': ['or', 'and'], 'type': 'str'},
                'name': {'v_range': [['7.4.1', '']], 'required': True, 'type': 'str'},
                'type': {'v_range': [['7.4.1', '']], 'choices': ['built-in', 'customized'], 'type': 'str'},
                'uuid': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'status': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_useractivity'),
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
