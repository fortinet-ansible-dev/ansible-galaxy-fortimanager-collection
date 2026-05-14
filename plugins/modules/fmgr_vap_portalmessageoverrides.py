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
module: fmgr_vap_portalmessageoverrides
short_description: Individual message overrides.
version_added: "2.0.0"
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
    vap:
        description: The parameter (vap) in requested url.
        type: str
        required: true
    vap_portalmessageoverrides:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_disclaimer_page:
                aliases: ['auth-disclaimer-page']
                type: str
                description: Override auth-disclaimer-page message with message from portal-message-overrides group.
            auth_login_failed_page:
                aliases: ['auth-login-failed-page']
                type: str
                description: Override auth-login-failed-page message with message from portal-message-overrides group.
            auth_login_page:
                aliases: ['auth-login-page']
                type: str
                description: Override auth-login-page message with message from portal-message-overrides group.
            auth_reject_page:
                aliases: ['auth-reject-page']
                type: str
                description: Override auth-reject-page message with message from portal-message-overrides group.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Individual message overrides.
      fortinet.fortimanager.fmgr_vap_portalmessageoverrides:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        vap: <your own value>
        vap_portalmessageoverrides:
          # auth_disclaimer_page: <string>
          # auth_login_failed_page: <string>
          # auth_login_page: <string>
          # auth_reject_page: <string>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/portal-message-overrides',
        '/pm/config/global/obj/wireless-controller/vap/{vap}/portal-message-overrides'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vap': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'vap_portalmessageoverrides': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'auth-disclaimer-page': {'type': 'str'},
                'auth-login-failed-page': {'type': 'str'},
                'auth-login-page': {'type': 'str'},
                'auth-reject-page': {'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vap_portalmessageoverrides'),
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
