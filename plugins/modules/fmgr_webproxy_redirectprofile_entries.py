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
module: fmgr_webproxy_redirectprofile_entries
short_description: Web proxy redirect profile entries
version_added: "2.12.0"
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
    redirect-profile:
        description: Deprecated, please use "redirect_profile"
        type: str
    redirect_profile:
        description: The parameter (redirect-profile) in requested url.
        type: str
    webproxy_redirectprofile_entries:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            id:
                type: int
                description: Id.
                required: true
            redirect_code:
                aliases: ['redirect-code']
                type: str
                description: Redirect code.
                choices: ['auto', '301', '302', '303', '307', '308']
            redirect_url:
                aliases: ['redirect-url']
                type: str
                description: Redirect url.
            type:
                type: str
                description: Type.
                choices: ['wildcard', 'regex', 'simple']
            url:
                type: str
                description: Url.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Web proxy redirect profile entries
      fortinet.fortimanager.fmgr_webproxy_redirectprofile_entries:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        redirect_profile: <your own value>
        state: present # <value in [present, absent]>
        webproxy_redirectprofile_entries:
          id: 0 # Required variable, integer
          # redirect_code: <value in [auto, 301, 302, ...]>
          # redirect_url: <string>
          # type: <value in [wildcard, regex, simple]>
          # url: <string>
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
        '/pm/config/adom/{adom}/obj/web-proxy/redirect-profile/{redirect-profile}/entries',
        '/pm/config/global/obj/web-proxy/redirect-profile/{redirect-profile}/entries'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'redirect-profile': {'type': 'str', 'api_name': 'redirect_profile'},
        'redirect_profile': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'webproxy_redirectprofile_entries': {
            'type': 'dict', 'v_range': [['7.6.4', '']],
            'options': {
                'id': {'v_range': [['7.6.4', '']], 'required': True, 'type': 'int'},
                'redirect-code': {'v_range': [['7.6.4', '']], 'choices': ['auto', '301', '302', '303', '307', '308'], 'type': 'str'},
                'redirect-url': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'type': {'v_range': [['7.6.4', '']], 'choices': ['wildcard', 'regex', 'simple'], 'type': 'str'},
                'url': {'v_range': [['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webproxy_redirectprofile_entries'),
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
