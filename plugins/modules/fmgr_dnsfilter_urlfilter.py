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
module: fmgr_dnsfilter_urlfilter
short_description: Configure URL filter list.
version_added: "2.2.0"
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
    dnsfilter_urlfilter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    action:
                        type: str
                        description: Action to take for filter matches.
                        choices: ['allow', 'monitor', 'block']
                    id:
                        type: int
                        description: Id.
                    status:
                        type: str
                        description: Enable/disable status.
                        choices: ['disable', 'enable']
                    type:
                        type: str
                        description: Filter type.
                        choices: ['wildcard', 'regex', 'simple']
                    url:
                        type: str
                        description: URL entries to be filtered.
            id:
                type: int
                description: ID.
                required: true
            name:
                type: str
                description: Name of table.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure URL filter list.
      fortinet.fortimanager.fmgr_dnsfilter_urlfilter:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        dnsfilter_urlfilter:
          id: 0 # Required variable, integer
          # comment: <string>
          # entries:
          #   - action: <value in [allow, monitor, block]>
          #     id: <integer>
          #     status: <value in [disable, enable]>
          #     type: <value in [wildcard, regex, simple]>
          #     url: <string>
          # name: <string>
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
        '/pm/config/adom/{adom}/obj/dnsfilter/urlfilter',
        '/pm/config/global/obj/dnsfilter/urlfilter'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dnsfilter_urlfilter': {
            'type': 'dict', 'v_range': [['6.2.0', '6.2.13']],
            'options': {
                'comment': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'entries': {
                    'v_range': [['6.2.0', '6.2.13']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['allow', 'monitor', 'block'], 'type': 'str'},
                        'id': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'},
                        'status': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['wildcard', 'regex', 'simple'], 'type': 'str'},
                        'url': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['6.2.0', '6.2.13']], 'required': True, 'type': 'int'},
                'name': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dnsfilter_urlfilter'),
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
