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
module: fmgr_firewall_explicitproxyaddress
short_description: Explicit web proxy address configuration.
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
    firewall_explicitproxyaddress:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            case_sensitivity:
                aliases: ['case-sensitivity']
                type: str
                description: Case sensitivity in pattern.
                choices: ['disable', 'enable']
            category:
                type: str
                description: FortiGuard category ID.
            color:
                type: int
                description: GUI icon color.
            comment:
                type: str
                description: Comment.
            header:
                type: str
                description: HTTP header regular expression.
            header_group:
                aliases: ['header-group']
                type: list
                elements: dict
                description: Header group.
                suboptions:
                    case_sensitivity:
                        aliases: ['case-sensitivity']
                        type: str
                        description: Case sensitivity in pattern.
                        choices: ['disable', 'enable']
                    header:
                        type: str
                        description: HTTP header regular expression.
                    header_name:
                        aliases: ['header-name']
                        type: str
                        description: HTTP header.
                    id:
                        type: int
                        description: ID.
            header_name:
                aliases: ['header-name']
                type: str
                description: HTTP header.
            host:
                type: str
                description: Host address
            host_regex:
                aliases: ['host-regex']
                type: str
                description: Host regular expression.
            method:
                type: list
                elements: str
                description: HTTP methods.
                choices: ['delete', 'get', 'head', 'options', 'post', 'put', 'trace', 'connect']
            name:
                type: str
                description: Address name.
                required: true
            path:
                type: str
                description: URL path regular expression.
            tags:
                type: str
                description: Applied object tags.
            type:
                type: str
                description: Address type.
                choices: ['host-regex', 'url', 'category', 'method', 'ua', 'header',
                          'src-advanced', 'dst-advanced']
            ua:
                type: list
                elements: str
                description: User agent.
                choices: ['chrome', 'ms', 'firefox', 'safari', 'other']
            uuid:
                type: str
                description: Universally Unique IDentifier.
            visibility:
                type: str
                description: Enable/disable address visibility.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Explicit web proxy address configuration.
      fortinet.fortimanager.fmgr_firewall_explicitproxyaddress:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        firewall_explicitproxyaddress:
          name: "your value" # Required variable, string
          # case_sensitivity: <value in [disable, enable]>
          # category: <string>
          # color: <integer>
          # comment: <string>
          # header: <string>
          # header_group:
          #   - case_sensitivity: <value in [disable, enable]>
          #     header: <string>
          #     header_name: <string>
          #     id: <integer>
          # header_name: <string>
          # host: <string>
          # host_regex: <string>
          # method: ["delete", "get", "head", "options", "post", "put", "trace", "connect"]
          # path: <string>
          # tags: <string>
          # type: <value in [host-regex, url, category, ...]>
          # ua: ["chrome", "ms", "firefox", "safari", "other"]
          # uuid: <string>
          # visibility: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-address',
        '/pm/config/global/obj/firewall/explicit-proxy-address'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_explicitproxyaddress': {
            'type': 'dict', 'v_range': [['6.2.0', '6.2.13']],
            'options': {
                'case-sensitivity': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'category': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'color': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'},
                'comment': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'header': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'header-group': {
                    'v_range': [['6.2.0', '6.2.13']],
                    'type': 'list',
                    'options': {
                        'case-sensitivity': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'header': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'header-name': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'id': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'header-name': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'host': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'host-regex': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'method': {
                    'v_range': [['6.2.0', '6.2.13']],
                    'type': 'list',
                    'choices': ['delete', 'get', 'head', 'options', 'post', 'put', 'trace', 'connect'],
                    'elements': 'str'
                },
                'name': {'v_range': [['6.2.0', '6.2.13']], 'required': True, 'type': 'str'},
                'path': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'tags': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'type': {
                    'v_range': [['6.2.0', '6.2.13']],
                    'choices': ['host-regex', 'url', 'category', 'method', 'ua', 'header', 'src-advanced', 'dst-advanced'],
                    'type': 'str'
                },
                'ua': {'v_range': [['6.2.0', '6.2.13']], 'type': 'list', 'choices': ['chrome', 'ms', 'firefox', 'safari', 'other'], 'elements': 'str'},
                'uuid': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'visibility': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_explicitproxyaddress'),
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
