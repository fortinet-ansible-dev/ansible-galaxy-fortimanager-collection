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
module: fmgr_webproxy_profile
short_description: Configure web proxy profiles.
version_added: "1.0.0"
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
    webproxy_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            header_client_ip:
                aliases: ['header-client-ip']
                type: str
                description: Action to take on the HTTP client-IP header in forwarded requests
                choices: ['pass', 'add', 'remove']
            header_front_end_https:
                aliases: ['header-front-end-https']
                type: str
                description: Action to take on the HTTP front-end-HTTPS header in forwarded requests
                choices: ['pass', 'add', 'remove']
            header_via_request:
                aliases: ['header-via-request']
                type: str
                description: Action to take on the HTTP via header in forwarded requests
                choices: ['pass', 'add', 'remove']
            header_via_response:
                aliases: ['header-via-response']
                type: str
                description: Action to take on the HTTP via header in forwarded responses
                choices: ['pass', 'add', 'remove']
            header_x_authenticated_groups:
                aliases: ['header-x-authenticated-groups']
                type: str
                description: Action to take on the HTTP x-authenticated-groups header in forwarded requests
                choices: ['pass', 'add', 'remove']
            header_x_authenticated_user:
                aliases: ['header-x-authenticated-user']
                type: str
                description: Action to take on the HTTP x-authenticated-user header in forwarded requests
                choices: ['pass', 'add', 'remove']
            header_x_forwarded_for:
                aliases: ['header-x-forwarded-for']
                type: str
                description: Action to take on the HTTP x-forwarded-for header in forwarded requests
                choices: ['pass', 'add', 'remove']
            headers:
                type: list
                elements: dict
                description: Headers.
                suboptions:
                    action:
                        type: str
                        description: Action when HTTP the header forwarded.
                        choices: ['add-to-request', 'add-to-response', 'remove-from-request',
                                  'remove-from-response', 'monitor-request', 'monitor-response']
                    content:
                        type: str
                        description: HTTP headers content.
                    id:
                        type: int
                        description: HTTP forwarded header id.
                    name:
                        type: str
                        description: HTTP forwarded header name.
                    add_option:
                        aliases: ['add-option']
                        type: str
                        description: Configure options to append content to existing HTTP header or add new HTTP header.
                        choices: ['append', 'new-on-not-found', 'new', 'replace',
                                  'replace-when-match']
                    base64_encoding:
                        aliases: ['base64-encoding']
                        type: str
                        description: Enable/disable use of base64 encoding of HTTP content.
                        choices: ['disable', 'enable']
                    dstaddr:
                        type: raw
                        description: (list or str) Destination address and address group names.
                    dstaddr6:
                        type: raw
                        description: (list or str) Destination address and address group names
                    protocol:
                        type: list
                        elements: str
                        description: Configure protocol
                        choices: ['https', 'http']
            log_header_change:
                aliases: ['log-header-change']
                type: str
                description: Enable/disable logging HTTP header changes.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Profile name.
                required: true
            strip_encoding:
                aliases: ['strip-encoding']
                type: str
                description: Enable/disable stripping unsupported encoding from the request header.
                choices: ['disable', 'enable']
            header_x_forwarded_client_cert:
                aliases: ['header-x-forwarded-client-cert']
                type: str
                description: Action to take on the HTTP x-forwarded-client-cert header in forwarded requests
                choices: ['pass', 'add', 'remove']
            max_cache_object_size:
                aliases: ['max-cache-object-size']
                type: int
                description: Max cache object size.
            header_client_cert:
                aliases: ['header-client-cert']
                type: str
                description: Action to take on the HTTP Client-Cert/Client-Cert-Chain headers in forwarded responses
                choices: ['pass', 'add', 'remove']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure web proxy profiles.
      fortinet.fortimanager.fmgr_webproxy_profile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        webproxy_profile:
          name: "your value" # Required variable, string
          # header_client_ip: <value in [pass, add, remove]>
          # header_front_end_https: <value in [pass, add, remove]>
          # header_via_request: <value in [pass, add, remove]>
          # header_via_response: <value in [pass, add, remove]>
          # header_x_authenticated_groups: <value in [pass, add, remove]>
          # header_x_authenticated_user: <value in [pass, add, remove]>
          # header_x_forwarded_for: <value in [pass, add, remove]>
          # headers:
          #   - action: <value in [add-to-request, add-to-response, remove-from-request, ...]>
          #     content: <string>
          #     id: <integer>
          #     name: <string>
          #     add_option: <value in [append, new-on-not-found, new, ...]>
          #     base64_encoding: <value in [disable, enable]>
          #     dstaddr: <list or string>
          #     dstaddr6: <list or string>
          #     protocol: ["https", "http"]
          # log_header_change: <value in [disable, enable]>
          # strip_encoding: <value in [disable, enable]>
          # header_x_forwarded_client_cert: <value in [pass, add, remove]>
          # max_cache_object_size: <integer>
          # header_client_cert: <value in [pass, add, remove]>
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
        '/pm/config/adom/{adom}/obj/web-proxy/profile',
        '/pm/config/global/obj/web-proxy/profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'webproxy_profile': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'header-client-ip': {'choices': ['pass', 'add', 'remove'], 'type': 'str'},
                'header-front-end-https': {'choices': ['pass', 'add', 'remove'], 'type': 'str'},
                'header-via-request': {'choices': ['pass', 'add', 'remove'], 'type': 'str'},
                'header-via-response': {'choices': ['pass', 'add', 'remove'], 'type': 'str'},
                'header-x-authenticated-groups': {'choices': ['pass', 'add', 'remove'], 'type': 'str'},
                'header-x-authenticated-user': {'choices': ['pass', 'add', 'remove'], 'type': 'str'},
                'header-x-forwarded-for': {'choices': ['pass', 'add', 'remove'], 'type': 'str'},
                'headers': {
                    'type': 'list',
                    'options': {
                        'action': {
                            'choices': [
                                'add-to-request', 'add-to-response', 'remove-from-request', 'remove-from-response', 'monitor-request',
                                'monitor-response'
                            ],
                            'type': 'str'
                        },
                        'content': {'type': 'str'},
                        'id': {'type': 'int'},
                        'name': {'type': 'str'},
                        'add-option': {
                            'v_range': [['6.2.0', '']],
                            'choices': ['append', 'new-on-not-found', 'new', 'replace', 'replace-when-match'],
                            'type': 'str'
                        },
                        'base64-encoding': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dstaddr': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                        'dstaddr6': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                        'protocol': {'v_range': [['6.2.0', '']], 'type': 'list', 'choices': ['https', 'http'], 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'log-header-change': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'strip-encoding': {'choices': ['disable', 'enable'], 'type': 'str'},
                'header-x-forwarded-client-cert': {'v_range': [['7.0.1', '']], 'choices': ['pass', 'add', 'remove'], 'type': 'str'},
                'max-cache-object-size': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'header-client-cert': {'v_range': [['7.6.5', '']], 'choices': ['pass', 'add', 'remove'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webproxy_profile'),
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
