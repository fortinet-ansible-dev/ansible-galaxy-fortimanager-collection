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
module: fmgr_pkg_firewall_acl6
short_description: Configure IPv6 access control list.
version_added: "2.1.0"
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_firewall_acl6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comments:
                type: str
                description: Comment.
            dstaddr:
                type: raw
                description: (list) Destination address name.
            interface:
                type: str
                description: Interface name.
            name:
                type: str
                description: Policy name.
            policyid:
                type: int
                description: Policy ID.
                required: true
            service:
                type: raw
                description: (list) Service name.
            srcaddr:
                type: raw
                description: (list) Source address name.
            status:
                type: str
                description: Enable/disable access control list status.
                choices: ['disable', 'enable']
            uuid:
                type: str
                description: Universally Unique Identifier
            fragment:
                type: str
                description: Pass/drop fragments that match L3 information.
                choices: ['pass', 'drop']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv6 access control list.
      fortinet.fortimanager.fmgr_pkg_firewall_acl6:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        pkg: <your own value>
        state: present # <value in [present, absent]>
        pkg_firewall_acl6:
          policyid: 0 # Required variable, integer
          # comments: <string>
          # dstaddr: <list or string>
          # interface: <string>
          # name: <string>
          # service: <list or string>
          # srcaddr: <list or string>
          # status: <value in [disable, enable]>
          # uuid: <string>
          # fragment: <value in [pass, drop]>
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl6'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_acl6': {
            'type': 'dict', 'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'comments': {'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'dstaddr': {'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'raw'},
                'interface': {'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'policyid': {'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'service': {'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'raw'},
                'srcaddr': {'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'raw'},
                'status': {'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['7.2.0', '7.2.0']], 'type': 'str'},
                'fragment': {'v_range': [['7.4.3', '']], 'choices': ['pass', 'drop'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_acl6'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'policyid', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
