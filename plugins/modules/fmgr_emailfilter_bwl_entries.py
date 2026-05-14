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
module: fmgr_emailfilter_bwl_entries
short_description: Anti-spam black/white list entries.
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
    bwl:
        description: The parameter (bwl) in requested url.
        type: str
        required: true
    emailfilter_bwl_entries:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Reject, mark as spam or good email.
                choices: ['spam', 'clear', 'reject']
            addr_type:
                aliases: ['addr-type']
                type: str
                description: IP address type.
                choices: ['ipv4', 'ipv6']
            email_pattern:
                aliases: ['email-pattern']
                type: str
                description: Email address pattern.
            id:
                type: int
                description: Entry ID.
                required: true
            ip4_subnet:
                aliases: ['ip4-subnet']
                type: str
                description: IPv4 network address/subnet mask bits.
            ip6_subnet:
                aliases: ['ip6-subnet']
                type: str
                description: IPv6 network address/subnet mask bits.
            pattern_type:
                aliases: ['pattern-type']
                type: str
                description: Wildcard pattern or regular expression.
                choices: ['wildcard', 'regexp']
            status:
                type: str
                description: Enable/disable status.
                choices: ['disable', 'enable']
            type:
                type: str
                description: Entry type.
                choices: ['ip', 'email']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Anti-spam black/white list entries.
      fortinet.fortimanager.fmgr_emailfilter_bwl_entries:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        bwl: <your own value>
        state: present # <value in [present, absent]>
        emailfilter_bwl_entries:
          id: 0 # Required variable, integer
          # action: <value in [spam, clear, reject]>
          # addr_type: <value in [ipv4, ipv6]>
          # email_pattern: <string>
          # ip4_subnet: <string>
          # ip6_subnet: <string>
          # pattern_type: <value in [wildcard, regexp]>
          # status: <value in [disable, enable]>
          # type: <value in [ip, email]>
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
        '/pm/config/adom/{adom}/obj/emailfilter/bwl/{bwl}/entries',
        '/pm/config/global/obj/emailfilter/bwl/{bwl}/entries'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'bwl': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'emailfilter_bwl_entries': {
            'type': 'dict', 'v_range': [['6.2.0', '']],
            'options': {
                'action': {'v_range': [['6.2.0', '']], 'choices': ['spam', 'clear', 'reject'], 'type': 'str'},
                'addr-type': {'v_range': [['6.2.0', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'email-pattern': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'id': {'v_range': [['6.2.0', '']], 'required': True, 'type': 'int'},
                'ip4-subnet': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'ip6-subnet': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'pattern-type': {'v_range': [['6.2.0', '']], 'choices': ['wildcard', 'regexp'], 'type': 'str'},
                'status': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['6.2.0', '']], 'choices': ['ip', 'email'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'emailfilter_bwl_entries'),
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
