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
module: fmgr_emailfilter_profile_filefilter
short_description: File filter.
version_added: "2.1.0"
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    emailfilter_profile_filefilter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    action:
                        type: str
                        description: Action taken for matched file.
                        choices: ['log', 'block']
                    comment:
                        type: str
                        description: Comment.
                    encryption:
                        type: str
                        description: Match encrypted files or not.
                        choices: ['any', 'yes']
                    file_type:
                        aliases: ['file-type']
                        type: raw
                        description: (list) Select file type.
                    filter:
                        type: str
                        description: Add a file filter.
                    password_protected:
                        aliases: ['password-protected']
                        type: str
                        description: Match password-protected files.
                        choices: ['any', 'yes']
                    protocol:
                        type: list
                        elements: str
                        description: Protocols to apply with.
                        choices: ['smtp', 'imap', 'pop3']
            log:
                type: str
                description: Enable/disable file filter logging.
                choices: ['disable', 'enable']
            scan_archive_contents:
                aliases: ['scan-archive-contents']
                type: str
                description: Enable/disable file filter archive contents scan.
                choices: ['disable', 'enable']
            status:
                type: str
                description: Enable/disable file filter.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: File filter.
      fortinet.fortimanager.fmgr_emailfilter_profile_filefilter:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        emailfilter_profile_filefilter:
          # entries:
          #   - action: <value in [log, block]>
          #     comment: <string>
          #     encryption: <value in [any, yes]>
          #     file_type: <list or string>
          #     filter: <string>
          #     password_protected: <value in [any, yes]>
          #     protocol: ["smtp", "imap", "pop3"]
          # log: <value in [disable, enable]>
          # scan_archive_contents: <value in [disable, enable]>
          # status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/file-filter',
        '/pm/config/global/obj/emailfilter/profile/{profile}/file-filter'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'emailfilter_profile_filefilter': {
            'type': 'dict', 'v_range': [['6.2.0', '7.6.2']],
            'options': {
                'entries': {
                    'v_range': [['6.2.0', '7.6.2']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['log', 'block'], 'type': 'str'},
                        'comment': {'v_range': [['6.2.0', '7.6.2']], 'type': 'str'},
                        'encryption': {'v_range': [['6.2.0', '7.2.0']], 'choices': ['any', 'yes'], 'type': 'str'},
                        'file-type': {'v_range': [['6.2.0', '7.6.2']], 'type': 'raw'},
                        'filter': {'v_range': [['6.2.0', '7.6.2']], 'type': 'str'},
                        'password-protected': {'v_range': [['6.2.1', '7.6.2']], 'choices': ['any', 'yes'], 'type': 'str'},
                        'protocol': {'v_range': [['6.2.0', '7.6.2']], 'type': 'list', 'choices': ['smtp', 'imap', 'pop3'], 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'log': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'scan-archive-contents': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['6.2.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'emailfilter_profile_filefilter'),
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
