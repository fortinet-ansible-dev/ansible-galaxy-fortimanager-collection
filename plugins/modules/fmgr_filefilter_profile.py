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
module: fmgr_filefilter_profile
short_description: Configure file-filter profiles.
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
    filefilter_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            extended_log:
                aliases: ['extended-log']
                type: str
                description: Enable/disable file-filter extended logging.
                choices: ['disable', 'enable']
            feature_set:
                aliases: ['feature-set']
                type: str
                description: Flow/proxy feature set.
                choices: ['proxy', 'flow']
            log:
                type: str
                description: Enable/disable file-filter logging.
                choices: ['disable', 'enable']
            name:
                type: str
                description: Profile name.
                required: true
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: str
                description: Replacement message group
            rules:
                type: list
                elements: dict
                description: Rules.
                suboptions:
                    action:
                        type: str
                        description: Action taken for matched file.
                        choices: ['log-only', 'block']
                    comment:
                        type: str
                        description: Comment.
                    direction:
                        type: str
                        description: Traffic direction.
                        choices: ['any', 'incoming', 'outgoing']
                    file_type:
                        aliases: ['file-type']
                        type: raw
                        description: (list) Select file type.
                    name:
                        type: str
                        description: File-filter rule name.
                    password_protected:
                        aliases: ['password-protected']
                        type: str
                        description: Match password-protected files.
                        choices: ['any', 'yes']
                    protocol:
                        type: list
                        elements: str
                        description: Protocols to apply rule to.
                        choices: ['imap', 'smtp', 'pop3', 'http', 'ftp', 'mapi', 'cifs', 'ssh']
            scan_archive_contents:
                aliases: ['scan-archive-contents']
                type: str
                description: Enable/disable archive contents scan.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure file-filter profiles.
      fortinet.fortimanager.fmgr_filefilter_profile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        filefilter_profile:
          name: "your value" # Required variable, string
          # comment: <string>
          # extended_log: <value in [disable, enable]>
          # feature_set: <value in [proxy, flow]>
          # log: <value in [disable, enable]>
          # replacemsg_group: <string>
          # rules:
          #   - action: <value in [log-only, block]>
          #     comment: <string>
          #     direction: <value in [any, incoming, outgoing]>
          #     file_type: <list or string>
          #     name: <string>
          #     password_protected: <value in [any, yes]>
          #     protocol: ["imap", "smtp", "pop3", "http", "ftp", "mapi", "cifs", "ssh"]
          # scan_archive_contents: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/file-filter/profile',
        '/pm/config/global/obj/file-filter/profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'filefilter_profile': {
            'type': 'dict', 'v_range': [['6.4.1', '']],
            'options': {
                'comment': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'extended-log': {'v_range': [['6.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'feature-set': {'v_range': [['6.4.1', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                'log': {'v_range': [['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['6.4.1', '']], 'required': True, 'type': 'str'},
                'replacemsg-group': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'rules': {
                    'v_range': [['6.4.1', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.4.1', '']], 'choices': ['log-only', 'block'], 'type': 'str'},
                        'comment': {'v_range': [['6.4.1', '']], 'type': 'str'},
                        'direction': {'v_range': [['6.4.1', '']], 'choices': ['any', 'incoming', 'outgoing'], 'type': 'str'},
                        'file-type': {'v_range': [['6.4.1', '']], 'type': 'raw'},
                        'name': {'v_range': [['6.4.1', '']], 'type': 'str'},
                        'password-protected': {'v_range': [['6.4.1', '']], 'choices': ['any', 'yes'], 'type': 'str'},
                        'protocol': {
                            'v_range': [['6.4.1', '']],
                            'type': 'list',
                            'choices': ['imap', 'smtp', 'pop3', 'http', 'ftp', 'mapi', 'cifs', 'ssh'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'scan-archive-contents': {'v_range': [['6.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'filefilter_profile'),
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
