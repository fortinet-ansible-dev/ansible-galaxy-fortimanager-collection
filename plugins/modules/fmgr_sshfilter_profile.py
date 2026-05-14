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
module: fmgr_sshfilter_profile
short_description: SSH filter profile.
version_added: "2.0.0"
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
    sshfilter_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            block:
                type: list
                elements: str
                description: SSH blocking options.
                choices: ['x11', 'shell', 'exec', 'port-forward', 'tun-forward', 'sftp',
                          'unknown', 'scp']
            default_command_log:
                aliases: ['default-command-log']
                type: str
                description: Enable/disable logging unmatched shell commands.
                choices: ['disable', 'enable']
            log:
                type: list
                elements: str
                description: SSH logging options.
                choices: ['x11', 'shell', 'exec', 'port-forward', 'tun-forward', 'sftp',
                          'unknown', 'scp']
            name:
                type: str
                description: SSH filter profile name.
                required: true
            shell_commands:
                aliases: ['shell-commands']
                type: list
                elements: dict
                description: Shell commands.
                suboptions:
                    action:
                        type: str
                        description: Action to take for URL filter matches.
                        choices: ['block', 'allow']
                    alert:
                        type: str
                        description: Enable/disable alert.
                        choices: ['disable', 'enable']
                    id:
                        type: int
                        description: Id.
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices: ['disable', 'enable']
                    pattern:
                        type: str
                        description: SSH shell command pattern.
                    severity:
                        type: str
                        description: Log severity.
                        choices: ['low', 'medium', 'high', 'critical']
                    type:
                        type: str
                        description: Matching type.
                        choices: ['regex', 'simple']
            file_filter:
                aliases: ['file-filter']
                type: dict
                description: File filter.
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
                            direction:
                                type: str
                                description: Match files transmitted in the sessions originating or reply direction.
                                choices: ['any', 'incoming', 'outgoing']
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
                                choices: ['ssh']
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
    - name: SSH filter profile.
      fortinet.fortimanager.fmgr_sshfilter_profile:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        sshfilter_profile:
          name: "your value" # Required variable, string
          # block: ["x11", "shell", "exec", "port-forward", "tun-forward", "sftp", "unknown",
          #         "scp"]
          # default_command_log: <value in [disable, enable]>
          # log: ["x11", "shell", "exec", "port-forward", "tun-forward", "sftp", "unknown", "scp"]
          # shell_commands:
          #   - action: <value in [block, allow]>
          #     alert: <value in [disable, enable]>
          #     id: <integer>
          #     log: <value in [disable, enable]>
          #     pattern: <string>
          #     severity: <value in [low, medium, high, ...]>
          #     type: <value in [regex, simple]>
          # file_filter:
          #   entries:
          #     - action: <value in [log, block]>
          #       comment: <string>
          #       direction: <value in [any, incoming, outgoing]>
          #       file_type: <list or string>
          #       filter: <string>
          #       password_protected: <value in [any, yes]>
          #       protocol: ["ssh"]
          #   log: <value in [disable, enable]>
          #   scan_archive_contents: <value in [disable, enable]>
          #   status: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/ssh-filter/profile',
        '/pm/config/global/obj/ssh-filter/profile'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'sshfilter_profile': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'block': {'type': 'list', 'choices': ['x11', 'shell', 'exec', 'port-forward', 'tun-forward', 'sftp', 'unknown', 'scp'], 'elements': 'str'},
                'default-command-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log': {'type': 'list', 'choices': ['x11', 'shell', 'exec', 'port-forward', 'tun-forward', 'sftp', 'unknown', 'scp'], 'elements': 'str'},
                'name': {'required': True, 'type': 'str'},
                'shell-commands': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['block', 'allow'], 'type': 'str'},
                        'alert': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'type': 'int'},
                        'log': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'pattern': {'type': 'str'},
                        'severity': {'choices': ['low', 'medium', 'high', 'critical'], 'type': 'str'},
                        'type': {'choices': ['regex', 'simple'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'file-filter': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                    'type': 'dict',
                    'options': {
                        'entries': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'type': 'list',
                            'options': {
                                'action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['log', 'block'], 'type': 'str'},
                                'comment': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'type': 'str'},
                                'direction': {
                                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                                    'choices': ['any', 'incoming', 'outgoing'],
                                    'type': 'str'
                                },
                                'file-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'type': 'raw'},
                                'filter': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'type': 'str'},
                                'password-protected': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['any', 'yes'], 'type': 'str'},
                                'protocol': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'type': 'list', 'choices': ['ssh'], 'elements': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'scan-archive-contents': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'sshfilter_profile'),
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
