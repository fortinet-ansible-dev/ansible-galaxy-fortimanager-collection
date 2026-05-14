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
module: fmgr_antivirus_profile_ssh
short_description: Configure SFTP and SCP AntiVirus options.
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
    antivirus_profile_ssh:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            archive_block:
                aliases: ['archive-block']
                type: list
                elements: str
                description: Select the archive types to block.
                choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb',
                          'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout']
            archive_log:
                aliases: ['archive-log']
                type: list
                elements: str
                description: Select the archive types to log.
                choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb',
                          'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout']
            emulator:
                type: str
                description: Enable/disable the virus emulator.
                choices: ['disable', 'enable']
            options:
                type: list
                elements: str
                description: Enable/disable SFTP and SCP AntiVirus scanning, monitoring, and quarantine.
                choices: ['avmonitor', 'quarantine', 'scan']
            outbreak_prevention:
                aliases: ['outbreak-prevention']
                type: str
                description: Enable Virus Outbreak Prevention service.
                choices: ['disabled', 'files', 'full-archive', 'disable', 'block', 'monitor']
            av_scan:
                aliases: ['av-scan']
                type: str
                description: Enable AntiVirus scan service.
                choices: ['disable', 'monitor', 'block']
            external_blocklist:
                aliases: ['external-blocklist']
                type: str
                description: Enable external-blocklist.
                choices: ['disable', 'monitor', 'block']
            quarantine:
                type: str
                description: Enable/disable quarantine for infected files.
                choices: ['disable', 'enable']
            fortindr:
                type: str
                description: Enable scanning of files by FortiNDR.
                choices: ['disable', 'block', 'monitor']
            fortisandbox:
                type: str
                description: Enable scanning of files by FortiSandbox.
                choices: ['disable', 'block', 'monitor']
            fortiai:
                type: str
                description: Enable/disable scanning of files by FortiAI.
                choices: ['disable', 'monitor', 'block']
            malware_stream:
                aliases: ['malware-stream']
                type: str
                description: Enable 0-day malware-stream scanning.
                choices: ['disable', 'monitor', 'block']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure SFTP and SCP AntiVirus options.
      fortinet.fortimanager.fmgr_antivirus_profile_ssh:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        antivirus_profile_ssh:
          # archive_block: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #                 "unhandled", "partiallycorrupted", "fileslimit", "timeout"]
          # archive_log: ["encrypted", "corrupted", "multipart", "nested", "mailbomb",
          #               "unhandled", "partiallycorrupted", "fileslimit", "timeout"]
          # emulator: <value in [disable, enable]>
          # options: ["avmonitor", "quarantine", "scan"]
          # outbreak_prevention: <value in [disabled, files, full-archive, ...]>
          # av_scan: <value in [disable, monitor, block]>
          # external_blocklist: <value in [disable, monitor, block]>
          # quarantine: <value in [disable, enable]>
          # fortindr: <value in [disable, block, monitor]>
          # fortisandbox: <value in [disable, block, monitor]>
          # fortiai: <value in [disable, monitor, block]>
          # malware_stream: <value in [disable, monitor, block]>
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
        '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/ssh',
        '/pm/config/global/obj/antivirus/profile/{profile}/ssh'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'antivirus_profile_ssh': {
            'type': 'dict', 'v_range': [['6.2.2', '']],
            'options': {
                'archive-block': {
                    'v_range': [['6.2.2', '']],
                    'type': 'list',
                    'choices': ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'],
                    'elements': 'str'
                },
                'archive-log': {
                    'v_range': [['6.2.2', '']],
                    'type': 'list',
                    'choices': ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'],
                    'elements': 'str'
                },
                'emulator': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'options': {'v_range': [['6.2.2', '']], 'type': 'list', 'choices': ['avmonitor', 'quarantine', 'scan'], 'elements': 'str'},
                'outbreak-prevention': {
                    'v_range': [['6.2.2', '']],
                    'choices': ['disabled', 'files', 'full-archive', 'disable', 'block', 'monitor'],
                    'type': 'str'
                },
                'av-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                'external-blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                'quarantine': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortindr': {'v_range': [['7.0.5', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'fortisandbox': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'fortiai': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                'malware-stream': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'antivirus_profile_ssh'),
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
