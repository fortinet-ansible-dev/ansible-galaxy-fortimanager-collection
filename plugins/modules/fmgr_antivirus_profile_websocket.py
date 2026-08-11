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
module: fmgr_antivirus_profile_websocket
short_description: Configure WEBSOCKET AntiVirus options.
version_added: "2.15.0"
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
  antivirus_profile_websocket:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      archive_block:
        aliases: ['archive-block']
        type: list
        elements: str
        description: Select the archive types to block.
        choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                  'partiallycorrupted', 'timeout']
      archive_log:
        aliases: ['archive-log']
        type: list
        elements: str
        description: Select the archive types to log.
        choices: ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled',
                  'partiallycorrupted', 'timeout']
      av_scan:
        aliases: ['av-scan']
        type: str
        description: Enable/disable AntiVirus scan service.
        choices: ['disable', 'block', 'monitor']
      emulator:
        type: str
        description: Enable/disable the virus emulator.
        choices: ['disable', 'enable']
      external_blocklist:
        aliases: ['external-blocklist']
        type: str
        description: Enable/disable external-blocklist.
        choices: ['disable', 'block', 'monitor']
      fortindr:
        type: str
        description: Enable/disable scanning of files by FortiNDR.
        choices: ['disable', 'block', 'monitor']
      fortisandbox:
        type: str
        description: Enable/disable scanning of files by FortiSandbox.
        choices: ['disable', 'block', 'monitor']
      malware_stream:
        aliases: ['malware-stream']
        type: str
        description: Enable/disable 0-day malware-stream scanning.
        choices: ['disable', 'block', 'monitor']
      outbreak_prevention:
        aliases: ['outbreak-prevention']
        type: str
        description: Enable/disable virus outbreak prevention service.
        choices: ['disable', 'block', 'monitor']
      quarantine:
        type: str
        description: Enable/disable quarantine for infected files.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Test antivirus profile WebSocket settings
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create the parent antivirus profile
      fortinet.fortimanager.fmgr_antivirus_profile:
        enable_log: true
        adom: root
        state: present
        antivirus_profile:
          name: test_profile

    - name: Configure antivirus profile WebSocket settings
      fortinet.fortimanager.fmgr_antivirus_profile_websocket:
        enable_log: true
        adom: root
        profile: test_profile
        antivirus_profile_websocket:
          av_scan: disable
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
        '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/websocket',
        '/pm/config/global/obj/antivirus/profile/{profile}/websocket'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'antivirus_profile_websocket': {
            'type': 'dict', 'v_range': [['7.6.7', '']],
            'options': {
                'archive-block': {
                    'v_range': [['7.6.7', '']],
                    'type': 'list',
                    'choices': ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout'],
                    'elements': 'str'
                },
                'archive-log': {
                    'v_range': [['7.6.7', '']],
                    'type': 'list',
                    'choices': ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout'],
                    'elements': 'str'
                },
                'av-scan': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'emulator': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'external-blocklist': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'fortindr': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'fortisandbox': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'malware-stream': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'outbreak-prevention': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'quarantine': {'v_range': [['7.6.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'antivirus_profile_websocket'),
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
