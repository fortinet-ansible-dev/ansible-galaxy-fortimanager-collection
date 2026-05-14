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
module: fmgr_antivirus_profile_contentdisarm
short_description: AV Content Disarm and Reconstruction settings.
version_added: "2.0.0"
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
    antivirus_profile_contentdisarm:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cover_page:
                aliases: ['cover-page']
                type: str
                description: Enable/disable inserting a cover page into the disarmed document.
                choices: ['disable', 'enable']
            detect_only:
                aliases: ['detect-only']
                type: str
                description: Enable/disable only detect disarmable files, do not alter content.
                choices: ['disable', 'enable']
            office_embed:
                aliases: ['office-embed']
                type: str
                description: Enable/disable stripping of embedded objects in Microsoft Office documents.
                choices: ['disable', 'enable']
            office_hylink:
                aliases: ['office-hylink']
                type: str
                description: Enable/disable stripping of hyperlinks in Microsoft Office documents.
                choices: ['disable', 'enable']
            office_linked:
                aliases: ['office-linked']
                type: str
                description: Enable/disable stripping of linked objects in Microsoft Office documents.
                choices: ['disable', 'enable']
            office_macro:
                aliases: ['office-macro']
                type: str
                description: Enable/disable stripping of macros in Microsoft Office documents.
                choices: ['disable', 'enable']
            original_file_destination:
                aliases: ['original-file-destination']
                type: str
                description: Destination to send original file if active content is removed.
                choices: ['fortisandbox', 'quarantine', 'discard']
            pdf_act_form:
                aliases: ['pdf-act-form']
                type: str
                description: Enable/disable stripping of actions that submit data to other targets in PDF documents.
                choices: ['disable', 'enable']
            pdf_act_gotor:
                aliases: ['pdf-act-gotor']
                type: str
                description: Enable/disable stripping of links to other PDFs in PDF documents.
                choices: ['disable', 'enable']
            pdf_act_java:
                aliases: ['pdf-act-java']
                type: str
                description: Enable/disable stripping of actions that execute JavaScript code in PDF documents.
                choices: ['disable', 'enable']
            pdf_act_launch:
                aliases: ['pdf-act-launch']
                type: str
                description: Enable/disable stripping of links to external applications in PDF documents.
                choices: ['disable', 'enable']
            pdf_act_movie:
                aliases: ['pdf-act-movie']
                type: str
                description: Enable/disable stripping of embedded movies in PDF documents.
                choices: ['disable', 'enable']
            pdf_act_sound:
                aliases: ['pdf-act-sound']
                type: str
                description: Enable/disable stripping of embedded sound files in PDF documents.
                choices: ['disable', 'enable']
            pdf_embedfile:
                aliases: ['pdf-embedfile']
                type: str
                description: Enable/disable stripping of embedded files in PDF documents.
                choices: ['disable', 'enable']
            pdf_hyperlink:
                aliases: ['pdf-hyperlink']
                type: str
                description: Enable/disable stripping of hyperlinks from PDF documents.
                choices: ['disable', 'enable']
            pdf_javacode:
                aliases: ['pdf-javacode']
                type: str
                description: Enable/disable stripping of JavaScript code in PDF documents.
                choices: ['disable', 'enable']
            office_action:
                aliases: ['office-action']
                type: str
                description: Enable/disable stripping of PowerPoint action events in Microsoft Office documents.
                choices: ['disable', 'enable']
            office_dde:
                aliases: ['office-dde']
                type: str
                description: Enable/disable stripping of Dynamic Data Exchange events in Microsoft Office documents.
                choices: ['disable', 'enable']
            error_action:
                aliases: ['error-action']
                type: str
                description: Action to be taken if CDR engine encounters an unrecoverable error.
                choices: ['block', 'log-only', 'ignore']
            analytics_suspicious:
                aliases: ['analytics-suspicious']
                type: str
                description: Enable/disable using CDR as a secondary method for determining suspicous files for analytics.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: AV Content Disarm and Reconstruction settings.
      fortinet.fortimanager.fmgr_antivirus_profile_contentdisarm:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        antivirus_profile_contentdisarm:
          # cover_page: <value in [disable, enable]>
          # detect_only: <value in [disable, enable]>
          # office_embed: <value in [disable, enable]>
          # office_hylink: <value in [disable, enable]>
          # office_linked: <value in [disable, enable]>
          # office_macro: <value in [disable, enable]>
          # original_file_destination: <value in [fortisandbox, quarantine, discard]>
          # pdf_act_form: <value in [disable, enable]>
          # pdf_act_gotor: <value in [disable, enable]>
          # pdf_act_java: <value in [disable, enable]>
          # pdf_act_launch: <value in [disable, enable]>
          # pdf_act_movie: <value in [disable, enable]>
          # pdf_act_sound: <value in [disable, enable]>
          # pdf_embedfile: <value in [disable, enable]>
          # pdf_hyperlink: <value in [disable, enable]>
          # pdf_javacode: <value in [disable, enable]>
          # office_action: <value in [disable, enable]>
          # office_dde: <value in [disable, enable]>
          # error_action: <value in [block, log-only, ignore]>
          # analytics_suspicious: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/content-disarm',
        '/pm/config/global/obj/antivirus/profile/{profile}/content-disarm'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'antivirus_profile_contentdisarm': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'cover-page': {'choices': ['disable', 'enable'], 'type': 'str'},
                'detect-only': {'choices': ['disable', 'enable'], 'type': 'str'},
                'office-embed': {'choices': ['disable', 'enable'], 'type': 'str'},
                'office-hylink': {'choices': ['disable', 'enable'], 'type': 'str'},
                'office-linked': {'choices': ['disable', 'enable'], 'type': 'str'},
                'office-macro': {'choices': ['disable', 'enable'], 'type': 'str'},
                'original-file-destination': {'choices': ['fortisandbox', 'quarantine', 'discard'], 'type': 'str'},
                'pdf-act-form': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pdf-act-gotor': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pdf-act-java': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pdf-act-launch': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pdf-act-movie': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pdf-act-sound': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pdf-embedfile': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pdf-hyperlink': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pdf-javacode': {'choices': ['disable', 'enable'], 'type': 'str'},
                'office-action': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'office-dde': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'error-action': {'v_range': [['6.4.2', '']], 'choices': ['block', 'log-only', 'ignore'], 'type': 'str'},
                'analytics-suspicious': {'v_range': [['7.4.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'antivirus_profile_contentdisarm'),
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
