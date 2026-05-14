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
module: fmgr_webfilter_profile_web
short_description: Web content filtering settings.
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
    webfilter_profile_web:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            blacklist:
                type: str
                description: Enable/disable automatic addition of URLs detected by FortiSandbox to blacklist.
                choices: ['disable', 'enable']
            bword_table:
                aliases: ['bword-table']
                type: str
                description: Banned word table ID.
            bword_threshold:
                aliases: ['bword-threshold']
                type: int
                description: Banned word score threshold.
            content_header_list:
                aliases: ['content-header-list']
                type: str
                description: Content header list.
            keyword_match:
                aliases: ['keyword-match']
                type: raw
                description: (list) Search keywords to log when match is found.
            log_search:
                aliases: ['log-search']
                type: str
                description: Enable/disable logging all search phrases.
                choices: ['disable', 'enable']
            safe_search:
                aliases: ['safe-search']
                type: list
                elements: str
                description: Safe search type.
                choices: ['google', 'yahoo', 'bing', 'url', 'header']
            urlfilter_table:
                aliases: ['urlfilter-table']
                type: str
                description: URL filter table ID.
            whitelist:
                type: list
                elements: str
                description: FortiGuard whitelist settings.
                choices: ['exempt-av', 'exempt-webcontent', 'exempt-activex-java-cookie',
                          'exempt-dlp', 'exempt-rangeblock', 'extended-log-others']
            youtube_restrict:
                aliases: ['youtube-restrict']
                type: str
                description: YouTube EDU filter level.
                choices: ['strict', 'none', 'moderate']
            allowlist:
                type: list
                elements: str
                description: FortiGuard allowlist settings.
                choices: ['exempt-av', 'exempt-webcontent', 'exempt-activex-java-cookie',
                          'exempt-dlp', 'exempt-rangeblock', 'extended-log-others']
            blocklist:
                type: str
                description: Enable/disable automatic addition of URLs detected by FortiSandbox to blocklist.
                choices: ['disable', 'enable']
            vimeo_restrict:
                aliases: ['vimeo-restrict']
                type: str
                description: Set Vimeo-restrict
            qwant_restrict:
                aliases: ['qwant-restrict']
                type: str
                description: Qwant restrict.
                choices: ['strict', 'none', 'moderate']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Web content filtering settings.
      fortinet.fortimanager.fmgr_webfilter_profile_web:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        webfilter_profile_web:
          # blacklist: <value in [disable, enable]>
          # bword_table: <string>
          # bword_threshold: <integer>
          # content_header_list: <string>
          # keyword_match: <list or string>
          # log_search: <value in [disable, enable]>
          # safe_search: ["google", "yahoo", "bing", "url", "header"]
          # urlfilter_table: <string>
          # whitelist: ["exempt-av", "exempt-webcontent", "exempt-activex-java-cookie",
          #             "exempt-dlp", "exempt-rangeblock", "extended-log-others"]
          # youtube_restrict: <value in [strict, none, moderate]>
          # allowlist: ["exempt-av", "exempt-webcontent", "exempt-activex-java-cookie",
          #             "exempt-dlp", "exempt-rangeblock", "extended-log-others"]
          # blocklist: <value in [disable, enable]>
          # vimeo_restrict: <string>
          # qwant_restrict: <value in [strict, none, moderate]>
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
        '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/web',
        '/pm/config/global/obj/webfilter/profile/{profile}/web'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'webfilter_profile_web': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'blacklist': {'choices': ['disable', 'enable'], 'type': 'str'},
                'bword-table': {'type': 'str'},
                'bword-threshold': {'type': 'int'},
                'content-header-list': {'type': 'str'},
                'keyword-match': {'no_log': True, 'type': 'raw'},
                'log-search': {'choices': ['disable', 'enable'], 'type': 'str'},
                'safe-search': {'type': 'list', 'choices': ['google', 'yahoo', 'bing', 'url', 'header'], 'elements': 'str'},
                'urlfilter-table': {'type': 'str'},
                'whitelist': {
                    'type': 'list',
                    'choices': ['exempt-av', 'exempt-webcontent', 'exempt-activex-java-cookie', 'exempt-dlp', 'exempt-rangeblock', 'extended-log-others'],
                    'elements': 'str'
                },
                'youtube-restrict': {'choices': ['strict', 'none', 'moderate'], 'type': 'str'},
                'allowlist': {
                    'v_range': [['7.0.0', '']],
                    'type': 'list',
                    'choices': ['exempt-av', 'exempt-webcontent', 'exempt-activex-java-cookie', 'exempt-dlp', 'exempt-rangeblock', 'extended-log-others'],
                    'elements': 'str'
                },
                'blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vimeo-restrict': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'qwant-restrict': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['strict', 'none', 'moderate'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile_web'),
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
