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
module: fmgr_webfilter_profile_ftgdimageclassification
short_description: FortiGuard image classification filter settings.
version_added: "2.16.0"
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
  webfilter_profile_ftgdimageclassification:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      file_size_maximum:
        aliases: ['file-size-maximum']
        type: int
        description: File size above which no classification request is performed in kilobytes
      file_size_minimum:
        aliases: ['file-size-minimum']
        type: int
        description: Minimum file size to trigger a classification request in kilobytes
      file_types:
        aliases: ['file-types']
        type: list
        elements: str
        description: Select file type.
      http_method:
        aliases: ['http-method']
        type: str
        description: Select HTTP requests methods that will be scanned.
        choices: ['disable', 'all', 'get', 'post']
      rating_error_action:
        aliases: ['rating-error-action']
        type: str
        description: Action to take if FortiGuard image classification query fails.
        choices: ['block', 'log', 'allow']
      rating_quota_reached_action:
        aliases: ['rating-quota-reached-action']
        type: str
        description: Action to take when FortiGuard image classification signals the rate limit is reached.
        choices: ['block', 'log', 'allow']
      rating_timeout:
        aliases: ['rating-timeout']
        type: int
        description: FortiGuard image classification timeout in seconds
      rating_timeout_action:
        aliases: ['rating-timeout-action']
        type: str
        description: Action to take if FortiGuard image classification times out.
        choices: ['block', 'log', 'allow']
      rules:
        type: list
        elements: dict
        description: Rules.
        suboptions:
          block_threshold:
            aliases: ['block-threshold']
            type: int
            description: Rating above which the image is blocked
          category:
            type: str
            description: Category name.
          log_threshold:
            aliases: ['log-threshold']
            type: int
            description: Rating above which the image is logged
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: FortiGuard image classification filter settings.
      fortinet.fortimanager.fmgr_webfilter_profile_ftgdimageclassification:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        webfilter_profile_ftgdimageclassification:
          # file_size_maximum: <integer>
          # file_size_minimum: <integer>
          # file_types: <list or string>
          # http_method: <value in [disable, all, get, ...]>
          # rating_error_action: <value in [block, log, allow]>
          # rating_quota_reached_action: <value in [block, log, allow]>
          # rating_timeout: <integer>
          # rating_timeout_action: <value in [block, log, allow]>
          # rules:
          #   - block_threshold: <integer>
          #     category: <string>
          #     log_threshold: <integer>
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
        '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-image-classification',
        '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-image-classification'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'webfilter_profile_ftgdimageclassification': {
            'type': 'dict', 'v_range': [['8.0.1', '']],
            'options': {
                'file-size-maximum': {'v_range': [['8.0.1', '']], 'type': 'int'},
                'file-size-minimum': {'v_range': [['8.0.1', '']], 'type': 'int'},
                'file-types': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                'http-method': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'all', 'get', 'post'], 'type': 'str'},
                'rating-error-action': {'v_range': [['8.0.1', '']], 'choices': ['block', 'log', 'allow'], 'type': 'str'},
                'rating-quota-reached-action': {'v_range': [['8.0.1', '']], 'choices': ['block', 'log', 'allow'], 'type': 'str'},
                'rating-timeout': {'v_range': [['8.0.1', '']], 'type': 'int'},
                'rating-timeout-action': {'v_range': [['8.0.1', '']], 'choices': ['block', 'log', 'allow'], 'type': 'str'},
                'rules': {
                    'v_range': [['8.0.1', '']],
                    'type': 'list',
                    'options': {
                        'block-threshold': {'v_range': [['8.0.1', '']], 'type': 'int'},
                        'category': {'v_range': [['8.0.1', '']], 'type': 'str'},
                        'log-threshold': {'v_range': [['8.0.1', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile_ftgdimageclassification'),
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
