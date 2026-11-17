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
module: fmgr_llm_server
short_description: Configure LLM Proxy servers.
version_added: "2.16.0"
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
  llm_server:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      accept_custom_model:
        aliases: ['accept-custom-model']
        type: str
        description: Accept custom model
        choices: ['disable', 'enable']
      anthropic_version:
        aliases: ['anthropic-version']
        type: str
        description: Anthropic version in API
      api_key:
        aliases: ['api-key']
        type: list
        elements: str
        description: API Keys of the LLM server
      azure_api_version:
        aliases: ['azure-api-version']
        type: str
        description: Azure API version.
      azure_resource_name:
        aliases: ['azure-resource-name']
        type: str
        description: Azure resource name.
      built_in_server:
        aliases: ['built-in-server']
        type: str
        description: Built-in LLM server
        choices: ['openai', 'azure', 'azure-openai', 'gemini', 'anthropic', 'grok',
                  'gemini-with-openai-api', 'anthropic-with-openai-api']
      chat_completions_api:
        aliases: ['chat-completions-api']
        type: str
        description: Chat Completions API of this server
        choices: ['none', 'openai', 'azure-openai', 'gemini', 'anthropic']
      custom_model_allow_regex:
        aliases: ['custom-model-allow-regex']
        type: str
        description: Custom model allow regex, allow all if empty
      custom_model_block_regex:
        aliases: ['custom-model-block-regex']
        type: str
        description: Custom model block regex, no block if empty
      display_name:
        aliases: ['display-name']
        type: str
        description: Display name of the LLM Server
      end_point:
        aliases: ['end-point']
        type: str
        description: Overwrite the default end-point of the vendor.
      image_gen_api:
        aliases: ['image-gen-api']
        type: str
        description: Image-Gen API of this server
        choices: ['none', 'openai', 'azure-openai']
      models:
        type: list
        elements: str
        description: Models of the LLM Server
      name:
        type: str
        description: LLM Proxy server name.
        required: true
      type:
        type: str
        description: LLM server type
        choices: ['built-in', 'customized']
      verify_cert:
        aliases: ['verify-cert']
        type: str
        description: Enable/disable certificate verification.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure LLM Proxy servers.
      fortinet.fortimanager.fmgr_llm_server:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        llm_server:
          name: "your value" # Required variable, string
          # accept_custom_model: <value in [disable, enable]>
          # anthropic_version: <string>
          # api_key: <list or string>
          # azure_api_version: <string>
          # azure_resource_name: <string>
          # built_in_server: <value in [openai, azure, azure-openai, ...]>
          # chat_completions_api: <value in [none, openai, azure-openai, ...]>
          # custom_model_allow_regex: <string>
          # custom_model_block_regex: <string>
          # display_name: <string>
          # end_point: <string>
          # image_gen_api: <value in [none, openai, azure-openai]>
          # models: <list or string>
          # type: <value in [built-in, customized]>
          # verify_cert: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/llm/server',
        '/pm/config/global/obj/llm/server'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'llm_server': {
            'type': 'dict', 'v_range': [['8.0.1', '']],
            'options': {
                'accept-custom-model': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'anthropic-version': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'api-key': {'v_range': [['8.0.1', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'azure-api-version': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'azure-resource-name': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'built-in-server': {
                    'v_range': [['8.0.1', '']],
                    'choices': ['openai', 'azure', 'azure-openai', 'gemini', 'anthropic', 'grok', 'gemini-with-openai-api', 'anthropic-with-openai-api'],
                    'type': 'str'
                },
                'chat-completions-api': {'v_range': [['8.0.1', '']], 'choices': ['none', 'openai', 'azure-openai', 'gemini', 'anthropic'], 'type': 'str'},
                'custom-model-allow-regex': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'custom-model-block-regex': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'display-name': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'end-point': {'v_range': [['8.0.1', '']], 'type': 'str'},
                'image-gen-api': {'v_range': [['8.0.1', '']], 'choices': ['none', 'openai', 'azure-openai'], 'type': 'str'},
                'models': {'v_range': [['8.0.1', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['8.0.1', '']], 'required': True, 'type': 'str'},
                'type': {'v_range': [['8.0.1', '']], 'choices': ['built-in', 'customized'], 'type': 'str'},
                'verify-cert': {'v_range': [['8.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'llm_server'),
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
