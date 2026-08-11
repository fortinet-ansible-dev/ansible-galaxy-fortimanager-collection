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
module: fmgr_dlp_exactdatamatch
short_description: Configure exact-data-match template used by DLP scan.
version_added: "2.10.0"
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
  dlp_exactdatamatch:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      columns:
        type: list
        elements: dict
        description: Columns.
        suboptions:
          index:
            type: int
            description: Column index.
          optional:
            type: str
            description: Enable/disable optional match.
            choices: ['disable', 'enable']
          type:
            type: list
            elements: str
            description: Data-type for this column.
      data:
        type: list
        elements: str
        description: External resource for exact data match.
      name:
        type: str
        description: Name of table containing the exact-data-match template.
        required: true
      optional:
        type: int
        description: Number of optional columns need to match.
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Source of truth for fabric object.
        choices: ['member', 'local', 'root']
      uuid:
        type: str
        description: Universally Unique Identifier
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure exact-data-match template used by DLP scan.
      fortinet.fortimanager.fmgr_dlp_exactdatamatch:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        dlp_exactdatamatch:
          name: "your value" # Required variable, string
          # columns:
          #   - index: <integer>
          #     optional: <value in [disable, enable]>
          #     type: <list or string>
          # data: <list or string>
          # optional: <integer>
          # fabric_force_sync: <value in [disable, enable]>
          # fabric_object: <value in [disable, enable]>
          # fabric_object_source: <value in [member, local, root]>
          # uuid: <string>
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
        '/pm/config/adom/{adom}/obj/dlp/exact-data-match',
        '/pm/config/global/obj/dlp/exact-data-match'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'dlp_exactdatamatch': {
            'type': 'dict', 'v_range': [['7.4.7', '7.4.11'], ['7.6.3', '']],
            'options': {
                'columns': {
                    'v_range': [['7.4.7', '7.4.11'], ['7.6.3', '']],
                    'type': 'list',
                    'options': {
                        'index': {'v_range': [['7.4.7', '7.4.11'], ['7.6.3', '']], 'type': 'int'},
                        'optional': {'v_range': [['7.4.7', '7.4.11'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {'v_range': [['7.4.7', '7.4.11'], ['7.6.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'data': {'v_range': [['7.4.7', '7.4.11'], ['7.6.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.4.7', '7.4.11'], ['7.6.3', '']], 'required': True, 'type': 'str'},
                'optional': {'v_range': [['7.4.7', '7.4.11'], ['7.6.3', '']], 'type': 'int'},
                'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_exactdatamatch'),
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
