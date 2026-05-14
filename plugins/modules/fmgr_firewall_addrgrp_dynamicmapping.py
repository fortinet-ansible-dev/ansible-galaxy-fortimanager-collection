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
module: fmgr_firewall_addrgrp_dynamicmapping
short_description: Configure IPv4 address groups.
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
    addrgrp:
        description: The parameter (addrgrp) in requested url.
        type: str
        required: true
    firewall_addrgrp_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _scope:
                type: list
                elements: dict
                description: Scope.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    vdom:
                        type: str
                        description: Vdom.
            allow_routing:
                aliases: ['allow-routing']
                type: str
                description: Allow routing.
                choices: ['disable', 'enable']
            color:
                type: int
                description: Color.
            comment:
                type: raw
                description: (dict or str) Comment.
            exclude:
                type: str
                description: Exclude.
                choices: ['disable', 'enable']
            exclude_member:
                aliases: ['exclude-member']
                type: raw
                description: (list or str) Exclude member.
            member:
                type: raw
                description: (list or str) Member.
            tags:
                type: raw
                description: (list or str) Tags.
            uuid:
                type: str
                description: Uuid.
            visibility:
                type: str
                description: Visibility.
                choices: ['disable', 'enable']
            _image_base64:
                aliases: ['_image-base64']
                type: str
                description: Image base64.
            global_object:
                aliases: ['global-object']
                type: int
                description: Global object.
            type:
                type: str
                description: Type.
                choices: ['default', 'array', 'folder']
            fabric_object:
                aliases: ['fabric-object']
                type: str
                description: Security Fabric global object setting.
                choices: ['disable', 'enable']
            category:
                type: str
                description: Address group category.
                choices: ['default', 'ztna-ems-tag', 'ztna-geo-tag', 'telemetry']
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure dynamic mappings of IPv4 address group
      fortinet.fortimanager.fmgr_firewall_addrgrp_dynamicmapping:
        bypass_validation: false
        adom: ansible
        addrgrp: "ansible" # name
        state: present
        firewall_addrgrp_dynamicmapping:
          _scope:
            - name: FGT_AWS # need a valid device name
              vdom: root # need a valid vdom name under the device
          allow_routing: disable
          color: 1
          member: "ansible-test1"
          visibility: enable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the dynamic mappings of IPv4 address group
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_addrgrp_dynamicmapping"
          params:
            adom: "ansible"
            addrgrp: "ansible-addrgrp4" # name
            dynamic_mapping: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping',
        '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'addrgrp': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_addrgrp_dynamicmapping': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                'allow-routing': {'choices': ['disable', 'enable'], 'type': 'str'},
                'color': {'type': 'int'},
                'comment': {'type': 'raw'},
                'exclude': {'choices': ['disable', 'enable'], 'type': 'str'},
                'exclude-member': {'type': 'raw'},
                'member': {'type': 'raw'},
                'tags': {'type': 'raw'},
                'uuid': {'type': 'str'},
                'visibility': {'choices': ['disable', 'enable'], 'type': 'str'},
                '_image-base64': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'global-object': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'type': {'v_range': [['6.4.0', '']], 'choices': ['default', 'array', 'folder'], 'type': 'str'},
                'fabric-object': {'v_range': [['6.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'category': {'v_range': [['7.0.0', '']], 'choices': ['default', 'ztna-ems-tag', 'ztna-geo-tag', 'telemetry'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_addrgrp_dynamicmapping'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
