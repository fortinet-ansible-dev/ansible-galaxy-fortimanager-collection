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
module: fmgr_pm_config_pblock_firewall_localinpolicy
short_description: Configure user defined IPv4 local-in policies.
version_added: "2.15.0"
extends_documentation_fragment:
  - fortinet.fortimanager.general
  - fortinet.fortimanager.general.full_crud
options:
  adom:
    description: The parameter (adom) in requested url.
    type: str
    required: true
  pblock:
    description: The parameter (pblock) in requested url.
    type: str
    required: true
  pm_config_pblock_firewall_localinpolicy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      _policy_block:
        type: int
        description: Assigned policy block.
      action:
        type: str
        description: Action performed on traffic matching the policy
        choices: ['deny', 'accept']
      comments:
        type: str
        description: Comment.
      custom_tags:
        aliases: ['custom-tags']
        type: list
        elements: str
        description: Custom tags.
      dstaddr:
        type: list
        elements: str
        description: Destination address object from available options.
      dstaddr_negate:
        aliases: ['dstaddr-negate']
        type: str
        description: When enabled dstaddr specifies what the destination address must NOT be.
        choices: ['disable', 'enable']
      ha_mgmt_intf_only:
        aliases: ['ha-mgmt-intf-only']
        type: str
        description: Enable/disable dedicating the HA management interface only for local-in policy.
        choices: ['disable', 'enable']
      internet_service_src:
        aliases: ['internet-service-src']
        type: str
        description: Enable/disable use of Internet Services in source for this local-in policy.
        choices: ['disable', 'enable']
      internet_service_src_custom:
        aliases: ['internet-service-src-custom']
        type: list
        elements: str
        description: Custom Internet Service source name.
      internet_service_src_custom_group:
        aliases: ['internet-service-src-custom-group']
        type: list
        elements: str
        description: Custom Internet Service source group name.
      internet_service_src_fortiguard:
        aliases: ['internet-service-src-fortiguard']
        type: list
        elements: str
        description: FortiGuard Internet Service source name.
      internet_service_src_group:
        aliases: ['internet-service-src-group']
        type: list
        elements: str
        description: Internet Service source group name.
      internet_service_src_name:
        aliases: ['internet-service-src-name']
        type: list
        elements: str
        description: Internet Service source name.
      internet_service_src_negate:
        aliases: ['internet-service-src-negate']
        type: str
        description: When enabled internet-service-src specifies what the service must NOT be.
        choices: ['disable', 'enable']
      intf:
        type: list
        elements: str
        description: Incoming interface name from available options.
      logtraffic:
        type: str
        description: Enable/disable local-in traffic logging.
        choices: ['disable', 'enable']
      policyid:
        type: int
        description: User defined local in policy ID.
        required: true
      schedule:
        type: list
        elements: str
        description: Schedule object from available options.
      service:
        type: list
        elements: str
        description: Service object from available options.
      service_negate:
        aliases: ['service-negate']
        type: str
        description: When enabled service specifies what the service must NOT be.
        choices: ['disable', 'enable']
      srcaddr:
        type: list
        elements: str
        description: Source address object from available options.
      srcaddr_negate:
        aliases: ['srcaddr-negate']
        type: str
        description: When enabled srcaddr specifies what the source address must NOT be.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable this local-in policy.
        choices: ['disable', 'enable']
      uuid:
        type: str
        description: Universally Unique Identifier
      virtual_patch:
        aliases: ['virtual-patch']
        type: str
        description: Enable/disable virtual patching.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Test policy block IPv4 local-in policies
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create the parent policy block
      fortinet.fortimanager.fmgr_pm_pblock_adom:
        enable_log: true
        adom: root
        pm_pblock_adom:
          name: test_policy_block
          type: pblock

    - name: Create a policy block IPv4 local-in policy
      fortinet.fortimanager.fmgr_pm_config_pblock_firewall_localinpolicy:
        enable_log: true
        adom: root
        pblock: test_policy_block
        state: present
        pm_config_pblock_firewall_localinpolicy:
          action: accept
          dstaddr:
            - all
          intf:
            - any
          policyid: 0
          schedule:
            - always
          service:
            - ALL
          srcaddr:
            - all
          status: disable
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
        '/pm/config/adom/{adom}/pblock/{pblock}/firewall/local-in-policy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pblock': {'required': True, 'type': 'str'},
        'pm_config_pblock_firewall_localinpolicy': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                '_policy_block': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'action': {'v_range': [['8.0.0', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'comments': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'custom-tags': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ha-mgmt-intf-only': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-custom': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-custom-group': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-fortiguard': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-group': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-name': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-src-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'intf': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'logtraffic': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'policyid': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'int'},
                'schedule': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'service': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'service-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr-negate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'virtual-patch': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pm_config_pblock_firewall_localinpolicy'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'policyid', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
