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
module: fmgr_pkg_firewall_explicitproxypolicy_identitybasedpolicy
short_description: Identity-based policy.
version_added: "2.2.0"
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    explicit-proxy-policy:
        description: Deprecated, please use "explicit_proxy_policy"
        type: str
    explicit_proxy_policy:
        description: The parameter (explicit-proxy-policy) in requested url.
        type: str
    pkg_firewall_explicitproxypolicy_identitybasedpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            application_list:
                aliases: ['application-list']
                type: str
                description: Application list.
            av_profile:
                aliases: ['av-profile']
                type: str
                description: Antivirus profile.
            casi_profile:
                aliases: ['casi-profile']
                type: str
                description: CASI profile.
            disclaimer:
                type: str
                description: Web proxy disclaimer setting.
                choices: ['disable', 'domain', 'policy', 'user']
            dlp_sensor:
                aliases: ['dlp-sensor']
                type: str
                description: DLP sensor.
            groups:
                type: str
                description: Group name.
            icap_profile:
                aliases: ['icap-profile']
                type: str
                description: ICAP profile.
            id:
                type: int
                description: ID.
                required: true
            ips_sensor:
                aliases: ['ips-sensor']
                type: str
                description: IPS sensor.
            logtraffic:
                type: str
                description: Enable/disable policy log traffic.
                choices: ['disable', 'all', 'utm']
            logtraffic_start:
                aliases: ['logtraffic-start']
                type: str
                description: Enable/disable policy log traffic start.
                choices: ['disable', 'enable']
            mms_profile:
                aliases: ['mms-profile']
                type: str
                description: Mms profile
            profile_group:
                aliases: ['profile-group']
                type: str
                description: Profile group
            profile_protocol_options:
                aliases: ['profile-protocol-options']
                type: str
                description: Profile protocol options.
            profile_type:
                aliases: ['profile-type']
                type: str
                description: Profile type
                choices: ['single', 'group']
            replacemsg_override_group:
                aliases: ['replacemsg-override-group']
                type: str
                description: Specify authentication replacement message override group.
            scan_botnet_connections:
                aliases: ['scan-botnet-connections']
                type: str
                description: Enable/disable scanning of connections to Botnet servers.
                choices: ['disable', 'block', 'monitor']
            schedule:
                type: str
                description: Schedule name.
            spamfilter_profile:
                aliases: ['spamfilter-profile']
                type: str
                description: Spam filter profile.
            ssl_ssh_profile:
                aliases: ['ssl-ssh-profile']
                type: str
                description: SSL SSH Profile.
            users:
                type: str
                description: User name.
            utm_status:
                aliases: ['utm-status']
                type: str
                description: Enable AV/web/IPS protection profile.
                choices: ['disable', 'enable']
            waf_profile:
                aliases: ['waf-profile']
                type: str
                description: Web application firewall profile.
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: str
                description: Web filter profile.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Identity-based policy.
      fortinet.fortimanager.fmgr_pkg_firewall_explicitproxypolicy_identitybasedpolicy:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        pkg: <your own value>
        explicit_proxy_policy: <your own value>
        state: present # <value in [present, absent]>
        pkg_firewall_explicitproxypolicy_identitybasedpolicy:
          id: 0 # Required variable, integer
          # application_list: <string>
          # av_profile: <string>
          # casi_profile: <string>
          # disclaimer: <value in [disable, domain, policy, ...]>
          # dlp_sensor: <string>
          # groups: <string>
          # icap_profile: <string>
          # ips_sensor: <string>
          # logtraffic: <value in [disable, all, utm]>
          # logtraffic_start: <value in [disable, enable]>
          # mms_profile: <string>
          # profile_group: <string>
          # profile_protocol_options: <string>
          # profile_type: <value in [single, group]>
          # replacemsg_override_group: <string>
          # scan_botnet_connections: <value in [disable, block, monitor]>
          # schedule: <string>
          # spamfilter_profile: <string>
          # ssl_ssh_profile: <string>
          # users: <string>
          # utm_status: <value in [disable, enable]>
          # waf_profile: <string>
          # webfilter_profile: <string>
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy/{explicit-proxy-policy}/identity-based-policy'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'explicit-proxy-policy': {'type': 'str', 'api_name': 'explicit_proxy_policy'},
        'explicit_proxy_policy': {'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_explicitproxypolicy_identitybasedpolicy': {
            'type': 'dict', 'v_range': [['6.2.0', '6.2.13']],
            'options': {
                'application-list': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'av-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'casi-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'disclaimer': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'domain', 'policy', 'user'], 'type': 'str'},
                'dlp-sensor': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'groups': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'icap-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'id': {'v_range': [['6.2.0', '6.2.13']], 'required': True, 'type': 'int'},
                'ips-sensor': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'logtraffic': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'all', 'utm'], 'type': 'str'},
                'logtraffic-start': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'profile-group': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'profile-protocol-options': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'profile-type': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['single', 'group'], 'type': 'str'},
                'replacemsg-override-group': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'scan-botnet-connections': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'schedule': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'spamfilter-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'ssl-ssh-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'users': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'utm-status': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'waf-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'webfilter-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_explicitproxypolicy_identitybasedpolicy'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgr.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
