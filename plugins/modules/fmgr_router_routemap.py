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
module: fmgr_router_routemap
short_description: Configure route maps.
version_added: "2.1.0"
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
    router_routemap:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comments:
                type: str
                description: Optional comments.
            name:
                type: str
                description: Name.
                required: true
            rule:
                type: list
                elements: dict
                description: Rule.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices: ['permit', 'deny']
                    id:
                        type: int
                        description: Rule ID.
                    match_as_path:
                        aliases: ['match-as-path']
                        type: str
                        description: Match BGP AS path list.
                    match_community:
                        aliases: ['match-community']
                        type: str
                        description: Match BGP community list.
                    match_community_exact:
                        aliases: ['match-community-exact']
                        type: str
                        description: Enable/disable exact matching of communities.
                        choices: ['disable', 'enable']
                    match_flags:
                        aliases: ['match-flags']
                        type: int
                        description: Match flags.
                    match_interface:
                        aliases: ['match-interface']
                        type: str
                        description: Match interface configuration.
                    match_ip_address:
                        aliases: ['match-ip-address']
                        type: str
                        description: Match IP address permitted by access-list or prefix-list.
                    match_ip_nexthop:
                        aliases: ['match-ip-nexthop']
                        type: str
                        description: Match next hop IP address passed by access-list or prefix-list.
                    match_ip6_address:
                        aliases: ['match-ip6-address']
                        type: str
                        description: Match IPv6 address permitted by access-list6 or prefix-list6.
                    match_ip6_nexthop:
                        aliases: ['match-ip6-nexthop']
                        type: str
                        description: Match next hop IPv6 address passed by access-list6 or prefix-list6.
                    match_metric:
                        aliases: ['match-metric']
                        type: str
                        description: Match metric for redistribute routes.
                    match_origin:
                        aliases: ['match-origin']
                        type: str
                        description: Match BGP origin code.
                        choices: ['none', 'egp', 'igp', 'incomplete']
                    match_route_type:
                        aliases: ['match-route-type']
                        type: str
                        description: Match route type.
                        choices: ['1', '2', 'none', 'external-type1', 'external-type2']
                    match_tag:
                        aliases: ['match-tag']
                        type: str
                        description: Match tag.
                    match_vrf:
                        aliases: ['match-vrf']
                        type: int
                        description: Match VRF ID.
                    set_aggregator_as:
                        aliases: ['set-aggregator-as']
                        type: int
                        description: BGP aggregator AS.
                    set_aggregator_ip:
                        aliases: ['set-aggregator-ip']
                        type: str
                        description: BGP aggregator IP.
                    set_aspath:
                        aliases: ['set-aspath']
                        type: raw
                        description: (list) Prepend BGP AS path attribute.
                    set_aspath_action:
                        aliases: ['set-aspath-action']
                        type: str
                        description: Specify preferred action of set-aspath.
                        choices: ['prepend', 'replace']
                    set_atomic_aggregate:
                        aliases: ['set-atomic-aggregate']
                        type: str
                        description: Enable/disable BGP atomic aggregate attribute.
                        choices: ['disable', 'enable']
                    set_community:
                        aliases: ['set-community']
                        type: raw
                        description: (list) BGP community attribute.
                    set_community_additive:
                        aliases: ['set-community-additive']
                        type: str
                        description: Enable/disable adding set-community to existing community.
                        choices: ['disable', 'enable']
                    set_community_delete:
                        aliases: ['set-community-delete']
                        type: str
                        description: Delete communities matching community list.
                    set_dampening_max_suppress:
                        aliases: ['set-dampening-max-suppress']
                        type: int
                        description: Maximum duration to suppress a route
                    set_dampening_reachability_half_life:
                        aliases: ['set-dampening-reachability-half-life']
                        type: int
                        description: Reachability half-life time for the penalty
                    set_dampening_reuse:
                        aliases: ['set-dampening-reuse']
                        type: int
                        description: Value to start reusing a route
                    set_dampening_suppress:
                        aliases: ['set-dampening-suppress']
                        type: int
                        description: Value to start suppressing a route
                    set_dampening_unreachability_half_life:
                        aliases: ['set-dampening-unreachability-half-life']
                        type: int
                        description: Unreachability Half-life time for the penalty
                    set_extcommunity_rt:
                        aliases: ['set-extcommunity-rt']
                        type: raw
                        description: (list) Route Target extended community.
                    set_extcommunity_soo:
                        aliases: ['set-extcommunity-soo']
                        type: raw
                        description: (list) Site-of-Origin extended community.
                    set_flags:
                        aliases: ['set-flags']
                        type: int
                        description: Set flags.
                    set_ip_nexthop:
                        aliases: ['set-ip-nexthop']
                        type: str
                        description: IP address of next hop.
                    set_ip6_nexthop:
                        aliases: ['set-ip6-nexthop']
                        type: str
                        description: IPv6 global address of next hop.
                    set_ip6_nexthop_local:
                        aliases: ['set-ip6-nexthop-local']
                        type: str
                        description: IPv6 local address of next hop.
                    set_local_preference:
                        aliases: ['set-local-preference']
                        type: str
                        description: BGP local preference path attribute.
                    set_metric:
                        aliases: ['set-metric']
                        type: str
                        description: Metric value.
                    set_metric_type:
                        aliases: ['set-metric-type']
                        type: str
                        description: Metric type.
                        choices: ['1', '2', 'none', 'external-type1', 'external-type2']
                    set_origin:
                        aliases: ['set-origin']
                        type: str
                        description: BGP origin code.
                        choices: ['none', 'egp', 'igp', 'incomplete']
                    set_originator_id:
                        aliases: ['set-originator-id']
                        type: str
                        description: BGP originator ID attribute.
                    set_priority:
                        aliases: ['set-priority']
                        type: int
                        description: Priority for routing table.
                    set_route_tag:
                        aliases: ['set-route-tag']
                        type: str
                        description: Route tag for routing table.
                    set_tag:
                        aliases: ['set-tag']
                        type: str
                        description: Tag value.
                    set_weight:
                        aliases: ['set-weight']
                        type: str
                        description: BGP weight for routing table.
                    match_extcommunity:
                        aliases: ['match-extcommunity']
                        type: str
                        description: Match BGP extended community list.
                    match_extcommunity_exact:
                        aliases: ['match-extcommunity-exact']
                        type: str
                        description: Enable/disable exact matching of extended communities.
                        choices: ['disable', 'enable']
                    set_ip_prefsrc:
                        aliases: ['set-ip-prefsrc']
                        type: str
                        description: IP address of preferred source.
                    set_vpnv4_nexthop:
                        aliases: ['set-vpnv4-nexthop']
                        type: str
                        description: IP address of VPNv4 next-hop.
                    set_vpnv6_nexthop:
                        aliases: ['set-vpnv6-nexthop']
                        type: str
                        description: IPv6 global address of VPNv6 next-hop.
                    set_vpnv6_nexthop_local:
                        aliases: ['set-vpnv6-nexthop-local']
                        type: str
                        description: IPv6 link-local address of VPNv6 next-hop.
                    match_suppress:
                        aliases: ['match-suppress']
                        type: str
                        description: Enable/disable matching of suppressed original neighbor.
                        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure route maps.
      fortinet.fortimanager.fmgr_router_routemap:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        state: present # <value in [present, absent]>
        router_routemap:
          name: "your value" # Required variable, string
          # comments: <string>
          # rule:
          #   - action: <value in [permit, deny]>
          #     id: <integer>
          #     match_as_path: <string>
          #     match_community: <string>
          #     match_community_exact: <value in [disable, enable]>
          #     match_flags: <integer>
          #     match_interface: <string>
          #     match_ip_address: <string>
          #     match_ip_nexthop: <string>
          #     match_ip6_address: <string>
          #     match_ip6_nexthop: <string>
          #     match_metric: <string>
          #     match_origin: <value in [none, egp, igp, ...]>
          #     match_route_type: <value in [1, 2, none, ...]>
          #     match_tag: <string>
          #     match_vrf: <integer>
          #     set_aggregator_as: <integer>
          #     set_aggregator_ip: <string>
          #     set_aspath: <list or string>
          #     set_aspath_action: <value in [prepend, replace]>
          #     set_atomic_aggregate: <value in [disable, enable]>
          #     set_community: <list or string>
          #     set_community_additive: <value in [disable, enable]>
          #     set_community_delete: <string>
          #     set_dampening_max_suppress: <integer>
          #     set_dampening_reachability_half_life: <integer>
          #     set_dampening_reuse: <integer>
          #     set_dampening_suppress: <integer>
          #     set_dampening_unreachability_half_life: <integer>
          #     set_extcommunity_rt: <list or string>
          #     set_extcommunity_soo: <list or string>
          #     set_flags: <integer>
          #     set_ip_nexthop: <string>
          #     set_ip6_nexthop: <string>
          #     set_ip6_nexthop_local: <string>
          #     set_local_preference: <string>
          #     set_metric: <string>
          #     set_metric_type: <value in [1, 2, none, ...]>
          #     set_origin: <value in [none, egp, igp, ...]>
          #     set_originator_id: <string>
          #     set_priority: <integer>
          #     set_route_tag: <string>
          #     set_tag: <string>
          #     set_weight: <string>
          #     match_extcommunity: <string>
          #     match_extcommunity_exact: <value in [disable, enable]>
          #     set_ip_prefsrc: <string>
          #     set_vpnv4_nexthop: <string>
          #     set_vpnv6_nexthop: <string>
          #     set_vpnv6_nexthop_local: <string>
          #     match_suppress: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/router/route-map',
        '/pm/config/global/obj/router/route-map'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'router_routemap': {
            'type': 'dict', 'v_range': [['7.0.2', '']],
            'options': {
                'comments': {'v_range': [['7.0.2', '']], 'type': 'str'},
                'name': {'v_range': [['7.0.2', '']], 'required': True, 'type': 'str'},
                'rule': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.0.2', '']], 'choices': ['permit', 'deny'], 'type': 'str'},
                        'id': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'match-as-path': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'match-community': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'match-community-exact': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'match-flags': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'match-interface': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'match-ip-address': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'match-ip-nexthop': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'match-ip6-address': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'match-ip6-nexthop': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'match-metric': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'match-origin': {'v_range': [['7.0.2', '']], 'choices': ['none', 'egp', 'igp', 'incomplete'], 'type': 'str'},
                        'match-route-type': {'v_range': [['7.0.2', '']], 'choices': ['1', '2', 'none', 'external-type1', 'external-type2'], 'type': 'str'},
                        'match-tag': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'match-vrf': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'set-aggregator-as': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'set-aggregator-ip': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'set-aspath': {'v_range': [['7.0.2', '']], 'type': 'raw'},
                        'set-aspath-action': {'v_range': [['7.0.2', '']], 'choices': ['prepend', 'replace'], 'type': 'str'},
                        'set-atomic-aggregate': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'set-community': {'v_range': [['7.0.2', '']], 'type': 'raw'},
                        'set-community-additive': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'set-community-delete': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'set-dampening-max-suppress': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'set-dampening-reachability-half-life': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'set-dampening-reuse': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'set-dampening-suppress': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'set-dampening-unreachability-half-life': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'set-extcommunity-rt': {'v_range': [['7.0.2', '']], 'type': 'raw'},
                        'set-extcommunity-soo': {'v_range': [['7.0.2', '']], 'type': 'raw'},
                        'set-flags': {'v_range': [['7.0.2', '']], 'type': 'int'},
                        'set-ip-nexthop': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'set-ip6-nexthop': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'set-ip6-nexthop-local': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'set-local-preference': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'set-metric': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'set-metric-type': {'v_range': [['7.0.2', '']], 'choices': ['1', '2', 'none', 'external-type1', 'external-type2'], 'type': 'str'},
                        'set-origin': {'v_range': [['7.0.2', '']], 'choices': ['none', 'egp', 'igp', 'incomplete'], 'type': 'str'},
                        'set-originator-id': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'set-priority': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'set-route-tag': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'set-tag': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'set-weight': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'match-extcommunity': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'match-extcommunity-exact': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'set-ip-prefsrc': {'v_range': [['7.4.0', '']], 'type': 'str'},
                        'set-vpnv4-nexthop': {'v_range': [['7.4.1', '']], 'type': 'str'},
                        'set-vpnv6-nexthop': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'set-vpnv6-nexthop-local': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'match-suppress': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_routemap'),
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
