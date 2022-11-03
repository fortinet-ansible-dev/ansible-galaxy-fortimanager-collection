#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2020-2021 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_move
short_description: Move fortimanager defined Object.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    bypass_validation:
        description: only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    move:
        description: the top level parameters set
        type: dict
        required: false
'''

EXAMPLES = '''
- hosts: fortimanager01
  collections:
   - fortinet.fortimanager
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: True
    ansible_httpapi_validate_certs: False
    ansible_httpapi_port: 443
  tasks:
   - name: Move a firewall vip object
     fmgr_move:
       move:
         selector: 'firewall_vip'
         target: 'ansible-test-vip_first'
         action: 'before'
         self:
           adom: 'root'
           vip: 'ansible-test-vip_second'
'''

RETURN = '''
request_url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
response_code:
    description: The status of api request
    returned: always
    type: int
    sample: 0
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager


def main():
    move_metadata = {
        'ips_sensor_entries': {
            'params': [
                'adom',
                'sensor',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'ips_sensor_filter': {
            'params': [
                'adom',
                'sensor',
                'filter'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/filter/{filter}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'application_list_entries': {
            'params': [
                'adom',
                'list',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'application_list_entries_parameters': {
            'params': [
                'adom',
                'list',
                'entries',
                'parameters'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters/{parameters}',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters/{parameters}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'spamfilter_bwl_entries': {
            'params': [
                'adom',
                'bwl',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_bword_entries': {
            'params': [
                'adom',
                'bword',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bword/{bword}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'system_sdnconnector_externalip': {
            'params': [
                'adom',
                'sdn-connector',
                'external-ip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-ip/{external-ip}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-ip/{external-ip}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_sdnconnector_nic': {
            'params': [
                'adom',
                'sdn-connector',
                'nic'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_sdnconnector_nic_ip': {
            'params': [
                'adom',
                'sdn-connector',
                'nic',
                'ip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip/{ip}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip/{ip}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_sdnconnector_routetable': {
            'params': [
                'adom',
                'sdn-connector',
                'route-table'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_sdnconnector_routetable_route': {
            'params': [
                'adom',
                'sdn-connector',
                'route-table',
                'route'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route/{route}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route/{route}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_sdnconnector_route': {
            'params': [
                'adom',
                'sdn-connector',
                'route'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route/{route}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route/{route}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'sshfilter_profile_shellcommands': {
            'params': [
                'adom',
                'profile',
                'shell-commands'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/shell-commands/{shell-commands}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}/shell-commands/{shell-commands}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'webfilter_contentheader_entries': {
            'params': [
                'adom',
                'content-header',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content-header/{content-header}/entries/{entries}',
                '/pm/config/global/obj/webfilter/content-header/{content-header}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'webfilter_urlfilter_entries': {
            'params': [
                'adom',
                'urlfilter',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}/entries/{entries}',
                '/pm/config/global/obj/webfilter/urlfilter/{urlfilter}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_carrierendpointbwl_entries': {
            'params': [
                'adom',
                'carrier-endpoint-bwl',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries/{entries}',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'firewall_identitybasedroute': {
            'params': [
                'adom',
                'identity-based-route'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}',
                '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_service_category': {
            'params': [
                'adom',
                'category'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/category/{category}',
                '/pm/config/global/obj/firewall/service/category/{category}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_service_custom': {
            'params': [
                'adom',
                'custom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/custom/{custom}',
                '/pm/config/global/obj/firewall/service/custom/{custom}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_shapingprofile_shapingentries': {
            'params': [
                'adom',
                'shaping-profile',
                'shaping-entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}',
                '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_vip': {
            'params': [
                'adom',
                'vip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}',
                '/pm/config/global/obj/firewall/vip/{vip}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_vip6': {
            'params': [
                'adom',
                'vip6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}',
                '/pm/config/global/obj/firewall/vip6/{vip6}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'vpnsslweb_portal_bookmarkgroup': {
            'params': [
                'adom',
                'portal',
                'bookmark-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks': {
            'params': [
                'adom',
                'portal',
                'bookmark-group',
                'bookmarks'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'vpnsslweb_portal_splitdns': {
            'params': [
                'adom',
                'portal',
                'split-dns'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_central_dnat': {
            'params': [
                'adom',
                'pkg',
                'dnat'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat/{dnat}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'wanprof_system_virtualwanlink_members': {
            'params': [
                'adom',
                'wanprof',
                'members'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/members/{members}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'wanprof_system_virtualwanlink_service': {
            'params': [
                'adom',
                'wanprof',
                'service'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service/{service}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'wanprof_system_virtualwanlink_service_sla': {
            'params': [
                'adom',
                'wanprof',
                'service',
                'sla'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service/{service}/sla/{sla}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'switchcontroller_managedswitch': {
            'params': [
                'adom',
                'managed-switch'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_centralsnatmap': {
            'params': [
                'adom',
                'pkg',
                'central-snat-map'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/central-snat-map/{central-snat-map}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_dospolicy': {
            'params': [
                'adom',
                'pkg',
                'DoS-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{DoS-policy}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_dospolicy6': {
            'params': [
                'adom',
                'pkg',
                'DoS-policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_interfacepolicy': {
            'params': [
                'adom',
                'pkg',
                'interface-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy/{interface-policy}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_interfacepolicy6': {
            'params': [
                'adom',
                'pkg',
                'interface-policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy6/{interface-policy6}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_localinpolicy': {
            'params': [
                'adom',
                'pkg',
                'local-in-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy/{local-in-policy}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_localinpolicy6': {
            'params': [
                'adom',
                'pkg',
                'local-in-policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy6/{local-in-policy6}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_multicastpolicy': {
            'params': [
                'adom',
                'pkg',
                'multicast-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy/{multicast-policy}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_multicastpolicy6': {
            'params': [
                'adom',
                'pkg',
                'multicast-policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy6/{multicast-policy6}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_policy': {
            'params': [
                'adom',
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_policy46': {
            'params': [
                'adom',
                'pkg',
                'policy46'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy46/{policy46}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True
            }
        },
        'pkg_firewall_policy6': {
            'params': [
                'adom',
                'pkg',
                'policy6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy6/{policy6}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'pkg_firewall_policy64': {
            'params': [
                'adom',
                'pkg',
                'policy64'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy64/{policy64}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True
            }
        },
        'pkg_firewall_proxypolicy': {
            'params': [
                'adom',
                'pkg',
                'proxy-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/proxy-policy/{proxy-policy}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_firewall_shapingpolicy': {
            'params': [
                'adom',
                'pkg',
                'shaping-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/shaping-policy/{shaping-policy}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'dnsfilter_domainfilter_entries': {
            'params': [
                'adom',
                'domain-filter',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}/entries/{entries}',
                '/pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'bonjourprofile_policylist': {
            'params': [
                'adom',
                'bonjour-profile',
                'policy-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}',
                '/pm/config/global/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'dlp_filepattern_entries': {
            'params': [
                'adom',
                'filepattern',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}/entries/{entries}',
                '/pm/config/global/obj/dlp/filepattern/{filepattern}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'dlp_sensor_filter': {
            'params': [
                'adom',
                'sensor',
                'filter'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/dlp/sensor/{sensor}/filter/{filter}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True
            }
        },
        'cifs_profile_filefilter_entries': {
            'params': [
                'profile',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cifs/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/file-filter/entries/{entries}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'application_list_defaultnetworkservices': {
            'params': [
                'list',
                'default-network-services',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/list/{list}/default-network-services/{default-network-services}',
                '/pm/config/adom/{adom}/obj/application/list/{list}/default-network-services/{default-network-services}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'emailfilter_bword_entries': {
            'params': [
                'bword',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/bword/{bword}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/bword/{bword}/entries/{entries}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'emailfilter_bwl_entries': {
            'params': [
                'bwl',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/bwl/{bwl}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/bwl/{bwl}/entries/{entries}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'emailfilter_profile_filefilter_entries': {
            'params': [
                'profile',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'pkg_authentication_rule': {
            'params': [
                'adom',
                'pkg',
                'rule'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/authentication/rule/{rule}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'webfilter_profile_filefilter_entries': {
            'params': [
                'profile',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/webfilter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'pkg_firewall_consolidated_policy': {
            'params': [
                'adom',
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/consolidated/policy/{policy}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'pkg_firewall_securitypolicy': {
            'params': [
                'adom',
                'pkg',
                'security-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy/{security-policy}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'sshfilter_profile_filefilter_entries': {
            'params': [
                'profile',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/ssh-filter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'filefilter_profile_rules': {
            'params': [
                'profile',
                'rules',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/file-filter/profile/{profile}/rules/{rules}',
                '/pm/config/adom/{adom}/obj/file-filter/profile/{profile}/rules/{rules}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'mpskprofile_mpskgroup': {
            'params': [
                'mpsk-profile',
                'mpsk-group',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}',
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'mpskprofile_mpskgroup_mpskkey': {
            'params': [
                'mpsk-profile',
                'mpsk-group',
                'mpsk-key',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}',
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_profileprotocoloptions_cifs_filefilter_entries': {
            'params': [
                'profile-protocol-options',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries/{entries}',
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries/{entries}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'vpn_ssl_settings_authenticationrule': {
            'params': [
                'device',
                'vdom',
                'authentication-rule'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule/{authentication-rule}'
            ],
            'revision': {
                '6.4.2': True
            }
        },
        'wanprof_system_sdwan_members': {
            'params': [
                'adom',
                'wanprof',
                'members'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/members/{members}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'wanprof_system_sdwan_service': {
            'params': [
                'adom',
                'wanprof',
                'service'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service/{service}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'wanprof_system_sdwan_service_sla': {
            'params': [
                'adom',
                'wanprof',
                'service',
                'sla'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service/{service}/sla/{sla}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'wanprof_system_sdwan_zone': {
            'params': [
                'adom',
                'wanprof',
                'zone'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/zone/{zone}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pkg_central_dnat6': {
            'params': [
                'adom',
                'pkg',
                'dnat6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat6/{dnat6}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_accessproxy': {
            'params': [
                'access-proxy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'emailfilter_blockallowlist_entries': {
            'params': [
                'block-allow-list',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'apcfgprofile_commandlist': {
            'params': [
                'apcfg-profile',
                'command-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}',
                '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'videofilter_youtubechannelfilter_entries': {
            'params': [
                'youtube-channel-filter',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries/{entries}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'videofilter_profile_fortiguardcategory_filters': {
            'params': [
                'profile',
                'filters',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/videofilter/profile/{profile}/fortiguard-category/filters/{filters}',
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/fortiguard-category/filters/{filters}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pm_config_pblock_firewall_policy': {
            'params': [
                'adom',
                'pblock',
                'policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy/{policy}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'pkg_firewall_acl': {
            'params': [
                'adom',
                'pkg',
                'acl'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl/{acl}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'pkg_firewall_acl6': {
            'params': [
                'adom',
                'pkg',
                'acl6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl6/{acl6}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'pm_config_pblock_firewall_securitypolicy': {
            'params': [
                'adom',
                'pblock',
                'security-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/security-policy/{security-policy}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'firewall_accessproxyvirtualhost': {
            'params': [
                'access-proxy-virtual-host',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'endpointcontrol_fctems': {
            'params': [
                'fctems',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/endpoint-control/fctems/{fctems}',
                '/pm/config/adom/{adom}/obj/endpoint-control/fctems/{fctems}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'vpn_ipsec_fec_mappings': {
            'params': [
                'fec',
                'mappings',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}',
                '/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'extendercontroller_extenderprofile_cellular_smsnotification_receiver': {
            'params': [
                'extender-profile',
                'receiver',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'extendercontroller_extenderprofile_lanextension_backhaul': {
            'params': [
                'extender-profile',
                'backhaul',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'vap_vlanname': {
            'params': [
                'vap',
                'vlan-name',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-name/{vlan-name}',
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-name/{vlan-name}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_sdnconnector_gcpprojectlist': {
            'params': [
                'sdn-connector',
                'gcp-project-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/gcp-project-list/{gcp-project-list}',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/gcp-project-list/{gcp-project-list}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_sdnconnector_forwardingrule': {
            'params': [
                'sdn-connector',
                'forwarding-rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/forwarding-rule/{forwarding-rule}',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/forwarding-rule/{forwarding-rule}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_sdnconnector_externalaccountlist': {
            'params': [
                'sdn-connector',
                'external-account-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-account-list/{external-account-list}',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-account-list/{external-account-list}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'dlp_sensor_entries': {
            'params': [
                'sensor',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/sensor/{sensor}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/entries/{entries}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'dlp_dictionary_entries': {
            'params': [
                'dictionary',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/dictionary/{dictionary}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/dlp/dictionary/{dictionary}/entries/{entries}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'dlp_profile_rule': {
            'params': [
                'profile',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/profile/{profile}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/dlp/profile/{profile}/rule/{rule}'
            ],
            'revision': {
                '7.2.0': True
            }
        }
    }

    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'move': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': [
                        'ips_sensor_entries',
                        'ips_sensor_filter',
                        'application_list_entries',
                        'application_list_entries_parameters',
                        'spamfilter_bwl_entries',
                        'spamfilter_bword_entries',
                        'system_sdnconnector_externalip',
                        'system_sdnconnector_nic',
                        'system_sdnconnector_nic_ip',
                        'system_sdnconnector_routetable',
                        'system_sdnconnector_routetable_route',
                        'system_sdnconnector_route',
                        'sshfilter_profile_shellcommands',
                        'webfilter_contentheader_entries',
                        'webfilter_urlfilter_entries',
                        'firewall_carrierendpointbwl_entries',
                        'firewall_identitybasedroute',
                        'firewall_service_category',
                        'firewall_service_custom',
                        'firewall_shapingprofile_shapingentries',
                        'firewall_vip',
                        'firewall_vip6',
                        'vpnsslweb_portal_bookmarkgroup',
                        'vpnsslweb_portal_bookmarkgroup_bookmarks',
                        'vpnsslweb_portal_splitdns',
                        'pkg_central_dnat',
                        'wanprof_system_virtualwanlink_members',
                        'wanprof_system_virtualwanlink_service',
                        'wanprof_system_virtualwanlink_service_sla',
                        'switchcontroller_managedswitch',
                        'pkg_firewall_centralsnatmap',
                        'pkg_firewall_dospolicy',
                        'pkg_firewall_dospolicy6',
                        'pkg_firewall_interfacepolicy',
                        'pkg_firewall_interfacepolicy6',
                        'pkg_firewall_localinpolicy',
                        'pkg_firewall_localinpolicy6',
                        'pkg_firewall_multicastpolicy',
                        'pkg_firewall_multicastpolicy6',
                        'pkg_firewall_policy',
                        'pkg_firewall_policy46',
                        'pkg_firewall_policy6',
                        'pkg_firewall_policy64',
                        'pkg_firewall_proxypolicy',
                        'pkg_firewall_shapingpolicy',
                        'dnsfilter_domainfilter_entries',
                        'bonjourprofile_policylist',
                        'dlp_filepattern_entries',
                        'dlp_sensor_filter',
                        'cifs_profile_filefilter_entries',
                        'application_list_defaultnetworkservices',
                        'emailfilter_bword_entries',
                        'emailfilter_bwl_entries',
                        'emailfilter_profile_filefilter_entries',
                        'pkg_authentication_rule',
                        'webfilter_profile_filefilter_entries',
                        'pkg_firewall_consolidated_policy',
                        'pkg_firewall_securitypolicy',
                        'sshfilter_profile_filefilter_entries',
                        'filefilter_profile_rules',
                        'mpskprofile_mpskgroup',
                        'mpskprofile_mpskgroup_mpskkey',
                        'firewall_profileprotocoloptions_cifs_filefilter_entries',
                        'vpn_ssl_settings_authenticationrule',
                        'wanprof_system_sdwan_members',
                        'wanprof_system_sdwan_service',
                        'wanprof_system_sdwan_service_sla',
                        'wanprof_system_sdwan_zone',
                        'pkg_central_dnat6',
                        'firewall_accessproxy',
                        'emailfilter_blockallowlist_entries',
                        'apcfgprofile_commandlist',
                        'videofilter_youtubechannelfilter_entries',
                        'videofilter_profile_fortiguardcategory_filters',
                        'pm_config_pblock_firewall_policy',
                        'pkg_firewall_acl',
                        'pkg_firewall_acl6',
                        'pm_config_pblock_firewall_securitypolicy',
                        'firewall_accessproxyvirtualhost',
                        'endpointcontrol_fctems',
                        'vpn_ipsec_fec_mappings',
                        'extendercontroller_extenderprofile_cellular_smsnotification_receiver',
                        'extendercontroller_extenderprofile_lanextension_backhaul',
                        'vap_vlanname',
                        'system_sdnconnector_gcpprojectlist',
                        'system_sdnconnector_forwardingrule',
                        'system_sdnconnector_externalaccountlist',
                        'dlp_sensor_entries',
                        'dlp_dictionary_entries',
                        'dlp_profile_rule'
                    ]
                },
                'self': {
                    'required': True,
                    'type': 'dict'
                },
                'target': {
                    'required': True,
                    'type': 'str'
                },
                'action': {
                    'required': True,
                    'type': 'str',
                    'choices': [
                        'after',
                        'before'
                    ]
                }
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(None, None, None, None, module, connection)
        fmgr.process_move(move_metadata)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
