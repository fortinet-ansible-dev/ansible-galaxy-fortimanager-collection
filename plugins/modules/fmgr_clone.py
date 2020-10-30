#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2020 Fortinet, Inc.
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
module: fmgr_clone
short_description: Clone an object in FortiManager.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10"
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
    clone:
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
   - name: clone an vip object using fmgr_clone module.
     fmgr_clone:
       clone:
        selector: 'firewall_vip'
        self:
          adom: 'root'
          vip: 'ansible-test-vip_first'
        target:
          name: 'ansible-test-vip_fourth'
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
    clone_metadata = {
        'dnsfilter_domainfilter': {
            'params': [
                'adom',
                'domain-filter'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}',
                '/pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}'
            ],
            'mkey': 'id'
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
            'mkey': 'id'
        },
        'dnsfilter_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}',
                '/pm/config/global/obj/dnsfilter/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'dnsfilter_profile_ftgddns_filters': {
            'params': [
                'adom',
                'profile',
                'filters'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/ftgd-dns/filters/{filters}',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/ftgd-dns/filters/{filters}'
            ],
            'mkey': 'id'
        },
        'webproxy_forwardservergroup': {
            'params': [
                'adom',
                'forward-server-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{forward-server-group}',
                '/pm/config/global/obj/web-proxy/forward-server-group/{forward-server-group}'
            ],
            'mkey': 'name'
        },
        'webproxy_forwardservergroup_serverlist': {
            'params': [
                'adom',
                'forward-server-group',
                'server-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{forward-server-group}/server-list/{server-list}',
                '/pm/config/global/obj/web-proxy/forward-server-group/{forward-server-group}/server-list/{server-list}'
            ],
            'mkey': 'name'
        },
        'webproxy_forwardserver': {
            'params': [
                'adom',
                'forward-server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server/{forward-server}',
                '/pm/config/global/obj/web-proxy/forward-server/{forward-server}'
            ],
            'mkey': 'name'
        },
        'webproxy_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/profile/{profile}',
                '/pm/config/global/obj/web-proxy/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'webproxy_profile_headers': {
            'params': [
                'adom',
                'profile',
                'headers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/profile/{profile}/headers/{headers}',
                '/pm/config/global/obj/web-proxy/profile/{profile}/headers/{headers}'
            ],
            'mkey': 'id'
        },
        'webproxy_wisp': {
            'params': [
                'adom',
                'wisp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/wisp/{wisp}',
                '/pm/config/global/obj/web-proxy/wisp/{wisp}'
            ],
            'mkey': 'name'
        },
        'log_customfield': {
            'params': [
                'adom',
                'custom-field'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/log/custom-field/{custom-field}',
                '/pm/config/global/obj/log/custom-field/{custom-field}'
            ],
            'mkey': 'id'
        },
        'voip_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/voip/profile/{profile}',
                '/pm/config/global/obj/voip/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'icap_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}',
                '/pm/config/global/obj/icap/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'icap_server': {
            'params': [
                'adom',
                'server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/server/{server}',
                '/pm/config/global/obj/icap/server/{server}'
            ],
            'mkey': 'name'
        },
        'gtp_apn': {
            'params': [
                'adom',
                'apn'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/apn/{apn}',
                '/pm/config/global/obj/gtp/apn/{apn}'
            ],
            'mkey': 'name'
        },
        'gtp_apngrp': {
            'params': [
                'adom',
                'apngrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/apngrp/{apngrp}',
                '/pm/config/global/obj/gtp/apngrp/{apngrp}'
            ],
            'mkey': 'name'
        },
        'gtp_iewhitelist': {
            'params': [
                'adom',
                'ie-white-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list/{ie-white-list}',
                '/pm/config/global/obj/gtp/ie-white-list/{ie-white-list}'
            ],
            'mkey': 'name'
        },
        'gtp_iewhitelist_entries': {
            'params': [
                'adom',
                'ie-white-list',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list/{ie-white-list}/entries/{entries}',
                '/pm/config/global/obj/gtp/ie-white-list/{ie-white-list}/entries/{entries}'
            ],
            'mkey': 'id'
        },
        'gtp_messagefilterv0v1': {
            'params': [
                'adom',
                'message-filter-v0v1'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v0v1/{message-filter-v0v1}',
                '/pm/config/global/obj/gtp/message-filter-v0v1/{message-filter-v0v1}'
            ],
            'mkey': 'name'
        },
        'gtp_messagefilterv2': {
            'params': [
                'adom',
                'message-filter-v2'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v2/{message-filter-v2}',
                '/pm/config/global/obj/gtp/message-filter-v2/{message-filter-v2}'
            ],
            'mkey': 'name'
        },
        'gtp_tunnellimit': {
            'params': [
                'adom',
                'tunnel-limit'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/tunnel-limit/{tunnel-limit}',
                '/pm/config/global/obj/gtp/tunnel-limit/{tunnel-limit}'
            ],
            'mkey': 'name'
        },
        'application_categories': {
            'params': [
                'adom',
                'categories'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/categories/{categories}',
                '/pm/config/global/obj/application/categories/{categories}'
            ],
            'mkey': 'id'
        },
        'application_custom': {
            'params': [
                'adom',
                'custom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/custom/{custom}',
                '/pm/config/global/obj/application/custom/{custom}'
            ],
            'mkey': 'tag'
        },
        'application_group': {
            'params': [
                'adom',
                'group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/group/{group}',
                '/pm/config/global/obj/application/group/{group}'
            ],
            'mkey': 'name'
        },
        'application_list': {
            'params': [
                'adom',
                'list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}',
                '/pm/config/global/obj/application/list/{list}'
            ],
            'mkey': 'name'
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
            'mkey': 'id'
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
            'mkey': 'id'
        },
        'vpn_certificate_ca': {
            'params': [
                'adom',
                'ca'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/ca/{ca}',
                '/pm/config/global/obj/vpn/certificate/ca/{ca}'
            ],
            'mkey': 'name'
        },
        'vpn_certificate_ocspserver': {
            'params': [
                'adom',
                'ocsp-server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server/{ocsp-server}',
                '/pm/config/global/obj/vpn/certificate/ocsp-server/{ocsp-server}'
            ],
            'mkey': 'name'
        },
        'vpn_certificate_remote': {
            'params': [
                'adom',
                'remote'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/remote/{remote}',
                '/pm/config/global/obj/vpn/certificate/remote/{remote}'
            ],
            'mkey': 'name'
        },
        'vpnsslweb_hostchecksoftware': {
            'params': [
                'adom',
                'host-check-software'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}'
            ],
            'mkey': 'name'
        },
        'vpnsslweb_hostchecksoftware_checkitemlist': {
            'params': [
                'adom',
                'host-check-software',
                'check-item-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list/{check-item-list}',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list/{check-item-list}'
            ],
            'mkey': 'id'
        },
        'vpnsslweb_portal': {
            'params': [
                'adom',
                'portal'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}'
            ],
            'mkey': 'name'
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
            'mkey': 'name'
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
            'mkey': 'name'
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks_formdata': {
            'params': [
                'adom',
                'portal',
                'bookmark-group',
                'bookmarks',
                'form-data'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data/{form-data}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data/{form-data}'
            ],
            'mkey': 'name'
        },
        'vpnsslweb_portal_macaddrcheckrule': {
            'params': [
                'adom',
                'portal',
                'mac-addr-check-rule'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule/{mac-addr-check-rule}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule/{mac-addr-check-rule}'
            ],
            'mkey': 'name'
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
            'mkey': 'id'
        },
        'vpnsslweb_realm': {
            'params': [
                'adom',
                'realm'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/realm/{realm}',
                '/pm/config/global/obj/vpn/ssl/web/realm/{realm}'
            ],
            'mkey': None
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
            'mkey': 'policyid'
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
            'mkey': 'policyid'
        },
        'pkg_firewall_dospolicy_anomaly': {
            'params': [
                'adom',
                'pkg',
                'DoS-policy',
                'anomaly'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{DoS-policy}/anomaly/{anomaly}'
            ],
            'mkey': 'name'
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
            'mkey': 'policyid'
        },
        'pkg_firewall_dospolicy6_anomaly': {
            'params': [
                'adom',
                'pkg',
                'DoS-policy6',
                'anomaly'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}/anomaly/{anomaly}'
            ],
            'mkey': 'name'
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
            'mkey': 'policyid'
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
            'mkey': 'policyid'
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
            'mkey': 'policyid'
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
            'mkey': 'policyid'
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
            'mkey': 'id'
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
            'mkey': 'id'
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
            'mkey': 'policyid'
        },
        'pkg_firewall_policy_vpndstnode': {
            'params': [
                'adom',
                'pkg',
                'policy',
                'vpn_dst_node'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_dst_node/{vpn_dst_node}'
            ],
            'mkey': 'seq'
        },
        'pkg_firewall_policy_vpnsrcnode': {
            'params': [
                'adom',
                'pkg',
                'policy',
                'vpn_src_node'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_src_node/{vpn_src_node}'
            ],
            'mkey': 'seq'
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
            'mkey': 'policyid'
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
            'mkey': 'policyid'
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
            'mkey': 'policyid'
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
            'mkey': 'policyid'
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
            'mkey': 'id'
        },
        'dvmdb_revision': {
            'params': [
                'adom',
                'revision'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/revision/{revision}',
                '/dvmdb/global/revision/{revision}',
                '/dvmdb/revision/{revision}'
            ],
            'mkey': 'name'
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
            'mkey': 'name'
        },
        'user_adgrp': {
            'params': [
                'adom',
                'adgrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/adgrp/{adgrp}',
                '/pm/config/global/obj/user/adgrp/{adgrp}'
            ],
            'mkey': 'name'
        },
        'user_devicecategory': {
            'params': [
                'adom',
                'device-category'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-category/{device-category}',
                '/pm/config/global/obj/user/device-category/{device-category}'
            ],
            'mkey': 'name'
        },
        'user_devicegroup': {
            'params': [
                'adom',
                'device-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}',
                '/pm/config/global/obj/user/device-group/{device-group}'
            ],
            'mkey': 'name'
        },
        'user_devicegroup_dynamicmapping': {
            'params': [
                'adom',
                'device-group',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/device-group/{device-group}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'user_devicegroup_tagging': {
            'params': [
                'adom',
                'device-group',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/tagging/{tagging}',
                '/pm/config/global/obj/user/device-group/{device-group}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'user_device': {
            'params': [
                'adom',
                'device'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}',
                '/pm/config/global/obj/user/device/{device}'
            ],
            'mkey': 'alias'
        },
        'user_device_dynamicmapping': {
            'params': [
                'adom',
                'device',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'user_device_tagging': {
            'params': [
                'adom',
                'device',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}/tagging/{tagging}',
                '/pm/config/global/obj/user/device/{device}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'user_fortitoken': {
            'params': [
                'adom',
                'fortitoken'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fortitoken/{fortitoken}',
                '/pm/config/global/obj/user/fortitoken/{fortitoken}'
            ],
            'mkey': 'serial-number'
        },
        'user_fssopolling': {
            'params': [
                'adom',
                'fsso-polling'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso-polling/{fsso-polling}',
                '/pm/config/global/obj/user/fsso-polling/{fsso-polling}'
            ],
            'mkey': 'id'
        },
        'user_fssopolling_adgrp': {
            'params': [
                'adom',
                'fsso-polling',
                'adgrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso-polling/{fsso-polling}/adgrp/{adgrp}',
                '/pm/config/global/obj/user/fsso-polling/{fsso-polling}/adgrp/{adgrp}'
            ],
            'mkey': 'name'
        },
        'user_fsso': {
            'params': [
                'adom',
                'fsso'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso/{fsso}',
                '/pm/config/global/obj/user/fsso/{fsso}'
            ],
            'mkey': 'name'
        },
        'user_fsso_dynamicmapping': {
            'params': [
                'adom',
                'fsso',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'user_group': {
            'params': [
                'adom',
                'group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}',
                '/pm/config/global/obj/user/group/{group}'
            ],
            'mkey': 'name'
        },
        'user_group_guest': {
            'params': [
                'adom',
                'group',
                'guest'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/guest/{guest}',
                '/pm/config/global/obj/user/group/{group}/guest/{guest}'
            ],
            'mkey': 'user-id'
        },
        'user_group_match': {
            'params': [
                'adom',
                'group',
                'match'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/match/{match}',
                '/pm/config/global/obj/user/group/{group}/match/{match}'
            ],
            'mkey': 'id'
        },
        'user_ldap': {
            'params': [
                'adom',
                'ldap'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/ldap/{ldap}',
                '/pm/config/global/obj/user/ldap/{ldap}'
            ],
            'mkey': 'name'
        },
        'user_ldap_dynamicmapping': {
            'params': [
                'adom',
                'ldap',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/ldap/{ldap}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/ldap/{ldap}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'user_local': {
            'params': [
                'adom',
                'local'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/local/{local}',
                '/pm/config/global/obj/user/local/{local}'
            ],
            'mkey': 'name'
        },
        'user_passwordpolicy': {
            'params': [
                'adom',
                'password-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/password-policy/{password-policy}',
                '/pm/config/global/obj/user/password-policy/{password-policy}'
            ],
            'mkey': 'name'
        },
        'user_peer': {
            'params': [
                'adom',
                'peer'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/peer/{peer}',
                '/pm/config/global/obj/user/peer/{peer}'
            ],
            'mkey': 'name'
        },
        'user_peergrp': {
            'params': [
                'adom',
                'peergrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/peergrp/{peergrp}',
                '/pm/config/global/obj/user/peergrp/{peergrp}'
            ],
            'mkey': 'name'
        },
        'user_pop3': {
            'params': [
                'adom',
                'pop3'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/pop3/{pop3}',
                '/pm/config/global/obj/user/pop3/{pop3}'
            ],
            'mkey': 'name'
        },
        'user_pxgrid': {
            'params': [
                'adom',
                'pxgrid'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/pxgrid/{pxgrid}',
                '/pm/config/global/obj/user/pxgrid/{pxgrid}'
            ],
            'mkey': 'name'
        },
        'user_radius': {
            'params': [
                'adom',
                'radius'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}',
                '/pm/config/global/obj/user/radius/{radius}'
            ],
            'mkey': 'name'
        },
        'user_radius_accountingserver': {
            'params': [
                'adom',
                'radius',
                'accounting-server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/accounting-server/{accounting-server}',
                '/pm/config/global/obj/user/radius/{radius}/accounting-server/{accounting-server}'
            ],
            'mkey': 'id'
        },
        'user_radius_dynamicmapping': {
            'params': [
                'adom',
                'radius',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'user_securityexemptlist': {
            'params': [
                'adom',
                'security-exempt-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/security-exempt-list/{security-exempt-list}',
                '/pm/config/global/obj/user/security-exempt-list/{security-exempt-list}'
            ],
            'mkey': 'name'
        },
        'user_securityexemptlist_rule': {
            'params': [
                'adom',
                'security-exempt-list',
                'rule'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/security-exempt-list/{security-exempt-list}/rule/{rule}',
                '/pm/config/global/obj/user/security-exempt-list/{security-exempt-list}/rule/{rule}'
            ],
            'mkey': 'id'
        },
        'user_tacacs': {
            'params': [
                'adom',
                'tacacs+'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/tacacs+/{tacacs+}',
                '/pm/config/global/obj/user/tacacs+/{tacacs+}'
            ],
            'mkey': 'name'
        },
        'user_tacacs_dynamicmapping': {
            'params': [
                'adom',
                'tacacs+',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/tacacs+/{tacacs+}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/tacacs+/{tacacs+}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'webfilter_categories': {
            'params': [
                'adom',
                'categories'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/categories/{categories}',
                '/pm/config/global/obj/webfilter/categories/{categories}'
            ],
            'mkey': 'id'
        },
        'webfilter_contentheader': {
            'params': [
                'adom',
                'content-header'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content-header/{content-header}',
                '/pm/config/global/obj/webfilter/content-header/{content-header}'
            ],
            'mkey': 'id'
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
            'mkey': None
        },
        'webfilter_content': {
            'params': [
                'adom',
                'content'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content/{content}',
                '/pm/config/global/obj/webfilter/content/{content}'
            ],
            'mkey': 'id'
        },
        'webfilter_content_entries': {
            'params': [
                'adom',
                'content',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content/{content}/entries/{entries}',
                '/pm/config/global/obj/webfilter/content/{content}/entries/{entries}'
            ],
            'mkey': 'name'
        },
        'webfilter_ftgdlocalcat': {
            'params': [
                'adom',
                'ftgd-local-cat'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-cat/{ftgd-local-cat}',
                '/pm/config/global/obj/webfilter/ftgd-local-cat/{ftgd-local-cat}'
            ],
            'mkey': 'id'
        },
        'webfilter_ftgdlocalrating': {
            'params': [
                'adom',
                'ftgd-local-rating'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-rating/{ftgd-local-rating}',
                '/pm/config/global/obj/webfilter/ftgd-local-rating/{ftgd-local-rating}'
            ],
            'mkey': 'rating'
        },
        'webfilter_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}',
                '/pm/config/global/obj/webfilter/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'webfilter_profile_ftgdwf_filters': {
            'params': [
                'adom',
                'profile',
                'filters'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/filters/{filters}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/filters/{filters}'
            ],
            'mkey': 'id'
        },
        'webfilter_profile_ftgdwf_quota': {
            'params': [
                'adom',
                'profile',
                'quota'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/quota/{quota}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/quota/{quota}'
            ],
            'mkey': 'id'
        },
        'webfilter_profile_youtubechannelfilter': {
            'params': [
                'adom',
                'profile',
                'youtube-channel-filter'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/youtube-channel-filter/{youtube-channel-filter}',
                '/pm/config/global/obj/webfilter/profile/{profile}/youtube-channel-filter/{youtube-channel-filter}'
            ],
            'mkey': 'id'
        },
        'webfilter_urlfilter': {
            'params': [
                'adom',
                'urlfilter'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}',
                '/pm/config/global/obj/webfilter/urlfilter/{urlfilter}'
            ],
            'mkey': 'id'
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
            'mkey': 'id'
        },
        'wanopt_authgroup': {
            'params': [
                'adom',
                'auth-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/auth-group/{auth-group}',
                '/pm/config/global/obj/wanopt/auth-group/{auth-group}'
            ],
            'mkey': 'name'
        },
        'wanopt_peer': {
            'params': [
                'adom',
                'peer'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/peer/{peer}',
                '/pm/config/global/obj/wanopt/peer/{peer}'
            ],
            'mkey': 'peer-host-id'
        },
        'wanopt_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}',
                '/pm/config/global/obj/wanopt/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'ips_custom': {
            'params': [
                'adom',
                'custom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/custom/{custom}',
                '/pm/config/global/obj/ips/custom/{custom}'
            ],
            'mkey': 'tag'
        },
        'ips_sensor': {
            'params': [
                'adom',
                'sensor'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}',
                '/pm/config/global/obj/ips/sensor/{sensor}'
            ],
            'mkey': 'name'
        },
        'ips_sensor_entries': {
            'params': [
                'adom',
                'sensor',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}'
            ],
            'mkey': 'id'
        },
        'ips_sensor_entries_exemptip': {
            'params': [
                'adom',
                'sensor',
                'entries',
                'exempt-ip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}'
            ],
            'mkey': 'id'
        },
        'ips_sensor_filter': {
            'params': [
                'adom',
                'sensor',
                'filter'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/ips/sensor/{sensor}/filter/{filter}'
            ],
            'mkey': 'name'
        },
        'ips_sensor_override': {
            'params': [
                'adom',
                'sensor',
                'override'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override/{override}',
                '/pm/config/global/obj/ips/sensor/{sensor}/override/{override}'
            ],
            'mkey': 'rule-id'
        },
        'ips_sensor_override_exemptip': {
            'params': [
                'adom',
                'sensor',
                'override',
                'exempt-ip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}'
            ],
            'mkey': 'id'
        },
        'vpnmgr_node': {
            'params': [
                'adom',
                'node'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}',
                '/pm/config/global/obj/vpnmgr/node/{node}'
            ],
            'mkey': 'id'
        },
        'vpnmgr_node_iprange': {
            'params': [
                'adom',
                'node',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ip-range/{ip-range}',
                '/pm/config/global/obj/vpnmgr/node/{node}/ip-range/{ip-range}'
            ],
            'mkey': 'id'
        },
        'vpnmgr_node_ipv4excluderange': {
            'params': [
                'adom',
                'node',
                'ipv4-exclude-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ipv4-exclude-range/{ipv4-exclude-range}',
                '/pm/config/global/obj/vpnmgr/node/{node}/ipv4-exclude-range/{ipv4-exclude-range}'
            ],
            'mkey': 'id'
        },
        'vpnmgr_node_protectedsubnet': {
            'params': [
                'adom',
                'node',
                'protected_subnet'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/protected_subnet/{protected_subnet}',
                '/pm/config/global/obj/vpnmgr/node/{node}/protected_subnet/{protected_subnet}'
            ],
            'mkey': 'seq'
        },
        'vpnmgr_node_summaryaddr': {
            'params': [
                'adom',
                'node',
                'summary_addr'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/summary_addr/{summary_addr}',
                '/pm/config/global/obj/vpnmgr/node/{node}/summary_addr/{summary_addr}'
            ],
            'mkey': 'seq'
        },
        'vpnmgr_vpntable': {
            'params': [
                'adom',
                'vpntable'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/vpntable/{vpntable}',
                '/pm/config/global/obj/vpnmgr/vpntable/{vpntable}'
            ],
            'mkey': 'name'
        },
        'spamfilter_bwl': {
            'params': [
                'adom',
                'bwl'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}'
            ],
            'mkey': 'id'
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
            'mkey': 'id'
        },
        'spamfilter_bword': {
            'params': [
                'adom',
                'bword'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}',
                '/pm/config/global/obj/spamfilter/bword/{bword}'
            ],
            'mkey': 'id'
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
            'mkey': 'id'
        },
        'spamfilter_dnsbl': {
            'params': [
                'adom',
                'dnsbl'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl/{dnsbl}',
                '/pm/config/global/obj/spamfilter/dnsbl/{dnsbl}'
            ],
            'mkey': 'id'
        },
        'spamfilter_dnsbl_entries': {
            'params': [
                'adom',
                'dnsbl',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl/{dnsbl}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/dnsbl/{dnsbl}/entries/{entries}'
            ],
            'mkey': 'id'
        },
        'spamfilter_iptrust': {
            'params': [
                'adom',
                'iptrust'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}',
                '/pm/config/global/obj/spamfilter/iptrust/{iptrust}'
            ],
            'mkey': 'id'
        },
        'spamfilter_iptrust_entries': {
            'params': [
                'adom',
                'iptrust',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/iptrust/{iptrust}/entries/{entries}'
            ],
            'mkey': 'id'
        },
        'spamfilter_mheader': {
            'params': [
                'adom',
                'mheader'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/mheader/{mheader}',
                '/pm/config/global/obj/spamfilter/mheader/{mheader}'
            ],
            'mkey': 'id'
        },
        'spamfilter_mheader_entries': {
            'params': [
                'adom',
                'mheader',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/mheader/{mheader}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/mheader/{mheader}/entries/{entries}'
            ],
            'mkey': 'id'
        },
        'spamfilter_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}',
                '/pm/config/global/obj/spamfilter/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'antivirus_mmschecksum': {
            'params': [
                'adom',
                'mms-checksum'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}',
                '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}'
            ],
            'mkey': 'id'
        },
        'antivirus_mmschecksum_entries': {
            'params': [
                'adom',
                'mms-checksum',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}/entries/{entries}',
                '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}/entries/{entries}'
            ],
            'mkey': 'name'
        },
        'antivirus_notification': {
            'params': [
                'adom',
                'notification'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/notification/{notification}',
                '/pm/config/global/obj/antivirus/notification/{notification}'
            ],
            'mkey': 'id'
        },
        'antivirus_notification_entries': {
            'params': [
                'adom',
                'notification',
                'entries'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/notification/{notification}/entries/{entries}',
                '/pm/config/global/obj/antivirus/notification/{notification}/entries/{entries}'
            ],
            'mkey': 'name'
        },
        'antivirus_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}',
                '/pm/config/global/obj/antivirus/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_lldpprofile': {
            'params': [
                'adom',
                'lldp-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_lldpprofile_customtlvs': {
            'params': [
                'adom',
                'lldp-profile',
                'custom-tlvs'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_lldpprofile_mednetworkpolicy': {
            'params': [
                'adom',
                'lldp-profile',
                'med-network-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}'
            ],
            'mkey': 'name'
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
            'mkey': 'name'
        },
        'switchcontroller_managedswitch_ports': {
            'params': [
                'adom',
                'managed-switch',
                'ports'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}'
            ],
            'mkey': 'port-name'
        },
        'switchcontroller_qos_dot1pmap': {
            'params': [
                'adom',
                'dot1p-map'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/dot1p-map/{dot1p-map}',
                '/pm/config/global/obj/switch-controller/qos/dot1p-map/{dot1p-map}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_qos_ipdscpmap': {
            'params': [
                'adom',
                'ip-dscp-map'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_qos_ipdscpmap_map': {
            'params': [
                'adom',
                'ip-dscp-map',
                'map'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_qos_qospolicy': {
            'params': [
                'adom',
                'qos-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/qos-policy/{qos-policy}',
                '/pm/config/global/obj/switch-controller/qos/qos-policy/{qos-policy}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_qos_queuepolicy': {
            'params': [
                'adom',
                'queue-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}',
                '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_qos_queuepolicy_cosqueue': {
            'params': [
                'adom',
                'queue-policy',
                'cos-queue'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}',
                '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_securitypolicy_8021x': {
            'params': [
                'adom',
                '802-1X'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/802-1X/{802-1X}',
                '/pm/config/global/obj/switch-controller/security-policy/802-1X/{802-1X}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_securitypolicy_captiveportal': {
            'params': [
                'adom',
                'captive-portal'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/captive-portal/{captive-portal}',
                '/pm/config/global/obj/switch-controller/security-policy/captive-portal/{captive-portal}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_managedswitch_customcommand': {
            'params': [
                'device',
                'vdom',
                'managed-switch',
                'custom-command'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}'
            ],
            'mkey': None
        },
        'switchcontroller_managedswitch_mirror': {
            'params': [
                'device',
                'vdom',
                'managed-switch',
                'mirror'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/mirror/{mirror}'
            ],
            'mkey': None
        },
        'firewall_address': {
            'params': [
                'adom',
                'address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}',
                '/pm/config/global/obj/firewall/address/{address}'
            ],
            'mkey': 'name'
        },
        'firewall_address_dynamicmapping': {
            'params': [
                'adom',
                'address',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'firewall_address_list': {
            'params': [
                'adom',
                'address',
                'list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/list/{list}',
                '/pm/config/global/obj/firewall/address/{address}/list/{list}'
            ],
            'mkey': 'ip'
        },
        'firewall_address_tagging': {
            'params': [
                'adom',
                'address',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/address/{address}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_address6template': {
            'params': [
                'adom',
                'address6-template'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}'
            ],
            'mkey': 'name'
        },
        'firewall_address6template_subnetsegment': {
            'params': [
                'adom',
                'address6-template',
                'subnet-segment'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}'
            ],
            'mkey': 'id'
        },
        'firewall_address6template_subnetsegment_values': {
            'params': [
                'adom',
                'address6-template',
                'subnet-segment',
                'values'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values/{values}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values/{values}'
            ],
            'mkey': 'name'
        },
        'firewall_address6': {
            'params': [
                'adom',
                'address6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}',
                '/pm/config/global/obj/firewall/address6/{address6}'
            ],
            'mkey': 'name'
        },
        'firewall_address6_dynamicmapping': {
            'params': [
                'adom',
                'address6',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'firewall_address6_list': {
            'params': [
                'adom',
                'address6',
                'list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/list/{list}',
                '/pm/config/global/obj/firewall/address6/{address6}/list/{list}'
            ],
            'mkey': 'ip'
        },
        'firewall_address6_subnetsegment': {
            'params': [
                'adom',
                'address6',
                'subnet-segment'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6/{address6}/subnet-segment/{subnet-segment}'
            ],
            'mkey': 'name'
        },
        'firewall_address6_tagging': {
            'params': [
                'adom',
                'address6',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/address6/{address6}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_addrgrp': {
            'params': [
                'adom',
                'addrgrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}'
            ],
            'mkey': 'name'
        },
        'firewall_addrgrp_dynamicmapping': {
            'params': [
                'adom',
                'addrgrp',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'firewall_addrgrp_tagging': {
            'params': [
                'adom',
                'addrgrp',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_addrgrp6': {
            'params': [
                'adom',
                'addrgrp6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}'
            ],
            'mkey': 'name'
        },
        'firewall_addrgrp6_dynamicmapping': {
            'params': [
                'adom',
                'addrgrp6',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'firewall_addrgrp6_tagging': {
            'params': [
                'adom',
                'addrgrp6',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_carrierendpointbwl': {
            'params': [
                'adom',
                'carrier-endpoint-bwl'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}'
            ],
            'mkey': 'id'
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
            'mkey': 'carrier-endpoint'
        },
        'firewall_gtp': {
            'params': [
                'adom',
                'gtp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}',
                '/pm/config/global/obj/firewall/gtp/{gtp}'
            ],
            'mkey': 'name'
        },
        'firewall_gtp_apn': {
            'params': [
                'adom',
                'gtp',
                'apn'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/apn/{apn}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/apn/{apn}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_ieremovepolicy': {
            'params': [
                'adom',
                'gtp',
                'ie-remove-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-remove-policy/{ie-remove-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ie-remove-policy/{ie-remove-policy}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_imsi': {
            'params': [
                'adom',
                'gtp',
                'imsi'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/imsi/{imsi}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/imsi/{imsi}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_ippolicy': {
            'params': [
                'adom',
                'gtp',
                'ip-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ip-policy/{ip-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ip-policy/{ip-policy}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_noippolicy': {
            'params': [
                'adom',
                'gtp',
                'noip-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/noip-policy/{noip-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/noip-policy/{noip-policy}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_perapnshaper': {
            'params': [
                'adom',
                'gtp',
                'per-apn-shaper'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/per-apn-shaper/{per-apn-shaper}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/per-apn-shaper/{per-apn-shaper}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_policy': {
            'params': [
                'adom',
                'gtp',
                'policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy/{policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/policy/{policy}'
            ],
            'mkey': 'id'
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
            'mkey': 'name'
        },
        'firewall_identitybasedroute_rule': {
            'params': [
                'adom',
                'identity-based-route',
                'rule'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}/rule/{rule}',
                '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}/rule/{rule}'
            ],
            'mkey': 'id'
        },
        'firewall_internetservicecustomgroup': {
            'params': [
                'adom',
                'internet-service-custom-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom-group/{internet-service-custom-group}',
                '/pm/config/global/obj/firewall/internet-service-custom-group/{internet-service-custom-group}'
            ],
            'mkey': 'name'
        },
        'firewall_internetservicecustom': {
            'params': [
                'adom',
                'internet-service-custom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}'
            ],
            'mkey': 'name'
        },
        'firewall_internetservicecustom_disableentry': {
            'params': [
                'adom',
                'internet-service-custom',
                'disable-entry'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}'
            ],
            'mkey': 'id'
        },
        'firewall_internetservicecustom_disableentry_iprange': {
            'params': [
                'adom',
                'internet-service-custom',
                'disable-entry',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}'
            ],
            'mkey': 'id'
        },
        'firewall_internetservicecustom_entry': {
            'params': [
                'adom',
                'internet-service-custom',
                'entry'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}'
            ],
            'mkey': 'id'
        },
        'firewall_internetservicecustom_entry_portrange': {
            'params': [
                'adom',
                'internet-service-custom',
                'entry',
                'port-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}'
            ],
            'mkey': 'id'
        },
        'firewall_internetservicegroup': {
            'params': [
                'adom',
                'internet-service-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-group/{internet-service-group}',
                '/pm/config/global/obj/firewall/internet-service-group/{internet-service-group}'
            ],
            'mkey': 'name'
        },
        'firewall_internetservice_entry': {
            'params': [
                'adom',
                'entry'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service/entry/{entry}'
            ],
            'mkey': 'id'
        },
        'firewall_ippool': {
            'params': [
                'adom',
                'ippool'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}',
                '/pm/config/global/obj/firewall/ippool/{ippool}'
            ],
            'mkey': 'name'
        },
        'firewall_ippool_dynamicmapping': {
            'params': [
                'adom',
                'ippool',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'firewall_ippool6': {
            'params': [
                'adom',
                'ippool6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool6/{ippool6}',
                '/pm/config/global/obj/firewall/ippool6/{ippool6}'
            ],
            'mkey': 'name'
        },
        'firewall_ippool6_dynamicmapping': {
            'params': [
                'adom',
                'ippool6',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool6/{ippool6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/ippool6/{ippool6}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'firewall_ldbmonitor': {
            'params': [
                'adom',
                'ldb-monitor'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ldb-monitor/{ldb-monitor}',
                '/pm/config/global/obj/firewall/ldb-monitor/{ldb-monitor}'
            ],
            'mkey': 'name'
        },
        'firewall_mmsprofile': {
            'params': [
                'adom',
                'mms-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}'
            ],
            'mkey': 'name'
        },
        'firewall_mmsprofile_notifmsisdn': {
            'params': [
                'adom',
                'mms-profile',
                'notif-msisdn'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/notif-msisdn/{notif-msisdn}',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/notif-msisdn/{notif-msisdn}'
            ],
            'mkey': 'msisdn'
        },
        'firewall_multicastaddress': {
            'params': [
                'adom',
                'multicast-address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}',
                '/pm/config/global/obj/firewall/multicast-address/{multicast-address}'
            ],
            'mkey': 'name'
        },
        'firewall_multicastaddress_tagging': {
            'params': [
                'adom',
                'multicast-address',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/multicast-address/{multicast-address}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_multicastaddress6': {
            'params': [
                'adom',
                'multicast-address6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}',
                '/pm/config/global/obj/firewall/multicast-address6/{multicast-address6}'
            ],
            'mkey': 'name'
        },
        'firewall_multicastaddress6_tagging': {
            'params': [
                'adom',
                'multicast-address6',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/multicast-address6/{multicast-address6}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_profilegroup': {
            'params': [
                'adom',
                'profile-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-group/{profile-group}',
                '/pm/config/global/obj/firewall/profile-group/{profile-group}'
            ],
            'mkey': 'name'
        },
        'firewall_profileprotocoloptions': {
            'params': [
                'adom',
                'profile-protocol-options'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}'
            ],
            'mkey': 'name'
        },
        'firewall_proxyaddress': {
            'params': [
                'adom',
                'proxy-address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}'
            ],
            'mkey': 'name'
        },
        'firewall_proxyaddress_headergroup': {
            'params': [
                'adom',
                'proxy-address',
                'header-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/header-group/{header-group}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/header-group/{header-group}'
            ],
            'mkey': 'id'
        },
        'firewall_proxyaddress_tagging': {
            'params': [
                'adom',
                'proxy-address',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_proxyaddrgrp': {
            'params': [
                'adom',
                'proxy-addrgrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp/{proxy-addrgrp}',
                '/pm/config/global/obj/firewall/proxy-addrgrp/{proxy-addrgrp}'
            ],
            'mkey': 'name'
        },
        'firewall_proxyaddrgrp_tagging': {
            'params': [
                'adom',
                'proxy-addrgrp',
                'tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_schedule_group': {
            'params': [
                'adom',
                'group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/group/{group}',
                '/pm/config/global/obj/firewall/schedule/group/{group}'
            ],
            'mkey': 'name'
        },
        'firewall_schedule_onetime': {
            'params': [
                'adom',
                'onetime'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/onetime/{onetime}',
                '/pm/config/global/obj/firewall/schedule/onetime/{onetime}'
            ],
            'mkey': 'name'
        },
        'firewall_schedule_recurring': {
            'params': [
                'adom',
                'recurring'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/recurring/{recurring}',
                '/pm/config/global/obj/firewall/schedule/recurring/{recurring}'
            ],
            'mkey': 'name'
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
            'mkey': 'name'
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
            'mkey': 'name'
        },
        'firewall_service_group': {
            'params': [
                'adom',
                'group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/group/{group}',
                '/pm/config/global/obj/firewall/service/group/{group}'
            ],
            'mkey': 'name'
        },
        'firewall_shaper_peripshaper': {
            'params': [
                'adom',
                'per-ip-shaper'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper/{per-ip-shaper}',
                '/pm/config/global/obj/firewall/shaper/per-ip-shaper/{per-ip-shaper}'
            ],
            'mkey': 'name'
        },
        'firewall_shaper_trafficshaper': {
            'params': [
                'adom',
                'traffic-shaper'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper/{traffic-shaper}',
                '/pm/config/global/obj/firewall/shaper/traffic-shaper/{traffic-shaper}'
            ],
            'mkey': 'name'
        },
        'firewall_shapingprofile': {
            'params': [
                'adom',
                'shaping-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}',
                '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}'
            ],
            'mkey': 'profile-name'
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
            'mkey': 'id'
        },
        'firewall_sslsshprofile': {
            'params': [
                'adom',
                'ssl-ssh-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}'
            ],
            'mkey': 'name'
        },
        'firewall_sslsshprofile_sslexempt': {
            'params': [
                'adom',
                'ssl-ssh-profile',
                'ssl-exempt'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt/{ssl-exempt}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt/{ssl-exempt}'
            ],
            'mkey': 'id'
        },
        'firewall_sslsshprofile_sslserver': {
            'params': [
                'adom',
                'ssl-ssh-profile',
                'ssl-server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}'
            ],
            'mkey': 'id'
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
            'mkey': 'name'
        },
        'firewall_vip_dynamicmapping': {
            'params': [
                'adom',
                'vip',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'firewall_vip_dynamicmapping_realservers': {
            'params': [
                'adom',
                'vip',
                'dynamic_mapping',
                'realservers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}'
            ],
            'mkey': 'seq'
        },
        'firewall_vip_dynamicmapping_sslciphersuites': {
            'params': [
                'adom',
                'vip',
                'dynamic_mapping',
                'ssl-cipher-suites'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': 'id'
        },
        'firewall_vip_realservers': {
            'params': [
                'adom',
                'vip',
                'realservers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip/{vip}/realservers/{realservers}'
            ],
            'mkey': 'seq'
        },
        'firewall_vip_sslciphersuites': {
            'params': [
                'adom',
                'vip',
                'ssl-cipher-suites'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': 'id'
        },
        'firewall_vip_sslserverciphersuites': {
            'params': [
                'adom',
                'vip',
                'ssl-server-cipher-suites'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-server-cipher-suites/{ssl-server-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-server-cipher-suites/{ssl-server-cipher-suites}'
            ],
            'mkey': 'priority'
        },
        'firewall_vip46': {
            'params': [
                'adom',
                'vip46'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}',
                '/pm/config/global/obj/firewall/vip46/{vip46}'
            ],
            'mkey': 'name'
        },
        'firewall_vip46_dynamicmapping': {
            'params': [
                'adom',
                'vip46',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip46/{vip46}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'firewall_vip46_realservers': {
            'params': [
                'adom',
                'vip46',
                'realservers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip46/{vip46}/realservers/{realservers}'
            ],
            'mkey': 'id'
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
            'mkey': 'name'
        },
        'firewall_vip6_dynamicmapping': {
            'params': [
                'adom',
                'vip6',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'firewall_vip6_realservers': {
            'params': [
                'adom',
                'vip6',
                'realservers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/realservers/{realservers}'
            ],
            'mkey': 'id'
        },
        'firewall_vip6_sslciphersuites': {
            'params': [
                'adom',
                'vip6',
                'ssl-cipher-suites'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': 'priority'
        },
        'firewall_vip6_sslserverciphersuites': {
            'params': [
                'adom',
                'vip6',
                'ssl-server-cipher-suites'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites/{ssl-server-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites/{ssl-server-cipher-suites}'
            ],
            'mkey': 'priority'
        },
        'firewall_vip64': {
            'params': [
                'adom',
                'vip64'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}',
                '/pm/config/global/obj/firewall/vip64/{vip64}'
            ],
            'mkey': 'name'
        },
        'firewall_vip64_dynamicmapping': {
            'params': [
                'adom',
                'vip64',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip64/{vip64}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'firewall_vip64_realservers': {
            'params': [
                'adom',
                'vip64',
                'realservers'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip64/{vip64}/realservers/{realservers}'
            ],
            'mkey': 'id'
        },
        'firewall_vipgrp': {
            'params': [
                'adom',
                'vipgrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp/{vipgrp}',
                '/pm/config/global/obj/firewall/vipgrp/{vipgrp}'
            ],
            'mkey': 'name'
        },
        'firewall_vipgrp_dynamicmapping': {
            'params': [
                'adom',
                'vipgrp',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'firewall_vipgrp46': {
            'params': [
                'adom',
                'vipgrp46'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp46/{vipgrp46}',
                '/pm/config/global/obj/firewall/vipgrp46/{vipgrp46}'
            ],
            'mkey': 'name'
        },
        'firewall_vipgrp6': {
            'params': [
                'adom',
                'vipgrp6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp6/{vipgrp6}',
                '/pm/config/global/obj/firewall/vipgrp6/{vipgrp6}'
            ],
            'mkey': 'name'
        },
        'firewall_vipgrp64': {
            'params': [
                'adom',
                'vipgrp64'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp64/{vipgrp64}',
                '/pm/config/global/obj/firewall/vipgrp64/{vipgrp64}'
            ],
            'mkey': 'name'
        },
        'firewall_wildcardfqdn_custom': {
            'params': [
                'adom',
                'custom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom/{custom}',
                '/pm/config/global/obj/firewall/wildcard-fqdn/custom/{custom}'
            ],
            'mkey': 'name'
        },
        'firewall_wildcardfqdn_group': {
            'params': [
                'adom',
                'group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/group/{group}',
                '/pm/config/global/obj/firewall/wildcard-fqdn/group/{group}'
            ],
            'mkey': 'name'
        },
        'pkg_footer_consolidated_policy': {
            'params': [
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/consolidated/policy/{policy}'
            ],
            'mkey': 'name'
        },
        'pkg_footer_policy': {
            'params': [
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}'
            ],
            'mkey': 'policyid'
        },
        'pkg_footer_policy_identitybasedpolicy': {
            'params': [
                'pkg',
                'policy',
                'identity-based-policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'mkey': 'id'
        },
        'pkg_footer_policy6': {
            'params': [
                'pkg',
                'policy6'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy6/{policy6}'
            ],
            'mkey': 'policyid'
        },
        'pkg_footer_policy6_identitybasedpolicy6': {
            'params': [
                'pkg',
                'policy6',
                'identity-based-policy6'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'mkey': 'id'
        },
        'pkg_footer_shapingpolicy': {
            'params': [
                'pkg',
                'shaping-policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/shaping-policy/{shaping-policy}'
            ],
            'mkey': 'id'
        },
        'pkg_header_consolidated_policy': {
            'params': [
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/consolidated/policy/{policy}'
            ],
            'mkey': 'name'
        },
        'pkg_header_policy': {
            'params': [
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}'
            ],
            'mkey': 'policyid'
        },
        'pkg_header_policy_identitybasedpolicy': {
            'params': [
                'pkg',
                'policy',
                'identity-based-policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'mkey': 'id'
        },
        'pkg_header_policy6': {
            'params': [
                'pkg',
                'policy6'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}'
            ],
            'mkey': 'policyid'
        },
        'pkg_header_policy6_identitybasedpolicy6': {
            'params': [
                'pkg',
                'policy6',
                'identity-based-policy6'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'mkey': 'id'
        },
        'pkg_header_shapingpolicy': {
            'params': [
                'pkg',
                'shaping-policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/shaping-policy/{shaping-policy}'
            ],
            'mkey': 'id'
        },
        'waf_mainclass': {
            'params': [
                'adom',
                'main-class'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/main-class/{main-class}',
                '/pm/config/global/obj/waf/main-class/{main-class}'
            ],
            'mkey': 'id'
        },
        'waf_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}',
                '/pm/config/global/obj/waf/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'waf_profile_constraint_exception': {
            'params': [
                'adom',
                'profile',
                'exception'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/exception/{exception}',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/exception/{exception}'
            ],
            'mkey': 'id'
        },
        'waf_profile_method_methodpolicy': {
            'params': [
                'adom',
                'profile',
                'method-policy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/method/method-policy/{method-policy}',
                '/pm/config/global/obj/waf/profile/{profile}/method/method-policy/{method-policy}'
            ],
            'mkey': 'id'
        },
        'waf_profile_signature_customsignature': {
            'params': [
                'adom',
                'profile',
                'custom-signature'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/signature/custom-signature/{custom-signature}',
                '/pm/config/global/obj/waf/profile/{profile}/signature/custom-signature/{custom-signature}'
            ],
            'mkey': 'name'
        },
        'waf_profile_urlaccess': {
            'params': [
                'adom',
                'profile',
                'url-access'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}',
                '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}'
            ],
            'mkey': 'id'
        },
        'waf_profile_urlaccess_accesspattern': {
            'params': [
                'adom',
                'profile',
                'url-access',
                'access-pattern'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern/{access-pattern}',
                '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern/{access-pattern}'
            ],
            'mkey': 'id'
        },
        'waf_signature': {
            'params': [
                'adom',
                'signature'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/signature/{signature}',
                '/pm/config/global/obj/waf/signature/{signature}'
            ],
            'mkey': 'id'
        },
        'waf_subclass': {
            'params': [
                'adom',
                'sub-class'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/sub-class/{sub-class}',
                '/pm/config/global/obj/waf/sub-class/{sub-class}'
            ],
            'mkey': 'id'
        },
        'certificate_template': {
            'params': [
                'adom',
                'template'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/certificate/template/{template}',
                '/pm/config/global/obj/certificate/template/{template}'
            ],
            'mkey': 'name'
        },
        'system_customlanguage': {
            'params': [
                'adom',
                'custom-language'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/custom-language/{custom-language}',
                '/pm/config/global/obj/system/custom-language/{custom-language}'
            ],
            'mkey': 'name'
        },
        'system_dhcp_server': {
            'params': [
                'adom',
                'server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}',
                '/pm/config/global/obj/system/dhcp/server/{server}'
            ],
            'mkey': 'id'
        },
        'system_dhcp_server_excluderange': {
            'params': [
                'adom',
                'server',
                'exclude-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/exclude-range/{exclude-range}',
                '/pm/config/global/obj/system/dhcp/server/{server}/exclude-range/{exclude-range}'
            ],
            'mkey': 'id'
        },
        'system_dhcp_server_iprange': {
            'params': [
                'adom',
                'server',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/ip-range/{ip-range}',
                '/pm/config/global/obj/system/dhcp/server/{server}/ip-range/{ip-range}'
            ],
            'mkey': 'id'
        },
        'system_dhcp_server_options': {
            'params': [
                'adom',
                'server',
                'options'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/options/{options}',
                '/pm/config/global/obj/system/dhcp/server/{server}/options/{options}'
            ],
            'mkey': 'id'
        },
        'system_dhcp_server_reservedaddress': {
            'params': [
                'adom',
                'server',
                'reserved-address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/reserved-address/{reserved-address}',
                '/pm/config/global/obj/system/dhcp/server/{server}/reserved-address/{reserved-address}'
            ],
            'mkey': 'id'
        },
        'system_externalresource': {
            'params': [
                'adom',
                'external-resource'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/external-resource/{external-resource}',
                '/pm/config/global/obj/system/external-resource/{external-resource}'
            ],
            'mkey': 'name'
        },
        'system_geoipcountry': {
            'params': [
                'adom',
                'geoip-country'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-country/{geoip-country}',
                '/pm/config/global/obj/system/geoip-country/{geoip-country}'
            ],
            'mkey': 'id'
        },
        'system_geoipoverride': {
            'params': [
                'adom',
                'geoip-override'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}'
            ],
            'mkey': 'name'
        },
        'system_geoipoverride_iprange': {
            'params': [
                'adom',
                'geoip-override',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}/ip-range/{ip-range}',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}/ip-range/{ip-range}'
            ],
            'mkey': 'id'
        },
        'system_meta': {
            'params': [
                'adom',
                'meta'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/meta/{meta}',
                '/pm/config/global/obj/system/meta/{meta}'
            ],
            'mkey': 'name'
        },
        'system_meta_sysmetafields': {
            'params': [
                'adom',
                'meta',
                'sys_meta_fields'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/meta/{meta}/sys_meta_fields/{sys_meta_fields}',
                '/pm/config/global/obj/system/meta/{meta}/sys_meta_fields/{sys_meta_fields}'
            ],
            'mkey': 'name'
        },
        'system_objecttagging': {
            'params': [
                'adom',
                'object-tagging'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/object-tagging/{object-tagging}',
                '/pm/config/global/obj/system/object-tagging/{object-tagging}'
            ],
            'mkey': 'category'
        },
        'system_replacemsggroup': {
            'params': [
                'adom',
                'replacemsg-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}'
            ],
            'mkey': 'name'
        },
        'system_replacemsggroup_admin': {
            'params': [
                'adom',
                'replacemsg-group',
                'admin'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/admin/{admin}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/admin/{admin}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_alertmail': {
            'params': [
                'adom',
                'replacemsg-group',
                'alertmail'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/alertmail/{alertmail}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/alertmail/{alertmail}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_auth': {
            'params': [
                'adom',
                'replacemsg-group',
                'auth'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/auth/{auth}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/auth/{auth}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_custommessage': {
            'params': [
                'adom',
                'replacemsg-group',
                'custom-message'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/custom-message/{custom-message}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/custom-message/{custom-message}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_devicedetectionportal': {
            'params': [
                'adom',
                'replacemsg-group',
                'device-detection-portal'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal/{device-detection-portal}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal/{device-detection-portal}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_ec': {
            'params': [
                'adom',
                'replacemsg-group',
                'ec'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ec/{ec}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ec/{ec}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_fortiguardwf': {
            'params': [
                'adom',
                'replacemsg-group',
                'fortiguard-wf'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf/{fortiguard-wf}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf/{fortiguard-wf}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_ftp': {
            'params': [
                'adom',
                'replacemsg-group',
                'ftp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ftp/{ftp}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ftp/{ftp}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_http': {
            'params': [
                'adom',
                'replacemsg-group',
                'http'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/http/{http}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/http/{http}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_icap': {
            'params': [
                'adom',
                'replacemsg-group',
                'icap'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/icap/{icap}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/icap/{icap}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mail': {
            'params': [
                'adom',
                'replacemsg-group',
                'mail'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mail/{mail}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mail/{mail}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mm1': {
            'params': [
                'adom',
                'replacemsg-group',
                'mm1'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm1/{mm1}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm1/{mm1}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mm3': {
            'params': [
                'adom',
                'replacemsg-group',
                'mm3'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm3/{mm3}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm3/{mm3}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mm4': {
            'params': [
                'adom',
                'replacemsg-group',
                'mm4'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm4/{mm4}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm4/{mm4}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mm7': {
            'params': [
                'adom',
                'replacemsg-group',
                'mm7'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mms': {
            'params': [
                'adom',
                'replacemsg-group',
                'mms'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mms/{mms}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mms/{mms}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_nacquar': {
            'params': [
                'adom',
                'replacemsg-group',
                'nac-quar'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nac-quar/{nac-quar}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nac-quar/{nac-quar}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_nntp': {
            'params': [
                'adom',
                'replacemsg-group',
                'nntp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nntp/{nntp}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nntp/{nntp}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_spam': {
            'params': [
                'adom',
                'replacemsg-group',
                'spam'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/spam/{spam}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/spam/{spam}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_sslvpn': {
            'params': [
                'adom',
                'replacemsg-group',
                'sslvpn'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/sslvpn/{sslvpn}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/sslvpn/{sslvpn}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_trafficquota': {
            'params': [
                'adom',
                'replacemsg-group',
                'traffic-quota'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota/{traffic-quota}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota/{traffic-quota}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_utm': {
            'params': [
                'adom',
                'replacemsg-group',
                'utm'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/utm/{utm}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/utm/{utm}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_webproxy': {
            'params': [
                'adom',
                'replacemsg-group',
                'webproxy'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/webproxy/{webproxy}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/webproxy/{webproxy}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsgimage': {
            'params': [
                'adom',
                'replacemsg-image'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-image/{replacemsg-image}',
                '/pm/config/global/obj/system/replacemsg-image/{replacemsg-image}'
            ],
            'mkey': 'name'
        },
        'system_sdnconnector': {
            'params': [
                'adom',
                'sdn-connector'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}'
            ],
            'mkey': 'name'
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
            'mkey': 'name'
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
            'mkey': 'name'
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
            'mkey': 'name'
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
            'mkey': 'name'
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
            'mkey': 'name'
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
            'mkey': 'name'
        },
        'system_smsserver': {
            'params': [
                'adom',
                'sms-server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sms-server/{sms-server}',
                '/pm/config/global/obj/system/sms-server/{sms-server}'
            ],
            'mkey': 'name'
        },
        'system_virtualwirepair': {
            'params': [
                'adom',
                'virtual-wire-pair'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/virtual-wire-pair/{virtual-wire-pair}',
                '/pm/config/global/obj/system/virtual-wire-pair/{virtual-wire-pair}'
            ],
            'mkey': 'name'
        },
        'templategroup': {
            'params': [
                'adom',
                'template-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/cli/template-group/{template-group}',
                '/pm/config/global/obj/cli/template-group/{template-group}'
            ],
            'mkey': 'name'
        },
        'template': {
            'params': [
                'adom',
                'template'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/cli/template/{template}',
                '/pm/config/global/obj/cli/template/{template}'
            ],
            'mkey': 'name'
        },
        'wanprof_system_virtualwanlink_healthcheck': {
            'params': [
                'adom',
                'wanprof',
                'health-check'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}'
            ],
            'mkey': 'name'
        },
        'wanprof_system_virtualwanlink_healthcheck_sla': {
            'params': [
                'adom',
                'wanprof',
                'health-check',
                'sla'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}/sla/{sla}'
            ],
            'mkey': 'id'
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
            'mkey': 'seq-num'
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
            'mkey': 'id'
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
            'mkey': 'id'
        },
        'sshfilter_profile': {
            'params': [
                'adom',
                'profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}'
            ],
            'mkey': 'name'
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
            'mkey': 'id'
        },
        'fsp_vlan': {
            'params': [
                'adom',
                'vlan'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}',
                '/pm/config/global/obj/fsp/vlan/{vlan}'
            ],
            'mkey': 'name'
        },
        'fsp_vlan_dhcpserver_excluderange': {
            'params': [
                'adom',
                'vlan',
                'exclude-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range/{exclude-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range/{exclude-range}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_dhcpserver_iprange': {
            'params': [
                'adom',
                'vlan',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/ip-range/{ip-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/ip-range/{ip-range}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_dhcpserver_options': {
            'params': [
                'adom',
                'vlan',
                'options'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/options/{options}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/options/{options}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_dhcpserver_reservedaddress': {
            'params': [
                'adom',
                'vlan',
                'reserved-address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address/{reserved-address}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address/{reserved-address}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_dynamicmapping': {
            'params': [
                'adom',
                'vlan',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': None
        },
        'fsp_vlan_dynamicmapping_dhcpserver_excluderange': {
            'params': [
                'adom',
                'vlan',
                'dynamic_mapping',
                'exclude-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range/{exclude-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range/{exclude-range}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_dynamicmapping_dhcpserver_iprange': {
            'params': [
                'adom',
                'vlan',
                'dynamic_mapping',
                'ip-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_dynamicmapping_dhcpserver_options': {
            'params': [
                'adom',
                'vlan',
                'dynamic_mapping',
                'options'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options/{options}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options/{options}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_dynamicmapping_dhcpserver_reservedaddress': {
            'params': [
                'adom',
                'vlan',
                'dynamic_mapping',
                'reserved-address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address/{reserved-address}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address/{reserved-address}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_interface_secondaryip': {
            'params': [
                'adom',
                'vlan',
                'secondaryip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/secondaryip/{secondaryip}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/secondaryip/{secondaryip}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_interface_vrrp': {
            'params': [
                'adom',
                'vlan',
                'vrrp'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}'
            ],
            'mkey': 'vrid'
        },
        'devprof_system_centralmanagement_serverlist': {
            'params': [
                'adom',
                'devprof',
                'server-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/central-management/server-list/{server-list}'
            ],
            'mkey': 'id'
        },
        'devprof_system_ntp_ntpserver': {
            'params': [
                'adom',
                'devprof',
                'ntpserver'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/ntp/ntpserver/{ntpserver}'
            ],
            'mkey': 'id'
        },
        'devprof_system_snmp_community': {
            'params': [
                'adom',
                'devprof',
                'community'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}'
            ],
            'mkey': 'id'
        },
        'devprof_system_snmp_community_hosts': {
            'params': [
                'adom',
                'devprof',
                'community',
                'hosts'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts/{hosts}'
            ],
            'mkey': 'id'
        },
        'devprof_system_snmp_community_hosts6': {
            'params': [
                'adom',
                'devprof',
                'community',
                'hosts6'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts6/{hosts6}'
            ],
            'mkey': 'id'
        },
        'devprof_system_snmp_user': {
            'params': [
                'adom',
                'devprof',
                'user'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user/{user}'
            ],
            'mkey': 'name'
        },
        'bleprofile': {
            'params': [
                'adom',
                'ble-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/ble-profile/{ble-profile}',
                '/pm/config/global/obj/wireless-controller/ble-profile/{ble-profile}'
            ],
            'mkey': 'name'
        },
        'bonjourprofile': {
            'params': [
                'adom',
                'bonjour-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile/{bonjour-profile}',
                '/pm/config/global/obj/wireless-controller/bonjour-profile/{bonjour-profile}'
            ],
            'mkey': 'name'
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
            'mkey': 'policy-id'
        },
        'hotspot20_anqp3gppcellular': {
            'params': [
                'adom',
                'anqp-3gpp-cellular'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqp3gppcellular_mccmnclist': {
            'params': [
                'adom',
                'anqp-3gpp-cellular',
                'mcc-mnc-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}'
            ],
            'mkey': 'id'
        },
        'hotspot20_anqpipaddresstype': {
            'params': [
                'adom',
                'anqp-ip-address-type'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqpnairealm': {
            'params': [
                'adom',
                'anqp-nai-realm'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqpnairealm_nailist': {
            'params': [
                'adom',
                'anqp-nai-realm',
                'nai-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqpnairealm_nailist_eapmethod': {
            'params': [
                'adom',
                'anqp-nai-realm',
                'nai-list',
                'eap-method'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}'
            ],
            'mkey': 'index'
        },
        'hotspot20_anqpnairealm_nailist_eapmethod_authparam': {
            'params': [
                'adom',
                'anqp-nai-realm',
                'nai-list',
                'eap-method',
                'auth-param'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-param/{auth-param}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-param/{auth-param}'
            ],
            'mkey': 'id'
        },
        'hotspot20_anqpnetworkauthtype': {
            'params': [
                'adom',
                'anqp-network-auth-type'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqproamingconsortium': {
            'params': [
                'adom',
                'anqp-roaming-consortium'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqproamingconsortium_oilist': {
            'params': [
                'adom',
                'anqp-roaming-consortium',
                'oi-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}'
            ],
            'mkey': 'index'
        },
        'hotspot20_anqpvenuename': {
            'params': [
                'adom',
                'anqp-venue-name'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqpvenuename_valuelist': {
            'params': [
                'adom',
                'anqp-venue-name',
                'value-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}'
            ],
            'mkey': 'index'
        },
        'hotspot20_h2qpconncapability': {
            'params': [
                'adom',
                'h2qp-conn-capability'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}'
            ],
            'mkey': 'name'
        },
        'hotspot20_h2qpoperatorname': {
            'params': [
                'adom',
                'h2qp-operator-name'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}'
            ],
            'mkey': 'name'
        },
        'hotspot20_h2qpoperatorname_valuelist': {
            'params': [
                'adom',
                'h2qp-operator-name',
                'value-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}'
            ],
            'mkey': 'index'
        },
        'hotspot20_h2qposuprovider': {
            'params': [
                'adom',
                'h2qp-osu-provider'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}'
            ],
            'mkey': 'name'
        },
        'hotspot20_h2qposuprovider_friendlyname': {
            'params': [
                'adom',
                'h2qp-osu-provider',
                'friendly-name'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}'
            ],
            'mkey': 'index'
        },
        'hotspot20_h2qposuprovider_servicedescription': {
            'params': [
                'adom',
                'h2qp-osu-provider',
                'service-description'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-description}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-description}'
            ],
            'mkey': 'service-id'
        },
        'hotspot20_h2qpwanmetric': {
            'params': [
                'adom',
                'h2qp-wan-metric'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}'
            ],
            'mkey': 'name'
        },
        'hotspot20_hsprofile': {
            'params': [
                'adom',
                'hs-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}',
                '/pm/config/global/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}'
            ],
            'mkey': 'name'
        },
        'hotspot20_qosmap': {
            'params': [
                'adom',
                'qos-map'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}'
            ],
            'mkey': 'name'
        },
        'hotspot20_qosmap_dscpexcept': {
            'params': [
                'adom',
                'qos-map',
                'dscp-except'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}'
            ],
            'mkey': 'index'
        },
        'hotspot20_qosmap_dscprange': {
            'params': [
                'adom',
                'qos-map',
                'dscp-range'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}'
            ],
            'mkey': 'index'
        },
        'qosprofile': {
            'params': [
                'adom',
                'qos-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/qos-profile/{qos-profile}',
                '/pm/config/global/obj/wireless-controller/qos-profile/{qos-profile}'
            ],
            'mkey': 'name'
        },
        'vapgroup': {
            'params': [
                'adom',
                'vap-group'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap-group/{vap-group}',
                '/pm/config/global/obj/wireless-controller/vap-group/{vap-group}'
            ],
            'mkey': 'name'
        },
        'vap': {
            'params': [
                'adom',
                'vap'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}'
            ],
            'mkey': 'name'
        },
        'vap_dynamicmapping': {
            'params': [
                'adom',
                'vap',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'vap_macfilterlist': {
            'params': [
                'adom',
                'vap',
                'mac-filter-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}'
            ],
            'mkey': 'id'
        },
        'vap_mpskkey': {
            'params': [
                'adom',
                'vap',
                'mpsk-key'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}'
            ],
            'mkey': 'key-name'
        },
        'vap_vlanpool': {
            'params': [
                'adom',
                'vap',
                'vlan-pool'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}'
            ],
            'mkey': 'id'
        },
        'widsprofile': {
            'params': [
                'adom',
                'wids-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wids-profile/{wids-profile}',
                '/pm/config/global/obj/wireless-controller/wids-profile/{wids-profile}'
            ],
            'mkey': 'name'
        },
        'wtpprofile': {
            'params': [
                'adom',
                'wtp-profile'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}'
            ],
            'mkey': 'name'
        },
        'wtpprofile_denymaclist': {
            'params': [
                'adom',
                'wtp-profile',
                'deny-mac-list'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}'
            ],
            'mkey': 'id'
        },
        'wtpprofile_splittunnelingacl': {
            'params': [
                'adom',
                'wtp-profile',
                'split-tunneling-acl'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}'
            ],
            'mkey': 'id'
        },
        'dynamic_address': {
            'params': [
                'adom',
                'address'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/address/{address}',
                '/pm/config/global/obj/dynamic/address/{address}'
            ],
            'mkey': 'name'
        },
        'dynamic_address_dynamicaddrmapping': {
            'params': [
                'adom',
                'address',
                'dynamic_addr_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/address/{address}/dynamic_addr_mapping/{dynamic_addr_mapping}',
                '/pm/config/global/obj/dynamic/address/{address}/dynamic_addr_mapping/{dynamic_addr_mapping}'
            ],
            'mkey': 'id'
        },
        'dynamic_certificate_local': {
            'params': [
                'adom',
                'local'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local/{local}',
                '/pm/config/global/obj/dynamic/certificate/local/{local}'
            ],
            'mkey': 'name'
        },
        'dynamic_certificate_local_dynamicmapping': {
            'params': [
                'adom',
                'local',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local/{local}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/certificate/local/{local}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'dynamic_interface': {
            'params': [
                'adom',
                'interface'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}',
                '/pm/config/global/obj/dynamic/interface/{interface}'
            ],
            'mkey': 'name'
        },
        'dynamic_interface_dynamicmapping': {
            'params': [
                'adom',
                'interface',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'dynamic_ippool': {
            'params': [
                'adom',
                'ippool'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/ippool/{ippool}',
                '/pm/config/global/obj/dynamic/ippool/{ippool}'
            ],
            'mkey': 'name'
        },
        'dynamic_multicast_interface': {
            'params': [
                'adom',
                'interface'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}',
                '/pm/config/global/obj/dynamic/multicast/interface/{interface}'
            ],
            'mkey': 'name'
        },
        'dynamic_multicast_interface_dynamicmapping': {
            'params': [
                'adom',
                'interface',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/multicast/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'dynamic_vip': {
            'params': [
                'adom',
                'vip'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vip/{vip}',
                '/pm/config/global/obj/dynamic/vip/{vip}'
            ],
            'mkey': 'name'
        },
        'dynamic_virtualwanlink_members': {
            'params': [
                'adom',
                'members'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}'
            ],
            'mkey': 'name'
        },
        'dynamic_virtualwanlink_members_dynamicmapping': {
            'params': [
                'adom',
                'members',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'dynamic_virtualwanlink_server': {
            'params': [
                'adom',
                'server'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server/{server}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server/{server}'
            ],
            'mkey': 'name'
        },
        'dynamic_virtualwanlink_server_dynamicmapping': {
            'params': [
                'adom',
                'server',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'dynamic_vpntunnel': {
            'params': [
                'adom',
                'vpntunnel'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}',
                '/pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}'
            ],
            'mkey': 'name'
        },
        'dynamic_vpntunnel_dynamicmapping': {
            'params': [
                'adom',
                'vpntunnel',
                'dynamic_mapping'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope'
        },
        'dlp_filepattern': {
            'params': [
                'adom',
                'filepattern'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}',
                '/pm/config/global/obj/dlp/filepattern/{filepattern}'
            ],
            'mkey': 'id'
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
            'mkey': None
        },
        'dlp_fpsensitivity': {
            'params': [
                'adom',
                'fp-sensitivity'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/fp-sensitivity/{fp-sensitivity}',
                '/pm/config/global/obj/dlp/fp-sensitivity/{fp-sensitivity}'
            ],
            'mkey': 'name'
        },
        'dlp_sensor': {
            'params': [
                'adom',
                'sensor'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}',
                '/pm/config/global/obj/dlp/sensor/{sensor}'
            ],
            'mkey': 'name'
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
            'mkey': 'id'
        }
    }

    module_arg_spec = {
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
        'clone': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': [
                        'dnsfilter_domainfilter',
                        'dnsfilter_domainfilter_entries',
                        'dnsfilter_profile',
                        'dnsfilter_profile_ftgddns_filters',
                        'webproxy_forwardservergroup',
                        'webproxy_forwardservergroup_serverlist',
                        'webproxy_forwardserver',
                        'webproxy_profile',
                        'webproxy_profile_headers',
                        'webproxy_wisp',
                        'log_customfield',
                        'voip_profile',
                        'icap_profile',
                        'icap_server',
                        'gtp_apn',
                        'gtp_apngrp',
                        'gtp_iewhitelist',
                        'gtp_iewhitelist_entries',
                        'gtp_messagefilterv0v1',
                        'gtp_messagefilterv2',
                        'gtp_tunnellimit',
                        'application_categories',
                        'application_custom',
                        'application_group',
                        'application_list',
                        'application_list_entries',
                        'application_list_entries_parameters',
                        'vpn_certificate_ca',
                        'vpn_certificate_ocspserver',
                        'vpn_certificate_remote',
                        'vpnsslweb_hostchecksoftware',
                        'vpnsslweb_hostchecksoftware_checkitemlist',
                        'vpnsslweb_portal',
                        'vpnsslweb_portal_bookmarkgroup',
                        'vpnsslweb_portal_bookmarkgroup_bookmarks',
                        'vpnsslweb_portal_bookmarkgroup_bookmarks_formdata',
                        'vpnsslweb_portal_macaddrcheckrule',
                        'vpnsslweb_portal_splitdns',
                        'vpnsslweb_realm',
                        'pkg_firewall_centralsnatmap',
                        'pkg_firewall_dospolicy',
                        'pkg_firewall_dospolicy_anomaly',
                        'pkg_firewall_dospolicy6',
                        'pkg_firewall_dospolicy6_anomaly',
                        'pkg_firewall_interfacepolicy',
                        'pkg_firewall_interfacepolicy6',
                        'pkg_firewall_localinpolicy',
                        'pkg_firewall_localinpolicy6',
                        'pkg_firewall_multicastpolicy',
                        'pkg_firewall_multicastpolicy6',
                        'pkg_firewall_policy',
                        'pkg_firewall_policy_vpndstnode',
                        'pkg_firewall_policy_vpnsrcnode',
                        'pkg_firewall_policy46',
                        'pkg_firewall_policy6',
                        'pkg_firewall_policy64',
                        'pkg_firewall_proxypolicy',
                        'pkg_firewall_shapingpolicy',
                        'dvmdb_revision',
                        'pkg_central_dnat',
                        'user_adgrp',
                        'user_devicecategory',
                        'user_devicegroup',
                        'user_devicegroup_dynamicmapping',
                        'user_devicegroup_tagging',
                        'user_device',
                        'user_device_dynamicmapping',
                        'user_device_tagging',
                        'user_fortitoken',
                        'user_fssopolling',
                        'user_fssopolling_adgrp',
                        'user_fsso',
                        'user_fsso_dynamicmapping',
                        'user_group',
                        'user_group_guest',
                        'user_group_match',
                        'user_ldap',
                        'user_ldap_dynamicmapping',
                        'user_local',
                        'user_passwordpolicy',
                        'user_peer',
                        'user_peergrp',
                        'user_pop3',
                        'user_pxgrid',
                        'user_radius',
                        'user_radius_accountingserver',
                        'user_radius_dynamicmapping',
                        'user_securityexemptlist',
                        'user_securityexemptlist_rule',
                        'user_tacacs',
                        'user_tacacs_dynamicmapping',
                        'webfilter_categories',
                        'webfilter_contentheader',
                        'webfilter_contentheader_entries',
                        'webfilter_content',
                        'webfilter_content_entries',
                        'webfilter_ftgdlocalcat',
                        'webfilter_ftgdlocalrating',
                        'webfilter_profile',
                        'webfilter_profile_ftgdwf_filters',
                        'webfilter_profile_ftgdwf_quota',
                        'webfilter_profile_youtubechannelfilter',
                        'webfilter_urlfilter',
                        'webfilter_urlfilter_entries',
                        'wanopt_authgroup',
                        'wanopt_peer',
                        'wanopt_profile',
                        'ips_custom',
                        'ips_sensor',
                        'ips_sensor_entries',
                        'ips_sensor_entries_exemptip',
                        'ips_sensor_filter',
                        'ips_sensor_override',
                        'ips_sensor_override_exemptip',
                        'vpnmgr_node',
                        'vpnmgr_node_iprange',
                        'vpnmgr_node_ipv4excluderange',
                        'vpnmgr_node_protectedsubnet',
                        'vpnmgr_node_summaryaddr',
                        'vpnmgr_vpntable',
                        'spamfilter_bwl',
                        'spamfilter_bwl_entries',
                        'spamfilter_bword',
                        'spamfilter_bword_entries',
                        'spamfilter_dnsbl',
                        'spamfilter_dnsbl_entries',
                        'spamfilter_iptrust',
                        'spamfilter_iptrust_entries',
                        'spamfilter_mheader',
                        'spamfilter_mheader_entries',
                        'spamfilter_profile',
                        'antivirus_mmschecksum',
                        'antivirus_mmschecksum_entries',
                        'antivirus_notification',
                        'antivirus_notification_entries',
                        'antivirus_profile',
                        'switchcontroller_lldpprofile',
                        'switchcontroller_lldpprofile_customtlvs',
                        'switchcontroller_lldpprofile_mednetworkpolicy',
                        'switchcontroller_managedswitch',
                        'switchcontroller_managedswitch_ports',
                        'switchcontroller_qos_dot1pmap',
                        'switchcontroller_qos_ipdscpmap',
                        'switchcontroller_qos_ipdscpmap_map',
                        'switchcontroller_qos_qospolicy',
                        'switchcontroller_qos_queuepolicy',
                        'switchcontroller_qos_queuepolicy_cosqueue',
                        'switchcontroller_securitypolicy_8021x',
                        'switchcontroller_securitypolicy_captiveportal',
                        'switchcontroller_managedswitch_customcommand',
                        'switchcontroller_managedswitch_mirror',
                        'firewall_address',
                        'firewall_address_dynamicmapping',
                        'firewall_address_list',
                        'firewall_address_tagging',
                        'firewall_address6template',
                        'firewall_address6template_subnetsegment',
                        'firewall_address6template_subnetsegment_values',
                        'firewall_address6',
                        'firewall_address6_dynamicmapping',
                        'firewall_address6_list',
                        'firewall_address6_subnetsegment',
                        'firewall_address6_tagging',
                        'firewall_addrgrp',
                        'firewall_addrgrp_dynamicmapping',
                        'firewall_addrgrp_tagging',
                        'firewall_addrgrp6',
                        'firewall_addrgrp6_dynamicmapping',
                        'firewall_addrgrp6_tagging',
                        'firewall_carrierendpointbwl',
                        'firewall_carrierendpointbwl_entries',
                        'firewall_gtp',
                        'firewall_gtp_apn',
                        'firewall_gtp_ieremovepolicy',
                        'firewall_gtp_imsi',
                        'firewall_gtp_ippolicy',
                        'firewall_gtp_noippolicy',
                        'firewall_gtp_perapnshaper',
                        'firewall_gtp_policy',
                        'firewall_identitybasedroute',
                        'firewall_identitybasedroute_rule',
                        'firewall_internetservicecustomgroup',
                        'firewall_internetservicecustom',
                        'firewall_internetservicecustom_disableentry',
                        'firewall_internetservicecustom_disableentry_iprange',
                        'firewall_internetservicecustom_entry',
                        'firewall_internetservicecustom_entry_portrange',
                        'firewall_internetservicegroup',
                        'firewall_internetservice_entry',
                        'firewall_ippool',
                        'firewall_ippool_dynamicmapping',
                        'firewall_ippool6',
                        'firewall_ippool6_dynamicmapping',
                        'firewall_ldbmonitor',
                        'firewall_mmsprofile',
                        'firewall_mmsprofile_notifmsisdn',
                        'firewall_multicastaddress',
                        'firewall_multicastaddress_tagging',
                        'firewall_multicastaddress6',
                        'firewall_multicastaddress6_tagging',
                        'firewall_profilegroup',
                        'firewall_profileprotocoloptions',
                        'firewall_proxyaddress',
                        'firewall_proxyaddress_headergroup',
                        'firewall_proxyaddress_tagging',
                        'firewall_proxyaddrgrp',
                        'firewall_proxyaddrgrp_tagging',
                        'firewall_schedule_group',
                        'firewall_schedule_onetime',
                        'firewall_schedule_recurring',
                        'firewall_service_category',
                        'firewall_service_custom',
                        'firewall_service_group',
                        'firewall_shaper_peripshaper',
                        'firewall_shaper_trafficshaper',
                        'firewall_shapingprofile',
                        'firewall_shapingprofile_shapingentries',
                        'firewall_sslsshprofile',
                        'firewall_sslsshprofile_sslexempt',
                        'firewall_sslsshprofile_sslserver',
                        'firewall_vip',
                        'firewall_vip_dynamicmapping',
                        'firewall_vip_dynamicmapping_realservers',
                        'firewall_vip_dynamicmapping_sslciphersuites',
                        'firewall_vip_realservers',
                        'firewall_vip_sslciphersuites',
                        'firewall_vip_sslserverciphersuites',
                        'firewall_vip46',
                        'firewall_vip46_dynamicmapping',
                        'firewall_vip46_realservers',
                        'firewall_vip6',
                        'firewall_vip6_dynamicmapping',
                        'firewall_vip6_realservers',
                        'firewall_vip6_sslciphersuites',
                        'firewall_vip6_sslserverciphersuites',
                        'firewall_vip64',
                        'firewall_vip64_dynamicmapping',
                        'firewall_vip64_realservers',
                        'firewall_vipgrp',
                        'firewall_vipgrp_dynamicmapping',
                        'firewall_vipgrp46',
                        'firewall_vipgrp6',
                        'firewall_vipgrp64',
                        'firewall_wildcardfqdn_custom',
                        'firewall_wildcardfqdn_group',
                        'pkg_footer_consolidated_policy',
                        'pkg_footer_policy',
                        'pkg_footer_policy_identitybasedpolicy',
                        'pkg_footer_policy6',
                        'pkg_footer_policy6_identitybasedpolicy6',
                        'pkg_footer_shapingpolicy',
                        'pkg_header_consolidated_policy',
                        'pkg_header_policy',
                        'pkg_header_policy_identitybasedpolicy',
                        'pkg_header_policy6',
                        'pkg_header_policy6_identitybasedpolicy6',
                        'pkg_header_shapingpolicy',
                        'waf_mainclass',
                        'waf_profile',
                        'waf_profile_constraint_exception',
                        'waf_profile_method_methodpolicy',
                        'waf_profile_signature_customsignature',
                        'waf_profile_urlaccess',
                        'waf_profile_urlaccess_accesspattern',
                        'waf_signature',
                        'waf_subclass',
                        'certificate_template',
                        'system_customlanguage',
                        'system_dhcp_server',
                        'system_dhcp_server_excluderange',
                        'system_dhcp_server_iprange',
                        'system_dhcp_server_options',
                        'system_dhcp_server_reservedaddress',
                        'system_externalresource',
                        'system_geoipcountry',
                        'system_geoipoverride',
                        'system_geoipoverride_iprange',
                        'system_meta',
                        'system_meta_sysmetafields',
                        'system_objecttagging',
                        'system_replacemsggroup',
                        'system_replacemsggroup_admin',
                        'system_replacemsggroup_alertmail',
                        'system_replacemsggroup_auth',
                        'system_replacemsggroup_custommessage',
                        'system_replacemsggroup_devicedetectionportal',
                        'system_replacemsggroup_ec',
                        'system_replacemsggroup_fortiguardwf',
                        'system_replacemsggroup_ftp',
                        'system_replacemsggroup_http',
                        'system_replacemsggroup_icap',
                        'system_replacemsggroup_mail',
                        'system_replacemsggroup_mm1',
                        'system_replacemsggroup_mm3',
                        'system_replacemsggroup_mm4',
                        'system_replacemsggroup_mm7',
                        'system_replacemsggroup_mms',
                        'system_replacemsggroup_nacquar',
                        'system_replacemsggroup_nntp',
                        'system_replacemsggroup_spam',
                        'system_replacemsggroup_sslvpn',
                        'system_replacemsggroup_trafficquota',
                        'system_replacemsggroup_utm',
                        'system_replacemsggroup_webproxy',
                        'system_replacemsgimage',
                        'system_sdnconnector',
                        'system_sdnconnector_externalip',
                        'system_sdnconnector_nic',
                        'system_sdnconnector_nic_ip',
                        'system_sdnconnector_routetable',
                        'system_sdnconnector_routetable_route',
                        'system_sdnconnector_route',
                        'system_smsserver',
                        'system_virtualwirepair',
                        'templategroup',
                        'template',
                        'wanprof_system_virtualwanlink_healthcheck',
                        'wanprof_system_virtualwanlink_healthcheck_sla',
                        'wanprof_system_virtualwanlink_members',
                        'wanprof_system_virtualwanlink_service',
                        'wanprof_system_virtualwanlink_service_sla',
                        'sshfilter_profile',
                        'sshfilter_profile_shellcommands',
                        'fsp_vlan',
                        'fsp_vlan_dhcpserver_excluderange',
                        'fsp_vlan_dhcpserver_iprange',
                        'fsp_vlan_dhcpserver_options',
                        'fsp_vlan_dhcpserver_reservedaddress',
                        'fsp_vlan_dynamicmapping',
                        'fsp_vlan_dynamicmapping_dhcpserver_excluderange',
                        'fsp_vlan_dynamicmapping_dhcpserver_iprange',
                        'fsp_vlan_dynamicmapping_dhcpserver_options',
                        'fsp_vlan_dynamicmapping_dhcpserver_reservedaddress',
                        'fsp_vlan_interface_secondaryip',
                        'fsp_vlan_interface_vrrp',
                        'devprof_system_centralmanagement_serverlist',
                        'devprof_system_ntp_ntpserver',
                        'devprof_system_snmp_community',
                        'devprof_system_snmp_community_hosts',
                        'devprof_system_snmp_community_hosts6',
                        'devprof_system_snmp_user',
                        'bleprofile',
                        'bonjourprofile',
                        'bonjourprofile_policylist',
                        'hotspot20_anqp3gppcellular',
                        'hotspot20_anqp3gppcellular_mccmnclist',
                        'hotspot20_anqpipaddresstype',
                        'hotspot20_anqpnairealm',
                        'hotspot20_anqpnairealm_nailist',
                        'hotspot20_anqpnairealm_nailist_eapmethod',
                        'hotspot20_anqpnairealm_nailist_eapmethod_authparam',
                        'hotspot20_anqpnetworkauthtype',
                        'hotspot20_anqproamingconsortium',
                        'hotspot20_anqproamingconsortium_oilist',
                        'hotspot20_anqpvenuename',
                        'hotspot20_anqpvenuename_valuelist',
                        'hotspot20_h2qpconncapability',
                        'hotspot20_h2qpoperatorname',
                        'hotspot20_h2qpoperatorname_valuelist',
                        'hotspot20_h2qposuprovider',
                        'hotspot20_h2qposuprovider_friendlyname',
                        'hotspot20_h2qposuprovider_servicedescription',
                        'hotspot20_h2qpwanmetric',
                        'hotspot20_hsprofile',
                        'hotspot20_qosmap',
                        'hotspot20_qosmap_dscpexcept',
                        'hotspot20_qosmap_dscprange',
                        'qosprofile',
                        'vapgroup',
                        'vap',
                        'vap_dynamicmapping',
                        'vap_macfilterlist',
                        'vap_mpskkey',
                        'vap_vlanpool',
                        'widsprofile',
                        'wtpprofile',
                        'wtpprofile_denymaclist',
                        'wtpprofile_splittunnelingacl',
                        'dynamic_address',
                        'dynamic_address_dynamicaddrmapping',
                        'dynamic_certificate_local',
                        'dynamic_certificate_local_dynamicmapping',
                        'dynamic_interface',
                        'dynamic_interface_dynamicmapping',
                        'dynamic_ippool',
                        'dynamic_multicast_interface',
                        'dynamic_multicast_interface_dynamicmapping',
                        'dynamic_vip',
                        'dynamic_virtualwanlink_members',
                        'dynamic_virtualwanlink_members_dynamicmapping',
                        'dynamic_virtualwanlink_server',
                        'dynamic_virtualwanlink_server_dynamicmapping',
                        'dynamic_vpntunnel',
                        'dynamic_vpntunnel_dynamicmapping',
                        'dlp_filepattern',
                        'dlp_filepattern_entries',
                        'dlp_fpsensitivity',
                        'dlp_sensor',
                        'dlp_sensor_filter'
                    ]
                },
                'self': {
                    'required': True,
                    'type': 'dict'
                },
                'target': {
                    'required': True,
                    'type': 'dict'
                }
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(None, None, None, None, module, connection)
        fmgr.process_clone(clone_metadata)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
