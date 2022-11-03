#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2021 Fortinet, Inc.
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
module: fmgr_export_playbooks
short_description: Export fortimanager configuration as playbooks.
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
    workspace_locking_adom:
        description: the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    export_playbooks:
        description: the top level parameters set
        type: dict
        required: false
'''

EXAMPLES = '''
- name: gathering fortimanager facts
  hosts: fortimanager00
  gather_facts: no
  connection: httpapi
  collections:
    - fortinet.fortimanager
  vars:
    ansible_httpapi_use_ssl: True
    ansible_httpapi_validate_certs: False
    ansible_httpapi_port: 443
  tasks:
   - name: Export Playbooks
     fmgr_export_playbooks:
        export_playbooks:
            selector:
                - all
            path: './exported'
            params:
                all:
                  adom: root
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
    export_metadata = {
        'fmupdate_fctservices': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fct-services'
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
        'footer_consolidated_policy': {
            'params': [
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/consolidated/policy/{policy}'
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
        'footer_policy': {
            'params': [
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/policy/{policy}'
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
        'footer_policy_identitybasedpolicy': {
            'params': [
                'policy',
                'identity-based-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'footer_policy6': {
            'params': [
                'policy6',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/policy6/{policy6}'
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
        'footer_policy6_identitybasedpolicy6': {
            'params': [
                'policy6',
                'identity-based-policy6',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'footer_shapingpolicy': {
            'params': [
                'shaping-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/shaping-policy/{shaping-policy}'
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
        'header_consolidated_policy': {
            'params': [
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/consolidated/policy/{policy}'
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
        'header_policy': {
            'params': [
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/policy/{policy}'
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
        'header_policy_identitybasedpolicy': {
            'params': [
                'policy',
                'identity-based-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'header_policy6': {
            'params': [
                'policy6',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/policy6/{policy6}'
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
        'header_policy6_identitybasedpolicy6': {
            'params': [
                'policy6',
                'identity-based-policy6',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'header_shapingpolicy': {
            'params': [
                'shaping-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/shaping-policy/{shaping-policy}'
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
        'pkg_footer_consolidated_policy': {
            'params': [
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/consolidated/policy/{policy}'
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
        'pkg_footer_policy': {
            'params': [
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}'
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
        'pkg_footer_policy_identitybasedpolicy': {
            'params': [
                'pkg',
                'policy',
                'identity-based-policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'pkg_footer_policy6': {
            'params': [
                'pkg',
                'policy6'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy6/{policy6}'
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
        'pkg_footer_policy6_identitybasedpolicy6': {
            'params': [
                'pkg',
                'policy6',
                'identity-based-policy6'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'pkg_footer_shapingpolicy': {
            'params': [
                'pkg',
                'shaping-policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/shaping-policy/{shaping-policy}'
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
        'pkg_header_consolidated_policy': {
            'params': [
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/consolidated/policy/{policy}'
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
        'pkg_header_policy': {
            'params': [
                'pkg',
                'policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}'
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
        'pkg_header_policy_identitybasedpolicy': {
            'params': [
                'pkg',
                'policy',
                'identity-based-policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'pkg_header_policy6': {
            'params': [
                'pkg',
                'policy6'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}'
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
        'pkg_header_policy6_identitybasedpolicy6': {
            'params': [
                'pkg',
                'policy6',
                'identity-based-policy6'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'pkg_header_shapingpolicy': {
            'params': [
                'pkg',
                'shaping-policy'
            ],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/shaping-policy/{shaping-policy}'
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
        'vpnmgr_node': {
            'params': [
                'node',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}',
                '/pm/config/global/obj/vpnmgr/node/{node}'
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
        'vpnmgr_node_iprange': {
            'params': [
                'node',
                'ip-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ip-range/{ip-range}',
                '/pm/config/global/obj/vpnmgr/node/{node}/ip-range/{ip-range}'
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
        'vpnmgr_node_ipv4excluderange': {
            'params': [
                'node',
                'ipv4-exclude-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ipv4-exclude-range/{ipv4-exclude-range}',
                '/pm/config/global/obj/vpnmgr/node/{node}/ipv4-exclude-range/{ipv4-exclude-range}'
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
        'vpnmgr_node_protectedsubnet': {
            'params': [
                'node',
                'protected_subnet',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/protected_subnet/{protected_subnet}',
                '/pm/config/global/obj/vpnmgr/node/{node}/protected_subnet/{protected_subnet}'
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
        'vpnmgr_node_summaryaddr': {
            'params': [
                'node',
                'summary_addr',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/summary_addr/{summary_addr}',
                '/pm/config/global/obj/vpnmgr/node/{node}/summary_addr/{summary_addr}'
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
        'vpnmgr_vpntable': {
            'params': [
                'vpntable',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/vpntable/{vpntable}',
                '/pm/config/global/obj/vpnmgr/vpntable/{vpntable}'
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
        'dvmdb_revision': {
            'params': [
                'revision',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/revision/{revision}',
                '/dvmdb/global/revision/{revision}',
                '/dvmdb/revision/{revision}'
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
        'system_ntp': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/ntp'
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
        'system_ntp_ntpserver': {
            'params': [
                'ntpserver'
            ],
            'urls': [
                '/cli/global/system/ntp/ntpserver/{ntpserver}'
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
        'user_adgrp': {
            'params': [
                'adgrp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/adgrp/{adgrp}',
                '/pm/config/global/obj/user/adgrp/{adgrp}'
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
        'user_device': {
            'params': [
                'device',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}',
                '/pm/config/global/obj/user/device/{device}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'user_devicecategory': {
            'params': [
                'device-category',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-category/{device-category}',
                '/pm/config/global/obj/user/device-category/{device-category}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'user_devicegroup': {
            'params': [
                'device-group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}',
                '/pm/config/global/obj/user/device-group/{device-group}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'user_devicegroup_dynamicmapping': {
            'params': [
                'device-group',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/device-group/{device-group}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'user_devicegroup_tagging': {
            'params': [
                'device-group',
                'tagging',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/tagging/{tagging}',
                '/pm/config/global/obj/user/device-group/{device-group}/tagging/{tagging}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'user_device_dynamicmapping': {
            'params': [
                'device',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'user_device_tagging': {
            'params': [
                'device',
                'tagging',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}/tagging/{tagging}',
                '/pm/config/global/obj/user/device/{device}/tagging/{tagging}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'user_fortitoken': {
            'params': [
                'fortitoken',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fortitoken/{fortitoken}',
                '/pm/config/global/obj/user/fortitoken/{fortitoken}'
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
        'user_fsso': {
            'params': [
                'fsso',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso/{fsso}',
                '/pm/config/global/obj/user/fsso/{fsso}'
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
        'user_fssopolling': {
            'params': [
                'fsso-polling',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso-polling/{fsso-polling}',
                '/pm/config/global/obj/user/fsso-polling/{fsso-polling}'
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
        'user_fssopolling_adgrp': {
            'params': [
                'fsso-polling',
                'adgrp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso-polling/{fsso-polling}/adgrp/{adgrp}',
                '/pm/config/global/obj/user/fsso-polling/{fsso-polling}/adgrp/{adgrp}'
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
        'user_fsso_dynamicmapping': {
            'params': [
                'fsso',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}'
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
        'user_group': {
            'params': [
                'group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}',
                '/pm/config/global/obj/user/group/{group}'
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
        'user_group_guest': {
            'params': [
                'group',
                'guest',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/guest/{guest}',
                '/pm/config/global/obj/user/group/{group}/guest/{guest}'
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
        'user_group_match': {
            'params': [
                'group',
                'match',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/match/{match}',
                '/pm/config/global/obj/user/group/{group}/match/{match}'
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
        'user_ldap': {
            'params': [
                'ldap',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/ldap/{ldap}',
                '/pm/config/global/obj/user/ldap/{ldap}'
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
        'user_ldap_dynamicmapping': {
            'params': [
                'ldap',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/ldap/{ldap}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/ldap/{ldap}/dynamic_mapping/{dynamic_mapping}'
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
        'user_local': {
            'params': [
                'local',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/local/{local}',
                '/pm/config/global/obj/user/local/{local}'
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
        'user_passwordpolicy': {
            'params': [
                'password-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/password-policy/{password-policy}',
                '/pm/config/global/obj/user/password-policy/{password-policy}'
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
        'user_peer': {
            'params': [
                'peer',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/peer/{peer}',
                '/pm/config/global/obj/user/peer/{peer}'
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
        'user_peergrp': {
            'params': [
                'peergrp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/peergrp/{peergrp}',
                '/pm/config/global/obj/user/peergrp/{peergrp}'
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
        'user_pop3': {
            'params': [
                'pop3',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/pop3/{pop3}',
                '/pm/config/global/obj/user/pop3/{pop3}'
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
        'user_pxgrid': {
            'params': [
                'pxgrid',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/pxgrid/{pxgrid}',
                '/pm/config/global/obj/user/pxgrid/{pxgrid}'
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
        'user_radius': {
            'params': [
                'radius',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}',
                '/pm/config/global/obj/user/radius/{radius}'
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
        'user_radius_accountingserver': {
            'params': [
                'radius',
                'accounting-server',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/accounting-server/{accounting-server}',
                '/pm/config/global/obj/user/radius/{radius}/accounting-server/{accounting-server}'
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
        'user_radius_dynamicmapping': {
            'params': [
                'radius',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}'
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
        'user_securityexemptlist': {
            'params': [
                'security-exempt-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/security-exempt-list/{security-exempt-list}',
                '/pm/config/global/obj/user/security-exempt-list/{security-exempt-list}'
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
        'user_securityexemptlist_rule': {
            'params': [
                'security-exempt-list',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/security-exempt-list/{security-exempt-list}/rule/{rule}',
                '/pm/config/global/obj/user/security-exempt-list/{security-exempt-list}/rule/{rule}'
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
        'user_tacacs': {
            'params': [
                'tacacs+',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/tacacs+/{tacacs+}',
                '/pm/config/global/obj/user/tacacs+/{tacacs+}'
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
        'user_tacacs_dynamicmapping': {
            'params': [
                'tacacs+',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/tacacs+/{tacacs+}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/tacacs+/{tacacs+}/dynamic_mapping/{dynamic_mapping}'
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
        'system_syslog': {
            'params': [
                'syslog'
            ],
            'urls': [
                '/cli/global/system/syslog/{syslog}'
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
        'fmupdate_avips_advancedlog': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/av-ips/advanced-log'
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
        'fmupdate_avips_webproxy': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/av-ips/web-proxy'
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
        'log_customfield': {
            'params': [
                'custom-field',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/log/custom-field/{custom-field}',
                '/pm/config/global/obj/log/custom-field/{custom-field}'
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
        'fmupdate_serveraccesspriorities': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/server-access-priorities'
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
        'fmupdate_serveraccesspriorities_privateserver': {
            'params': [
                'private-server'
            ],
            'urls': [
                '/cli/global/fmupdate/server-access-priorities/private-server/{private-server}'
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
        'system_saml': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/saml'
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
        'system_saml_serviceproviders': {
            'params': [
                'service-providers'
            ],
            'urls': [
                '/cli/global/system/saml/service-providers/{service-providers}'
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
        'devprof_log_fortianalyzer_setting': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/fortianalyzer/setting'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_log_syslogd_filter': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_log_syslogd_setting': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/setting'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_device_profile_fortianalyzer': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/device/profile/fortianalyzer'
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
        'devprof_device_profile_fortiguard': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/device/profile/fortiguard'
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
        'ips_custom': {
            'params': [
                'custom',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/custom/{custom}',
                '/pm/config/global/obj/ips/custom/{custom}'
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
        'ips_sensor': {
            'params': [
                'sensor',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}',
                '/pm/config/global/obj/ips/sensor/{sensor}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}'
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
        'ips_sensor_entries': {
            'params': [
                'sensor',
                'entries',
                'adom'
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
        'ips_sensor_entries_exemptip': {
            'params': [
                'sensor',
                'entries',
                'exempt-ip',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}'
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
                'sensor',
                'filter',
                'adom'
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
        'ips_sensor_override': {
            'params': [
                'sensor',
                'override',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override/{override}',
                '/pm/config/global/obj/ips/sensor/{sensor}/override/{override}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/override/{override}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/override/{override}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'ips_sensor_override_exemptip': {
            'params': [
                'sensor',
                'override',
                'exempt-ip',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'fmupdate_publicnetwork': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/publicnetwork'
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
        'template': {
            'params': [
                'template',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/cli/template/{template}',
                '/pm/config/global/obj/cli/template/{template}'
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
        'templategroup': {
            'params': [
                'template-group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/cli/template-group/{template-group}',
                '/pm/config/global/obj/cli/template-group/{template-group}'
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
        'system_global': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/global'
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
        'antivirus_mmschecksum': {
            'params': [
                'mms-checksum',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}',
                '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'antivirus_mmschecksum_entries': {
            'params': [
                'mms-checksum',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}/entries/{entries}',
                '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'antivirus_notification': {
            'params': [
                'notification',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/notification/{notification}',
                '/pm/config/global/obj/antivirus/notification/{notification}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'antivirus_notification_entries': {
            'params': [
                'notification',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/notification/{notification}/entries/{entries}',
                '/pm/config/global/obj/antivirus/notification/{notification}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'antivirus_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}',
                '/pm/config/global/obj/antivirus/profile/{profile}'
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
        'antivirus_profile_contentdisarm': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/content-disarm',
                '/pm/config/global/obj/antivirus/profile/{profile}/content-disarm'
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
        'antivirus_profile_ftp': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/ftp',
                '/pm/config/global/obj/antivirus/profile/{profile}/ftp'
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
        'antivirus_profile_http': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/http',
                '/pm/config/global/obj/antivirus/profile/{profile}/http'
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
        'antivirus_profile_imap': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/imap',
                '/pm/config/global/obj/antivirus/profile/{profile}/imap'
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
        'antivirus_profile_mapi': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/mapi',
                '/pm/config/global/obj/antivirus/profile/{profile}/mapi'
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
        'antivirus_profile_nacquar': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/nac-quar',
                '/pm/config/global/obj/antivirus/profile/{profile}/nac-quar'
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
        'antivirus_profile_nntp': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/nntp',
                '/pm/config/global/obj/antivirus/profile/{profile}/nntp'
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
        'antivirus_profile_pop3': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/pop3',
                '/pm/config/global/obj/antivirus/profile/{profile}/pop3'
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
        'antivirus_profile_smb': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/smb',
                '/pm/config/global/obj/antivirus/profile/{profile}/smb'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'antivirus_profile_smtp': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/smtp',
                '/pm/config/global/obj/antivirus/profile/{profile}/smtp'
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
        'application_categories': {
            'params': [
                'categories',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/categories/{categories}',
                '/pm/config/global/obj/application/categories/{categories}'
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
        'application_custom': {
            'params': [
                'custom',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/custom/{custom}',
                '/pm/config/global/obj/application/custom/{custom}'
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
        'application_group': {
            'params': [
                'group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/group/{group}',
                '/pm/config/global/obj/application/group/{group}'
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
        'application_list': {
            'params': [
                'list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}',
                '/pm/config/global/obj/application/list/{list}'
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
        'application_list_entries': {
            'params': [
                'list',
                'entries',
                'adom'
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
                'list',
                'entries',
                'parameters',
                'adom'
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
        'waf_mainclass': {
            'params': [
                'main-class',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/main-class/{main-class}',
                '/pm/config/global/obj/waf/main-class/{main-class}'
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
        'waf_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}',
                '/pm/config/global/obj/waf/profile/{profile}'
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
        'waf_profile_addresslist': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/address-list',
                '/pm/config/global/obj/waf/profile/{profile}/address-list'
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
        'waf_profile_constraint': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint',
                '/pm/config/global/obj/waf/profile/{profile}/constraint'
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
        'waf_profile_constraint_contentlength': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/content-length',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/content-length'
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
        'waf_profile_constraint_exception': {
            'params': [
                'profile',
                'exception',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/exception/{exception}',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/exception/{exception}'
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
        'waf_profile_constraint_headerlength': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/header-length',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/header-length'
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
        'waf_profile_constraint_hostname': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/hostname',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/hostname'
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
        'waf_profile_constraint_linelength': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/line-length',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/line-length'
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
        'waf_profile_constraint_malformed': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/malformed',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/malformed'
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
        'waf_profile_constraint_maxcookie': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/max-cookie',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/max-cookie'
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
        'waf_profile_constraint_maxheaderline': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/max-header-line',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/max-header-line'
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
        'waf_profile_constraint_maxrangesegment': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/max-range-segment',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/max-range-segment'
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
        'waf_profile_constraint_maxurlparam': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/max-url-param',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/max-url-param'
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
        'waf_profile_constraint_method': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/method',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/method'
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
        'waf_profile_constraint_paramlength': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/param-length',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/param-length'
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
        'waf_profile_constraint_urlparamlength': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/url-param-length',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/url-param-length'
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
        'waf_profile_constraint_version': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/version',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/version'
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
        'waf_profile_method': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/method',
                '/pm/config/global/obj/waf/profile/{profile}/method'
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
        'waf_profile_method_methodpolicy': {
            'params': [
                'profile',
                'method-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/method/method-policy/{method-policy}',
                '/pm/config/global/obj/waf/profile/{profile}/method/method-policy/{method-policy}'
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
        'waf_profile_signature': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/signature',
                '/pm/config/global/obj/waf/profile/{profile}/signature'
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
        'waf_profile_signature_customsignature': {
            'params': [
                'profile',
                'custom-signature',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/signature/custom-signature/{custom-signature}',
                '/pm/config/global/obj/waf/profile/{profile}/signature/custom-signature/{custom-signature}'
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
        'waf_profile_signature_mainclass': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/signature/main-class',
                '/pm/config/global/obj/waf/profile/{profile}/signature/main-class'
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
        'waf_profile_urlaccess': {
            'params': [
                'profile',
                'url-access',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}',
                '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}'
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
        'waf_profile_urlaccess_accesspattern': {
            'params': [
                'profile',
                'url-access',
                'access-pattern',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern/{access-pattern}',
                '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern/{access-pattern}'
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
        'waf_signature': {
            'params': [
                'signature',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/signature/{signature}',
                '/pm/config/global/obj/waf/signature/{signature}'
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
        'waf_subclass': {
            'params': [
                'sub-class',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/sub-class/{sub-class}',
                '/pm/config/global/obj/waf/sub-class/{sub-class}'
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
        'system_status': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/status'
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
        'spamfilter_bwl': {
            'params': [
                'bwl',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_bwl_entries': {
            'params': [
                'bwl',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_bword': {
            'params': [
                'bword',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}',
                '/pm/config/global/obj/spamfilter/bword/{bword}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_bword_entries': {
            'params': [
                'bword',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bword/{bword}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_dnsbl': {
            'params': [
                'dnsbl',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl/{dnsbl}',
                '/pm/config/global/obj/spamfilter/dnsbl/{dnsbl}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_dnsbl_entries': {
            'params': [
                'dnsbl',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl/{dnsbl}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/dnsbl/{dnsbl}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_iptrust': {
            'params': [
                'iptrust',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}',
                '/pm/config/global/obj/spamfilter/iptrust/{iptrust}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_iptrust_entries': {
            'params': [
                'iptrust',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/iptrust/{iptrust}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_mheader': {
            'params': [
                'mheader',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/mheader/{mheader}',
                '/pm/config/global/obj/spamfilter/mheader/{mheader}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_mheader_entries': {
            'params': [
                'mheader',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/mheader/{mheader}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/mheader/{mheader}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}',
                '/pm/config/global/obj/spamfilter/profile/{profile}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_profile_gmail': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/gmail',
                '/pm/config/global/obj/spamfilter/profile/{profile}/gmail'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_profile_imap': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/imap',
                '/pm/config/global/obj/spamfilter/profile/{profile}/imap'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_profile_mapi': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/mapi',
                '/pm/config/global/obj/spamfilter/profile/{profile}/mapi'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_profile_msnhotmail': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/msn-hotmail',
                '/pm/config/global/obj/spamfilter/profile/{profile}/msn-hotmail'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_profile_pop3': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/pop3',
                '/pm/config/global/obj/spamfilter/profile/{profile}/pop3'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_profile_smtp': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/smtp',
                '/pm/config/global/obj/spamfilter/profile/{profile}/smtp'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'spamfilter_profile_yahoomail': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/yahoo-mail',
                '/pm/config/global/obj/spamfilter/profile/{profile}/yahoo-mail'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'fmupdate_fdssetting': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting'
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
        'fmupdate_fdssetting_pushoverride': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override'
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
        'fmupdate_fdssetting_pushoverridetoclient': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override-to-client'
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
        'fmupdate_fdssetting_pushoverridetoclient_announceip': {
            'params': [
                'announce-ip'
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override-to-client/announce-ip/{announce-ip}'
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
        'fmupdate_fdssetting_serveroverride': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/server-override'
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
        'fmupdate_fdssetting_serveroverride_servlist': {
            'params': [
                'servlist'
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/server-override/servlist/{servlist}'
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
        'fmupdate_fdssetting_updateschedule': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fds-setting/update-schedule'
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
        'system_dns': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/dns'
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
        'dvmdb_device': {
            'params': [
                'device',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/device/{device}',
                '/dvmdb/device/{device}'
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
        'dvmdb_device_haslave': {
            'params': [
                'device',
                'ha_slave',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/device/{device}/ha_slave/{ha_slave}',
                '/dvmdb/device/{device}/ha_slave/{ha_slave}'
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
        'dvmdb_device_vdom': {
            'params': [
                'device',
                'vdom',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/device/{device}/vdom/{vdom}',
                '/dvmdb/device/{device}/vdom/{vdom}'
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
        'system_mail': {
            'params': [
                'mail'
            ],
            'urls': [
                '/cli/global/system/mail/{mail}'
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
        'system_alertemail': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/alertemail'
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
        'fmupdate_service': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/service'
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
        'system_logfetch_clientprofile': {
            'params': [
                'client-profile'
            ],
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}'
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
        'system_logfetch_clientprofile_devicefilter': {
            'params': [
                'client-profile',
                'device-filter'
            ],
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}/device-filter/{device-filter}'
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
        'system_logfetch_clientprofile_logfilter': {
            'params': [
                'client-profile',
                'log-filter'
            ],
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}/log-filter/{log-filter}'
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
        'system_logfetch_serversettings': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log-fetch/server-settings'
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
        'system_customlanguage': {
            'params': [
                'custom-language',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/custom-language/{custom-language}',
                '/pm/config/global/obj/system/custom-language/{custom-language}'
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
        'system_dhcp_server': {
            'params': [
                'server',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}',
                '/pm/config/global/obj/system/dhcp/server/{server}'
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
        'system_dhcp_server_excluderange': {
            'params': [
                'server',
                'exclude-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/exclude-range/{exclude-range}',
                '/pm/config/global/obj/system/dhcp/server/{server}/exclude-range/{exclude-range}'
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
        'system_dhcp_server_iprange': {
            'params': [
                'server',
                'ip-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/ip-range/{ip-range}',
                '/pm/config/global/obj/system/dhcp/server/{server}/ip-range/{ip-range}'
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
        'system_dhcp_server_options': {
            'params': [
                'server',
                'options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/options/{options}',
                '/pm/config/global/obj/system/dhcp/server/{server}/options/{options}'
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
        'system_dhcp_server_reservedaddress': {
            'params': [
                'server',
                'reserved-address',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/reserved-address/{reserved-address}',
                '/pm/config/global/obj/system/dhcp/server/{server}/reserved-address/{reserved-address}'
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
        'system_externalresource': {
            'params': [
                'external-resource',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/external-resource/{external-resource}',
                '/pm/config/global/obj/system/external-resource/{external-resource}'
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
        'system_fortiguard': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/fortiguard',
                '/pm/config/global/obj/system/fortiguard'
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
        'system_geoipcountry': {
            'params': [
                'geoip-country',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-country/{geoip-country}',
                '/pm/config/global/obj/system/geoip-country/{geoip-country}'
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
        'system_geoipoverride': {
            'params': [
                'geoip-override',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}'
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
        'system_geoipoverride_iprange': {
            'params': [
                'geoip-override',
                'ip-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}/ip-range/{ip-range}',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}/ip-range/{ip-range}'
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
        'system_meta': {
            'params': [
                'meta',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/meta/{meta}',
                '/pm/config/global/obj/system/meta/{meta}'
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
        'system_meta_sysmetafields': {
            'params': [
                'meta',
                'sys_meta_fields',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/meta/{meta}/sys_meta_fields/{sys_meta_fields}',
                '/pm/config/global/obj/system/meta/{meta}/sys_meta_fields/{sys_meta_fields}'
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
        'system_objecttagging': {
            'params': [
                'object-tagging',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/object-tagging/{object-tagging}',
                '/pm/config/global/obj/system/object-tagging/{object-tagging}'
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
        'system_replacemsggroup': {
            'params': [
                'replacemsg-group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}'
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
        'system_replacemsggroup_admin': {
            'params': [
                'replacemsg-group',
                'admin',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/admin/{admin}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/admin/{admin}'
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
        'system_replacemsggroup_alertmail': {
            'params': [
                'replacemsg-group',
                'alertmail',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/alertmail/{alertmail}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/alertmail/{alertmail}'
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
        'system_replacemsggroup_auth': {
            'params': [
                'replacemsg-group',
                'auth',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/auth/{auth}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/auth/{auth}'
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
        'system_replacemsggroup_custommessage': {
            'params': [
                'replacemsg-group',
                'custom-message',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/custom-message/{custom-message}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/custom-message/{custom-message}'
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
        'system_replacemsggroup_devicedetectionportal': {
            'params': [
                'replacemsg-group',
                'device-detection-portal',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal/{device-detection-portal}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal/{device-detection-portal}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'system_replacemsggroup_ec': {
            'params': [
                'replacemsg-group',
                'ec',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ec/{ec}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ec/{ec}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'system_replacemsggroup_fortiguardwf': {
            'params': [
                'replacemsg-group',
                'fortiguard-wf',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf/{fortiguard-wf}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf/{fortiguard-wf}'
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
        'system_replacemsggroup_ftp': {
            'params': [
                'replacemsg-group',
                'ftp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ftp/{ftp}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ftp/{ftp}'
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
        'system_replacemsggroup_http': {
            'params': [
                'replacemsg-group',
                'http',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/http/{http}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/http/{http}'
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
        'system_replacemsggroup_icap': {
            'params': [
                'replacemsg-group',
                'icap',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/icap/{icap}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/icap/{icap}'
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
        'system_replacemsggroup_mail': {
            'params': [
                'replacemsg-group',
                'mail',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mail/{mail}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mail/{mail}'
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
        'system_replacemsggroup_mm1': {
            'params': [
                'replacemsg-group',
                'mm1',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm1/{mm1}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm1/{mm1}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'system_replacemsggroup_mm3': {
            'params': [
                'replacemsg-group',
                'mm3',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm3/{mm3}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm3/{mm3}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'system_replacemsggroup_mm4': {
            'params': [
                'replacemsg-group',
                'mm4',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm4/{mm4}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm4/{mm4}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'system_replacemsggroup_mm7': {
            'params': [
                'replacemsg-group',
                'mm7',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'system_replacemsggroup_mms': {
            'params': [
                'replacemsg-group',
                'mms',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mms/{mms}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mms/{mms}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'system_replacemsggroup_nacquar': {
            'params': [
                'replacemsg-group',
                'nac-quar',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nac-quar/{nac-quar}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nac-quar/{nac-quar}'
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
        'system_replacemsggroup_nntp': {
            'params': [
                'replacemsg-group',
                'nntp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nntp/{nntp}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nntp/{nntp}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'system_replacemsggroup_spam': {
            'params': [
                'replacemsg-group',
                'spam',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/spam/{spam}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/spam/{spam}'
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
        'system_replacemsggroup_sslvpn': {
            'params': [
                'replacemsg-group',
                'sslvpn',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/sslvpn/{sslvpn}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/sslvpn/{sslvpn}'
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
        'system_replacemsggroup_trafficquota': {
            'params': [
                'replacemsg-group',
                'traffic-quota',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota/{traffic-quota}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota/{traffic-quota}'
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
        'system_replacemsggroup_utm': {
            'params': [
                'replacemsg-group',
                'utm',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/utm/{utm}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/utm/{utm}'
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
        'system_replacemsggroup_webproxy': {
            'params': [
                'replacemsg-group',
                'webproxy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/webproxy/{webproxy}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/webproxy/{webproxy}'
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
        'system_replacemsgimage': {
            'params': [
                'replacemsg-image',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-image/{replacemsg-image}',
                '/pm/config/global/obj/system/replacemsg-image/{replacemsg-image}'
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
        'system_sdnconnector': {
            'params': [
                'sdn-connector',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}'
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
        'system_sdnconnector_externalip': {
            'params': [
                'sdn-connector',
                'external-ip',
                'adom'
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
                'sdn-connector',
                'nic',
                'adom'
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
                'sdn-connector',
                'nic',
                'ip',
                'adom'
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
        'system_sdnconnector_route': {
            'params': [
                'sdn-connector',
                'route',
                'adom'
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
        'system_sdnconnector_routetable': {
            'params': [
                'sdn-connector',
                'route-table',
                'adom'
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
                'sdn-connector',
                'route-table',
                'route',
                'adom'
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
        'system_smsserver': {
            'params': [
                'sms-server',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sms-server/{sms-server}',
                '/pm/config/global/obj/system/sms-server/{sms-server}'
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
        'system_virtualwirepair': {
            'params': [
                'virtual-wire-pair',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/virtual-wire-pair/{virtual-wire-pair}',
                '/pm/config/global/obj/system/virtual-wire-pair/{virtual-wire-pair}'
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
        'sys_ha_status': {
            'params': [
            ],
            'urls': [
                '/sys/ha/status'
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
        'fmupdate_webspam_fgdsetting': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting'
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
        'fmupdate_webspam_fgdsetting_serveroverride': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting/server-override'
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
        'fmupdate_webspam_fgdsetting_serveroverride_servlist': {
            'params': [
                'servlist'
            ],
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting/server-override/servlist/{servlist}'
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
        'fmupdate_webspam_webproxy': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/web-spam/web-proxy'
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
        'dvmdb_workflow': {
            'params': [
                'workflow',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/workflow/{workflow}',
                '/dvmdb/global/workflow/{workflow}',
                '/dvmdb/workflow/{workflow}'
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
        'dvmdb_workflow_wflog': {
            'params': [
                'workflow',
                'wflog',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/workflow/{workflow}/wflog/{wflog}',
                '/dvmdb/global/workflow/{workflow}/wflog/{wflog}',
                '/dvmdb/workflow/{workflow}/wflog/{wflog}'
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
        'system_autodelete': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/auto-delete'
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
        'system_autodelete_dlpfilesautodeletion': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/auto-delete/dlp-files-auto-deletion'
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
        'system_autodelete_logautodeletion': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/auto-delete/log-auto-deletion'
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
        'system_autodelete_quarantinefilesautodeletion': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/auto-delete/quarantine-files-auto-deletion'
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
        'system_autodelete_reportautodeletion': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/auto-delete/report-auto-deletion'
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
        'sshfilter_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}'
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
                'profile',
                'shell-commands',
                'adom'
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
        'system_alertevent': {
            'params': [
                'alert-event'
            ],
            'urls': [
                '/cli/global/system/alert-event/{alert-event}'
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
        'system_alertevent_alertdestination': {
            'params': [
                'alert-event',
                'alert-destination'
            ],
            'urls': [
                '/cli/global/system/alert-event/{alert-event}/alert-destination/{alert-destination}'
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
        'system_interface': {
            'params': [
                'interface'
            ],
            'urls': [
                '/cli/global/system/interface/{interface}'
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
        'system_interface_ipv6': {
            'params': [
                'interface'
            ],
            'urls': [
                '/cli/global/system/interface/{interface}/ipv6'
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
        'system_locallog_disk_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/disk/filter'
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
        'system_locallog_disk_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/disk/setting'
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
        'system_locallog_fortianalyzer_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer/filter'
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
        'system_locallog_fortianalyzer_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer/setting'
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
        'system_locallog_fortianalyzer2_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer2/filter'
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
        'system_locallog_fortianalyzer2_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer2/setting'
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
        'system_locallog_fortianalyzer3_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer3/filter'
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
        'system_locallog_fortianalyzer3_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer3/setting'
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
        'system_locallog_memory_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/memory/filter'
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
        'system_locallog_memory_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/memory/setting'
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
        'system_locallog_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/setting'
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
        'system_locallog_syslogd_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd/filter'
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
        'system_locallog_syslogd_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd/setting'
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
        'system_locallog_syslogd2_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd2/filter'
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
        'system_locallog_syslogd2_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd2/setting'
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
        'system_locallog_syslogd3_filter': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd3/filter'
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
        'system_locallog_syslogd3_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/locallog/syslogd3/setting'
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
        'system_workflow_approvalmatrix': {
            'params': [
                'approval-matrix'
            ],
            'urls': [
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}'
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
        'system_workflow_approvalmatrix_approver': {
            'params': [
                'approval-matrix',
                'approver'
            ],
            'urls': [
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}/approver/{approver}'
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
        'system_report_autocache': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/report/auto-cache'
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
        'system_report_estbrowsetime': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/report/est-browse-time'
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
        'system_report_group': {
            'params': [
                'group'
            ],
            'urls': [
                '/cli/global/system/report/group/{group}'
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
        'system_report_group_chartalternative': {
            'params': [
                'group',
                'chart-alternative'
            ],
            'urls': [
                '/cli/global/system/report/group/{group}/chart-alternative/{chart-alternative}'
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
        'system_report_group_groupby': {
            'params': [
                'group',
                'group-by'
            ],
            'urls': [
                '/cli/global/system/report/group/{group}/group-by/{group-by}'
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
        'system_report_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/report/setting'
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
        'system_passwordpolicy': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/password-policy'
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
        'certificate_template': {
            'params': [
                'template',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/certificate/template/{template}',
                '/pm/config/global/obj/certificate/template/{template}'
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
        'system_backup_allsettings': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/backup/all-settings'
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
        'dvmdb_adom': {
            'params': [
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}'
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
        'system_snmp_community': {
            'params': [
                'community'
            ],
            'urls': [
                '/cli/global/system/snmp/community/{community}'
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
        'system_snmp_community_hosts': {
            'params': [
                'community',
                'hosts'
            ],
            'urls': [
                '/cli/global/system/snmp/community/{community}/hosts/{hosts}'
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
        'system_snmp_community_hosts6': {
            'params': [
                'community',
                'hosts6'
            ],
            'urls': [
                '/cli/global/system/snmp/community/{community}/hosts6/{hosts6}'
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
        'system_snmp_sysinfo': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/snmp/sysinfo'
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
        'system_snmp_user': {
            'params': [
                'user'
            ],
            'urls': [
                '/cli/global/system/snmp/user/{user}'
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
        'system_performance': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/performance'
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
        'system_route6': {
            'params': [
                'route6'
            ],
            'urls': [
                '/cli/global/system/route6/{route6}'
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
        'voip_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/voip/profile/{profile}',
                '/pm/config/global/obj/voip/profile/{profile}'
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
        'voip_profile_sccp': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/voip/profile/{profile}/sccp',
                '/pm/config/global/obj/voip/profile/{profile}/sccp'
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
        'voip_profile_sip': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/voip/profile/{profile}/sip',
                '/pm/config/global/obj/voip/profile/{profile}/sip'
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
        'metafields_system_admin_user': {
            'params': [
            ],
            'urls': [
                '/cli/global/_meta_fields/system/admin/user'
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
        'fmupdate_analyzer_virusreport': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/analyzer/virusreport'
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
        'webfilter_categories': {
            'params': [
                'categories',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/categories/{categories}',
                '/pm/config/global/obj/webfilter/categories/{categories}'
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
        'webfilter_content': {
            'params': [
                'content',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content/{content}',
                '/pm/config/global/obj/webfilter/content/{content}'
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
        'webfilter_contentheader': {
            'params': [
                'content-header',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content-header/{content-header}',
                '/pm/config/global/obj/webfilter/content-header/{content-header}'
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
                'content-header',
                'entries',
                'adom'
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
        'webfilter_content_entries': {
            'params': [
                'content',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content/{content}/entries/{entries}',
                '/pm/config/global/obj/webfilter/content/{content}/entries/{entries}'
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
        'webfilter_ftgdlocalcat': {
            'params': [
                'ftgd-local-cat',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-cat/{ftgd-local-cat}',
                '/pm/config/global/obj/webfilter/ftgd-local-cat/{ftgd-local-cat}'
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
        'webfilter_ftgdlocalrating': {
            'params': [
                'ftgd-local-rating',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-rating/{ftgd-local-rating}',
                '/pm/config/global/obj/webfilter/ftgd-local-rating/{ftgd-local-rating}'
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
        'webfilter_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}',
                '/pm/config/global/obj/webfilter/profile/{profile}'
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
        'webfilter_profile_ftgdwf': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf'
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
        'webfilter_profile_ftgdwf_filters': {
            'params': [
                'profile',
                'filters',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/filters/{filters}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/filters/{filters}'
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
        'webfilter_profile_ftgdwf_quota': {
            'params': [
                'profile',
                'quota',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/quota/{quota}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/quota/{quota}'
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
        'webfilter_profile_override': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/override',
                '/pm/config/global/obj/webfilter/profile/{profile}/override'
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
        'webfilter_profile_urlextraction': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/url-extraction',
                '/pm/config/global/obj/webfilter/profile/{profile}/url-extraction'
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
        'webfilter_profile_web': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/web',
                '/pm/config/global/obj/webfilter/profile/{profile}/web'
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
        'webfilter_profile_youtubechannelfilter': {
            'params': [
                'profile',
                'youtube-channel-filter',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/youtube-channel-filter/{youtube-channel-filter}',
                '/pm/config/global/obj/webfilter/profile/{profile}/youtube-channel-filter/{youtube-channel-filter}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'webfilter_urlfilter': {
            'params': [
                'urlfilter',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}',
                '/pm/config/global/obj/webfilter/urlfilter/{urlfilter}'
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
                'urlfilter',
                'entries',
                'adom'
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
        'system_alertconsole': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/alert-console'
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
        'firewall_address': {
            'params': [
                'address',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}',
                '/pm/config/global/obj/firewall/address/{address}'
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
        'firewall_address_dynamicmapping': {
            'params': [
                'address',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}'
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
        'firewall_address_list': {
            'params': [
                'address',
                'list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/list/{list}',
                '/pm/config/global/obj/firewall/address/{address}/list/{list}'
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
        'firewall_address_tagging': {
            'params': [
                'address',
                'tagging',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/address/{address}/tagging/{tagging}'
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
        'firewall_address6': {
            'params': [
                'address6',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}',
                '/pm/config/global/obj/firewall/address6/{address6}'
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
        'firewall_address6template': {
            'params': [
                'address6-template',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}'
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
        'firewall_address6template_subnetsegment': {
            'params': [
                'address6-template',
                'subnet-segment',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}'
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
        'firewall_address6template_subnetsegment_values': {
            'params': [
                'address6-template',
                'subnet-segment',
                'values',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values/{values}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values/{values}'
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
        'firewall_address6_dynamicmapping': {
            'params': [
                'address6',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}'
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
        'firewall_address6_list': {
            'params': [
                'address6',
                'list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/list/{list}',
                '/pm/config/global/obj/firewall/address6/{address6}/list/{list}'
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
        'firewall_address6_subnetsegment': {
            'params': [
                'address6',
                'subnet-segment',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6/{address6}/subnet-segment/{subnet-segment}'
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
        'firewall_address6_tagging': {
            'params': [
                'address6',
                'tagging',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/address6/{address6}/tagging/{tagging}'
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
        'firewall_addrgrp': {
            'params': [
                'addrgrp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}'
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
        'firewall_addrgrp_dynamicmapping': {
            'params': [
                'addrgrp',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping/{dynamic_mapping}'
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
        'firewall_addrgrp_tagging': {
            'params': [
                'addrgrp',
                'tagging',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/tagging/{tagging}'
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
        'firewall_addrgrp6': {
            'params': [
                'addrgrp6',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}'
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
        'firewall_addrgrp6_dynamicmapping': {
            'params': [
                'addrgrp6',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping/{dynamic_mapping}'
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
        'firewall_addrgrp6_tagging': {
            'params': [
                'addrgrp6',
                'tagging',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/tagging/{tagging}'
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
        'firewall_carrierendpointbwl': {
            'params': [
                'carrier-endpoint-bwl',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'firewall_carrierendpointbwl_entries': {
            'params': [
                'carrier-endpoint-bwl',
                'entries',
                'adom'
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
        'firewall_gtp': {
            'params': [
                'gtp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}',
                '/pm/config/global/obj/firewall/gtp/{gtp}'
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
        'firewall_gtp_apn': {
            'params': [
                'gtp',
                'apn',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/apn/{apn}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/apn/{apn}'
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
        'firewall_gtp_ieremovepolicy': {
            'params': [
                'gtp',
                'ie-remove-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-remove-policy/{ie-remove-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ie-remove-policy/{ie-remove-policy}'
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
        'firewall_gtp_ievalidation': {
            'params': [
                'gtp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-validation',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ie-validation'
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
        'firewall_gtp_imsi': {
            'params': [
                'gtp',
                'imsi',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/imsi/{imsi}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/imsi/{imsi}'
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
        'firewall_gtp_ippolicy': {
            'params': [
                'gtp',
                'ip-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ip-policy/{ip-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ip-policy/{ip-policy}'
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
        'firewall_gtp_messageratelimit': {
            'params': [
                'gtp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-rate-limit',
                '/pm/config/global/obj/firewall/gtp/{gtp}/message-rate-limit'
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
        'firewall_gtp_messageratelimitv0': {
            'params': [
                'gtp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-rate-limit-v0',
                '/pm/config/global/obj/firewall/gtp/{gtp}/message-rate-limit-v0'
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
        'firewall_gtp_messageratelimitv1': {
            'params': [
                'gtp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-rate-limit-v1',
                '/pm/config/global/obj/firewall/gtp/{gtp}/message-rate-limit-v1'
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
        'firewall_gtp_messageratelimitv2': {
            'params': [
                'gtp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-rate-limit-v2',
                '/pm/config/global/obj/firewall/gtp/{gtp}/message-rate-limit-v2'
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
        'firewall_gtp_noippolicy': {
            'params': [
                'gtp',
                'noip-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/noip-policy/{noip-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/noip-policy/{noip-policy}'
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
        'firewall_gtp_perapnshaper': {
            'params': [
                'gtp',
                'per-apn-shaper',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/per-apn-shaper/{per-apn-shaper}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/per-apn-shaper/{per-apn-shaper}'
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
        'firewall_gtp_policy': {
            'params': [
                'gtp',
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy/{policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/policy/{policy}'
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
        'firewall_identitybasedroute': {
            'params': [
                'identity-based-route',
                'adom'
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
        'firewall_identitybasedroute_rule': {
            'params': [
                'identity-based-route',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}/rule/{rule}',
                '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}/rule/{rule}'
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
        'firewall_internetservice': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service',
                '/pm/config/global/obj/firewall/internet-service'
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
        'firewall_internetservicecustom': {
            'params': [
                'internet-service-custom',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}'
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
        'firewall_internetservicecustomgroup': {
            'params': [
                'internet-service-custom-group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom-group/{internet-service-custom-group}',
                '/pm/config/global/obj/firewall/internet-service-custom-group/{internet-service-custom-group}'
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
        'firewall_internetservicecustom_disableentry': {
            'params': [
                'internet-service-custom',
                'disable-entry',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'firewall_internetservicecustom_disableentry_iprange': {
            'params': [
                'internet-service-custom',
                'disable-entry',
                'ip-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'firewall_internetservicecustom_entry': {
            'params': [
                'internet-service-custom',
                'entry',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}'
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
        'firewall_internetservicecustom_entry_portrange': {
            'params': [
                'internet-service-custom',
                'entry',
                'port-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}'
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
        'firewall_internetservicegroup': {
            'params': [
                'internet-service-group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-group/{internet-service-group}',
                '/pm/config/global/obj/firewall/internet-service-group/{internet-service-group}'
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
        'firewall_internetservice_entry': {
            'params': [
                'entry',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service/entry/{entry}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'firewall_ippool': {
            'params': [
                'ippool',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}',
                '/pm/config/global/obj/firewall/ippool/{ippool}'
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
        'firewall_ippool_dynamicmapping': {
            'params': [
                'ippool',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}'
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
        'firewall_ippool6': {
            'params': [
                'ippool6',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool6/{ippool6}',
                '/pm/config/global/obj/firewall/ippool6/{ippool6}'
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
        'firewall_ippool6_dynamicmapping': {
            'params': [
                'ippool6',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool6/{ippool6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/ippool6/{ippool6}/dynamic_mapping/{dynamic_mapping}'
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
        'firewall_ldbmonitor': {
            'params': [
                'ldb-monitor',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ldb-monitor/{ldb-monitor}',
                '/pm/config/global/obj/firewall/ldb-monitor/{ldb-monitor}'
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
        'firewall_mmsprofile': {
            'params': [
                'mms-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'firewall_mmsprofile_dupe': {
            'params': [
                'mms-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/dupe',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/dupe'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'firewall_mmsprofile_flood': {
            'params': [
                'mms-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/flood',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/flood'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'firewall_mmsprofile_notifmsisdn': {
            'params': [
                'mms-profile',
                'notif-msisdn',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/notif-msisdn/{notif-msisdn}',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/notif-msisdn/{notif-msisdn}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'firewall_mmsprofile_notification': {
            'params': [
                'mms-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/notification',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/notification'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'firewall_multicastaddress': {
            'params': [
                'multicast-address',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}',
                '/pm/config/global/obj/firewall/multicast-address/{multicast-address}'
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
        'firewall_multicastaddress_tagging': {
            'params': [
                'multicast-address',
                'tagging',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/multicast-address/{multicast-address}/tagging/{tagging}'
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
        'firewall_multicastaddress6': {
            'params': [
                'multicast-address6',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}',
                '/pm/config/global/obj/firewall/multicast-address6/{multicast-address6}'
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
        'firewall_multicastaddress6_tagging': {
            'params': [
                'multicast-address6',
                'tagging',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/multicast-address6/{multicast-address6}/tagging/{tagging}'
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
        'firewall_profilegroup': {
            'params': [
                'profile-group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-group/{profile-group}',
                '/pm/config/global/obj/firewall/profile-group/{profile-group}'
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
        'firewall_profileprotocoloptions': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}'
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
        'firewall_profileprotocoloptions_dns': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/dns',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/dns'
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
        'firewall_profileprotocoloptions_ftp': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/ftp',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/ftp'
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
        'firewall_profileprotocoloptions_http': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/http',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/http'
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
        'firewall_profileprotocoloptions_imap': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/imap',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/imap'
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
        'firewall_profileprotocoloptions_mailsignature': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/mail-signature',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/mail-signature'
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
        'firewall_profileprotocoloptions_mapi': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/mapi',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/mapi'
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
        'firewall_profileprotocoloptions_nntp': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/nntp',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/nntp'
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
        'firewall_profileprotocoloptions_pop3': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/pop3',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/pop3'
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
        'firewall_profileprotocoloptions_smtp': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/smtp',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/smtp'
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
        'firewall_proxyaddress': {
            'params': [
                'proxy-address',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}'
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
        'firewall_proxyaddress_headergroup': {
            'params': [
                'proxy-address',
                'header-group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/header-group/{header-group}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/header-group/{header-group}'
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
        'firewall_proxyaddress_tagging': {
            'params': [
                'proxy-address',
                'tagging',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/tagging/{tagging}'
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
        'firewall_proxyaddrgrp': {
            'params': [
                'proxy-addrgrp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp/{proxy-addrgrp}',
                '/pm/config/global/obj/firewall/proxy-addrgrp/{proxy-addrgrp}'
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
        'firewall_proxyaddrgrp_tagging': {
            'params': [
                'proxy-addrgrp',
                'tagging',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging/{tagging}'
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
        'firewall_schedule_group': {
            'params': [
                'group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/group/{group}',
                '/pm/config/global/obj/firewall/schedule/group/{group}'
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
        'firewall_schedule_onetime': {
            'params': [
                'onetime',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/onetime/{onetime}',
                '/pm/config/global/obj/firewall/schedule/onetime/{onetime}'
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
        'firewall_schedule_recurring': {
            'params': [
                'recurring',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/recurring/{recurring}',
                '/pm/config/global/obj/firewall/schedule/recurring/{recurring}'
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
                'category',
                'adom'
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
                'custom',
                'adom'
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
        'firewall_service_group': {
            'params': [
                'group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/group/{group}',
                '/pm/config/global/obj/firewall/service/group/{group}'
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
        'firewall_shaper_peripshaper': {
            'params': [
                'per-ip-shaper',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper/{per-ip-shaper}',
                '/pm/config/global/obj/firewall/shaper/per-ip-shaper/{per-ip-shaper}'
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
        'firewall_shaper_trafficshaper': {
            'params': [
                'traffic-shaper',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper/{traffic-shaper}',
                '/pm/config/global/obj/firewall/shaper/traffic-shaper/{traffic-shaper}'
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
        'firewall_shapingprofile': {
            'params': [
                'shaping-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}',
                '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}'
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
                'shaping-profile',
                'shaping-entries',
                'adom'
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
        'firewall_sslsshprofile': {
            'params': [
                'ssl-ssh-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}'
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
        'firewall_sslsshprofile_ftps': {
            'params': [
                'ssl-ssh-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ftps',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ftps'
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
        'firewall_sslsshprofile_https': {
            'params': [
                'ssl-ssh-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/https',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/https'
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
        'firewall_sslsshprofile_imaps': {
            'params': [
                'ssl-ssh-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/imaps',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/imaps'
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
        'firewall_sslsshprofile_pop3s': {
            'params': [
                'ssl-ssh-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/pop3s',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/pop3s'
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
        'firewall_sslsshprofile_smtps': {
            'params': [
                'ssl-ssh-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/smtps',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/smtps'
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
        'firewall_sslsshprofile_ssh': {
            'params': [
                'ssl-ssh-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssh',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssh'
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
        'firewall_sslsshprofile_ssl': {
            'params': [
                'ssl-ssh-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl'
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
        'firewall_sslsshprofile_sslexempt': {
            'params': [
                'ssl-ssh-profile',
                'ssl-exempt',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt/{ssl-exempt}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt/{ssl-exempt}'
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
        'firewall_sslsshprofile_sslserver': {
            'params': [
                'ssl-ssh-profile',
                'ssl-server',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}'
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
                'vip',
                'adom'
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
        'firewall_vip_dynamicmapping': {
            'params': [
                'vip',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}'
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
        'firewall_vip_dynamicmapping_realservers': {
            'params': [
                'vip',
                'dynamic_mapping',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}'
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
        'firewall_vip_dynamicmapping_sslciphersuites': {
            'params': [
                'vip',
                'dynamic_mapping',
                'ssl-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}'
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
        'firewall_vip_realservers': {
            'params': [
                'vip',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip/{vip}/realservers/{realservers}'
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
        'firewall_vip_sslciphersuites': {
            'params': [
                'vip',
                'ssl-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-cipher-suites/{ssl-cipher-suites}'
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
        'firewall_vip_sslserverciphersuites': {
            'params': [
                'vip',
                'ssl-server-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-server-cipher-suites/{ssl-server-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-server-cipher-suites/{ssl-server-cipher-suites}'
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
        'firewall_vip46': {
            'params': [
                'vip46',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}',
                '/pm/config/global/obj/firewall/vip46/{vip46}'
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
        'firewall_vip46_dynamicmapping': {
            'params': [
                'vip46',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip46/{vip46}/dynamic_mapping/{dynamic_mapping}'
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
        'firewall_vip46_realservers': {
            'params': [
                'vip46',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip46/{vip46}/realservers/{realservers}'
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
        'firewall_vip6': {
            'params': [
                'vip6',
                'adom'
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
        'firewall_vip6_dynamicmapping': {
            'params': [
                'vip6',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}'
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
        'firewall_vip6_realservers': {
            'params': [
                'vip6',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/realservers/{realservers}'
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
        'firewall_vip6_sslciphersuites': {
            'params': [
                'vip6',
                'ssl-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-cipher-suites/{ssl-cipher-suites}'
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
        'firewall_vip6_sslserverciphersuites': {
            'params': [
                'vip6',
                'ssl-server-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites/{ssl-server-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites/{ssl-server-cipher-suites}'
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
        'firewall_vip64': {
            'params': [
                'vip64',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}',
                '/pm/config/global/obj/firewall/vip64/{vip64}'
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
        'firewall_vip64_dynamicmapping': {
            'params': [
                'vip64',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip64/{vip64}/dynamic_mapping/{dynamic_mapping}'
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
        'firewall_vip64_realservers': {
            'params': [
                'vip64',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip64/{vip64}/realservers/{realservers}'
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
        'firewall_vipgrp': {
            'params': [
                'vipgrp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp/{vipgrp}',
                '/pm/config/global/obj/firewall/vipgrp/{vipgrp}'
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
        'firewall_vipgrp_dynamicmapping': {
            'params': [
                'vipgrp',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping/{dynamic_mapping}'
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
        'firewall_vipgrp46': {
            'params': [
                'vipgrp46',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp46/{vipgrp46}',
                '/pm/config/global/obj/firewall/vipgrp46/{vipgrp46}'
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
        'firewall_vipgrp6': {
            'params': [
                'vipgrp6',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp6/{vipgrp6}',
                '/pm/config/global/obj/firewall/vipgrp6/{vipgrp6}'
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
        'firewall_vipgrp64': {
            'params': [
                'vipgrp64',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp64/{vipgrp64}',
                '/pm/config/global/obj/firewall/vipgrp64/{vipgrp64}'
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
        'firewall_wildcardfqdn_custom': {
            'params': [
                'custom',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom/{custom}',
                '/pm/config/global/obj/firewall/wildcard-fqdn/custom/{custom}'
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
        'firewall_wildcardfqdn_group': {
            'params': [
                'group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/group/{group}',
                '/pm/config/global/obj/firewall/wildcard-fqdn/group/{group}'
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
        'webproxy_forwardserver': {
            'params': [
                'forward-server',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server/{forward-server}',
                '/pm/config/global/obj/web-proxy/forward-server/{forward-server}'
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
        'webproxy_forwardservergroup': {
            'params': [
                'forward-server-group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{forward-server-group}',
                '/pm/config/global/obj/web-proxy/forward-server-group/{forward-server-group}'
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
        'webproxy_forwardservergroup_serverlist': {
            'params': [
                'forward-server-group',
                'server-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{forward-server-group}/server-list/{server-list}',
                '/pm/config/global/obj/web-proxy/forward-server-group/{forward-server-group}/server-list/{server-list}'
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
        'webproxy_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/profile/{profile}',
                '/pm/config/global/obj/web-proxy/profile/{profile}'
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
        'webproxy_profile_headers': {
            'params': [
                'profile',
                'headers',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/profile/{profile}/headers/{headers}',
                '/pm/config/global/obj/web-proxy/profile/{profile}/headers/{headers}'
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
        'webproxy_wisp': {
            'params': [
                'wisp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/wisp/{wisp}',
                '/pm/config/global/obj/web-proxy/wisp/{wisp}'
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
        'system_route': {
            'params': [
                'route'
            ],
            'urls': [
                '/cli/global/system/route/{route}'
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
        'dvmdb_script': {
            'params': [
                'script',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/script/{script}',
                '/dvmdb/global/script/{script}',
                '/dvmdb/script/{script}'
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
        'dvmdb_script_scriptschedule': {
            'params': [
                'script',
                'script_schedule',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/script/{script}/script_schedule/{script_schedule}',
                '/dvmdb/global/script/{script}/script_schedule/{script_schedule}',
                '/dvmdb/script/{script}/script_schedule/{script_schedule}'
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
        'dvmdb_script_log_latest': {
            'params': [
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/latest',
                '/dvmdb/global/script/log/latest'
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
        'dvmdb_script_log_latest_device': {
            'params': [
                'device_name',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/latest/device/{device_name}',
                '/dvmdb/script/log/latest/device/{device_name}'
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
        'dvmdb_script_log_list': {
            'params': [
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/list',
                '/dvmdb/global/script/log/list'
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
        'dvmdb_script_log_list_device': {
            'params': [
                'device_name',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/list/device/{device_name}',
                '/dvmdb/script/log/list/device/{device_name}'
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
        'dvmdb_script_log_output_device_logid': {
            'params': [
                'device',
                'log_id',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/output/device/{device}/logid/{log_id}',
                '/dvmdb/script/log/output/device/{device}/logid/{log_id}'
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
        'dvmdb_script_log_output_logid': {
            'params': [
                'log_id',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/output/logid/{log_id}',
                '/dvmdb/global/script/log/output/logid/{log_id}'
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
        'dvmdb_script_log_summary': {
            'params': [
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/summary',
                '/dvmdb/global/script/log/summary'
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
        'dvmdb_script_log_summary_device': {
            'params': [
                'device_name',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/summary/device/{device_name}',
                '/dvmdb/script/log/summary/device/{device_name}'
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
        'system_fortiview_autocache': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/fortiview/auto-cache'
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
        'system_fortiview_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/fortiview/setting'
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
        'vpn_certificate_ca': {
            'params': [
                'ca',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/ca/{ca}',
                '/pm/config/global/obj/vpn/certificate/ca/{ca}'
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
        'vpn_certificate_ocspserver': {
            'params': [
                'ocsp-server',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server/{ocsp-server}',
                '/pm/config/global/obj/vpn/certificate/ocsp-server/{ocsp-server}'
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
        'vpn_certificate_remote': {
            'params': [
                'remote',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/remote/{remote}',
                '/pm/config/global/obj/vpn/certificate/remote/{remote}'
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
        'vpnsslweb_hostchecksoftware': {
            'params': [
                'host-check-software',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}'
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
        'vpnsslweb_hostchecksoftware_checkitemlist': {
            'params': [
                'host-check-software',
                'check-item-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list/{check-item-list}',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list/{check-item-list}'
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
        'vpnsslweb_portal': {
            'params': [
                'portal',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}'
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
                'portal',
                'bookmark-group',
                'adom'
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
                'portal',
                'bookmark-group',
                'bookmarks',
                'adom'
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
        'vpnsslweb_portal_bookmarkgroup_bookmarks_formdata': {
            'params': [
                'portal',
                'bookmark-group',
                'bookmarks',
                'form-data',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data/{form-data}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data/{form-data}'
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
        'vpnsslweb_portal_macaddrcheckrule': {
            'params': [
                'portal',
                'mac-addr-check-rule',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule/{mac-addr-check-rule}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule/{mac-addr-check-rule}'
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
        'vpnsslweb_portal_oschecklist': {
            'params': [
                'portal',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/os-check-list',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/os-check-list'
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
                'portal',
                'split-dns',
                'adom'
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
        'vpnsslweb_realm': {
            'params': [
                'realm',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/realm/{realm}',
                '/pm/config/global/obj/vpn/ssl/web/realm/{realm}'
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
        'fmupdate_serveroverridestatus': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/server-override-status'
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
                'pkg',
                'dnat',
                'adom'
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
        'wanprof_system_virtualwanlink': {
            'params': [
                'wanprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'wanprof_system_virtualwanlink_healthcheck': {
            'params': [
                'wanprof',
                'health-check',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'wanprof_system_virtualwanlink_healthcheck_sla': {
            'params': [
                'wanprof',
                'health-check',
                'sla',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}/sla/{sla}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'wanprof_system_virtualwanlink_members': {
            'params': [
                'wanprof',
                'members',
                'adom'
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
                'wanprof',
                'service',
                'adom'
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
                'wanprof',
                'service',
                'sla',
                'adom'
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
        'devprof_system_centralmanagement': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/central-management'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_centralmanagement_serverlist': {
            'params': [
                'devprof',
                'server-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/central-management/server-list/{server-list}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_dns': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/dns'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'devprof_system_emailserver': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/email-server'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_global': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/global'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_ntp': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/ntp'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_ntp_ntpserver': {
            'params': [
                'devprof',
                'ntpserver',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/ntp/ntpserver/{ntpserver}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_admin': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/admin'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_alertmail': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/alertmail'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_auth': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/auth'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_devicedetectionportal': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/device-detection-portal'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True
            }
        },
        'devprof_system_replacemsg_ec': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/ec'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'devprof_system_replacemsg_fortiguardwf': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/fortiguard-wf'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_ftp': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/ftp'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_http': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/http'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_mail': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/mail'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_mms': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/mms'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'devprof_system_replacemsg_nacquar': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/nac-quar'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_nntp': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/nntp'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True
            }
        },
        'devprof_system_replacemsg_spam': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/spam'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_sslvpn': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/sslvpn'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_trafficquota': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/traffic-quota'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_utm': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/utm'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_replacemsg_webproxy': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/webproxy'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_snmp_community': {
            'params': [
                'devprof',
                'community',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_snmp_community_hosts': {
            'params': [
                'devprof',
                'community',
                'hosts',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts/{hosts}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_snmp_community_hosts6': {
            'params': [
                'devprof',
                'community',
                'hosts6',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts6/{hosts6}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_snmp_sysinfo': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/sysinfo'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'devprof_system_snmp_user': {
            'params': [
                'devprof',
                'user',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user/{user}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'dvmdb_metafields_adom': {
            'params': [
            ],
            'urls': [
                '/dvmdb/_meta_fields/adom'
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
        'dvmdb_metafields_device': {
            'params': [
            ],
            'urls': [
                '/dvmdb/_meta_fields/device'
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
        'dvmdb_metafields_group': {
            'params': [
            ],
            'urls': [
                '/dvmdb/_meta_fields/group'
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
        'gtp_apn': {
            'params': [
                'apn',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/apn/{apn}',
                '/pm/config/global/obj/gtp/apn/{apn}'
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
        'gtp_apngrp': {
            'params': [
                'apngrp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/apngrp/{apngrp}',
                '/pm/config/global/obj/gtp/apngrp/{apngrp}'
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
        'gtp_iewhitelist': {
            'params': [
                'ie-white-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list/{ie-white-list}',
                '/pm/config/global/obj/gtp/ie-white-list/{ie-white-list}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'gtp_iewhitelist_entries': {
            'params': [
                'ie-white-list',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list/{ie-white-list}/entries/{entries}',
                '/pm/config/global/obj/gtp/ie-white-list/{ie-white-list}/entries/{entries}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'gtp_messagefilterv0v1': {
            'params': [
                'message-filter-v0v1',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v0v1/{message-filter-v0v1}',
                '/pm/config/global/obj/gtp/message-filter-v0v1/{message-filter-v0v1}'
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
        'gtp_messagefilterv2': {
            'params': [
                'message-filter-v2',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v2/{message-filter-v2}',
                '/pm/config/global/obj/gtp/message-filter-v2/{message-filter-v2}'
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
        'gtp_tunnellimit': {
            'params': [
                'tunnel-limit',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/tunnel-limit/{tunnel-limit}',
                '/pm/config/global/obj/gtp/tunnel-limit/{tunnel-limit}'
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
        'wanopt_authgroup': {
            'params': [
                'auth-group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/auth-group/{auth-group}',
                '/pm/config/global/obj/wanopt/auth-group/{auth-group}'
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
        'wanopt_peer': {
            'params': [
                'peer',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/peer/{peer}',
                '/pm/config/global/obj/wanopt/peer/{peer}'
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
        'wanopt_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}',
                '/pm/config/global/obj/wanopt/profile/{profile}'
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
        'wanopt_profile_cifs': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/cifs',
                '/pm/config/global/obj/wanopt/profile/{profile}/cifs'
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
        'wanopt_profile_ftp': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/ftp',
                '/pm/config/global/obj/wanopt/profile/{profile}/ftp'
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
        'wanopt_profile_http': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/http',
                '/pm/config/global/obj/wanopt/profile/{profile}/http'
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
        'wanopt_profile_mapi': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/mapi',
                '/pm/config/global/obj/wanopt/profile/{profile}/mapi'
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
        'wanopt_profile_tcp': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/tcp',
                '/pm/config/global/obj/wanopt/profile/{profile}/tcp'
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
        'system_ha': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/ha'
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
        'system_ha_peer': {
            'params': [
                'peer'
            ],
            'urls': [
                '/cli/global/system/ha/peer/{peer}'
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
        'system_admin_group': {
            'params': [
                'group'
            ],
            'urls': [
                '/cli/global/system/admin/group/{group}'
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
        'system_admin_group_member': {
            'params': [
                'group',
                'member'
            ],
            'urls': [
                '/cli/global/system/admin/group/{group}/member/{member}'
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
        'system_admin_ldap': {
            'params': [
                'ldap'
            ],
            'urls': [
                '/cli/global/system/admin/ldap/{ldap}'
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
        'system_admin_ldap_adom': {
            'params': [
                'ldap',
                'adom'
            ],
            'urls': [
                '/cli/global/system/admin/ldap/{ldap}/adom/{adom}'
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
        'system_admin_profile': {
            'params': [
                'profile'
            ],
            'urls': [
                '/cli/global/system/admin/profile/{profile}'
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
        'system_admin_profile_datamaskcustomfields': {
            'params': [
                'profile',
                'datamask-custom-fields'
            ],
            'urls': [
                '/cli/global/system/admin/profile/{profile}/datamask-custom-fields/{datamask-custom-fields}'
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
        'system_admin_radius': {
            'params': [
                'radius'
            ],
            'urls': [
                '/cli/global/system/admin/radius/{radius}'
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
        'system_admin_setting': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/admin/setting'
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
        'system_admin_tacacs': {
            'params': [
                'tacacs'
            ],
            'urls': [
                '/cli/global/system/admin/tacacs/{tacacs}'
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
        'system_admin_user': {
            'params': [
                'user'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}'
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
        'system_admin_user_adom': {
            'params': [
                'user',
                'adom'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/adom/{adom}'
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
        'system_admin_user_adomexclude': {
            'params': [
                'user',
                'adom-exclude'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/adom-exclude/{adom-exclude}'
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
        'system_admin_user_appfilter': {
            'params': [
                'user',
                'app-filter'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/app-filter/{app-filter}'
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
        'system_admin_user_dashboard': {
            'params': [
                'user',
                'dashboard'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/dashboard/{dashboard}'
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
        'system_admin_user_dashboardtabs': {
            'params': [
                'user',
                'dashboard-tabs'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/dashboard-tabs/{dashboard-tabs}'
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
        'system_admin_user_ipsfilter': {
            'params': [
                'user',
                'ips-filter'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/ips-filter/{ips-filter}'
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
        'system_admin_user_metadata': {
            'params': [
                'user',
                'meta-data'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/meta-data/{meta-data}'
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
        'system_admin_user_policypackage': {
            'params': [
                'user',
                'policy-package'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/policy-package/{policy-package}'
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
        'system_admin_user_restrictdevvdom': {
            'params': [
                'user',
                'restrict-dev-vdom'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/restrict-dev-vdom/{restrict-dev-vdom}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.4.0': True
            }
        },
        'system_admin_user_webfilter': {
            'params': [
                'user',
                'web-filter'
            ],
            'urls': [
                '/cli/global/system/admin/user/{user}/web-filter/{web-filter}'
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
        'dynamic_address': {
            'params': [
                'address',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/address/{address}',
                '/pm/config/global/obj/dynamic/address/{address}'
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
        'dynamic_address_dynamicaddrmapping': {
            'params': [
                'address',
                'dynamic_addr_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/address/{address}/dynamic_addr_mapping/{dynamic_addr_mapping}',
                '/pm/config/global/obj/dynamic/address/{address}/dynamic_addr_mapping/{dynamic_addr_mapping}'
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
        'dynamic_certificate_local': {
            'params': [
                'local',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local/{local}',
                '/pm/config/global/obj/dynamic/certificate/local/{local}'
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
        'dynamic_certificate_local_dynamicmapping': {
            'params': [
                'local',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local/{local}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/certificate/local/{local}/dynamic_mapping/{dynamic_mapping}'
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
        'dynamic_interface': {
            'params': [
                'interface',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}',
                '/pm/config/global/obj/dynamic/interface/{interface}'
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
        'dynamic_interface_dynamicmapping': {
            'params': [
                'interface',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
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
        'dynamic_ippool': {
            'params': [
                'ippool',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/ippool/{ippool}',
                '/pm/config/global/obj/dynamic/ippool/{ippool}'
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
        'dynamic_multicast_interface': {
            'params': [
                'interface',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}',
                '/pm/config/global/obj/dynamic/multicast/interface/{interface}'
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
        'dynamic_multicast_interface_dynamicmapping': {
            'params': [
                'interface',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/multicast/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
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
        'dynamic_vip': {
            'params': [
                'vip',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vip/{vip}',
                '/pm/config/global/obj/dynamic/vip/{vip}'
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
        'dynamic_virtualwanlink_members': {
            'params': [
                'members',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'dynamic_virtualwanlink_members_dynamicmapping': {
            'params': [
                'members',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'dynamic_virtualwanlink_server': {
            'params': [
                'server',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server/{server}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server/{server}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'dynamic_virtualwanlink_server_dynamicmapping': {
            'params': [
                'server',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'dynamic_vpntunnel': {
            'params': [
                'vpntunnel',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}',
                '/pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}'
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
        'dynamic_vpntunnel_dynamicmapping': {
            'params': [
                'vpntunnel',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping/{dynamic_mapping}'
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
        'system_certificate_ca': {
            'params': [
                'ca'
            ],
            'urls': [
                '/cli/global/system/certificate/ca/{ca}'
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
        'system_certificate_crl': {
            'params': [
                'crl'
            ],
            'urls': [
                '/cli/global/system/certificate/crl/{crl}'
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
        'system_certificate_local': {
            'params': [
                'local'
            ],
            'urls': [
                '/cli/global/system/certificate/local/{local}'
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
        'system_certificate_oftp': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/certificate/oftp'
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
        'system_certificate_remote': {
            'params': [
                'remote'
            ],
            'urls': [
                '/cli/global/system/certificate/remote/{remote}'
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
        'system_certificate_ssh': {
            'params': [
                'ssh'
            ],
            'urls': [
                '/cli/global/system/certificate/ssh/{ssh}'
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
        'system_log_alert': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/alert'
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
        'system_log_ioc': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/ioc'
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
        'system_log_maildomain': {
            'params': [
                'mail-domain'
            ],
            'urls': [
                '/cli/global/system/log/mail-domain/{mail-domain}'
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
        'system_log_settings': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/settings'
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
        'system_log_settings_rollinganalyzer': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/settings/rolling-analyzer'
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
        'system_log_settings_rollinglocal': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/settings/rolling-local'
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
        'system_log_settings_rollingregular': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/settings/rolling-regular'
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
        'system_dm': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/dm'
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
        'adom_options': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/adom/options',
                '/pm/config/global/obj/adom/options'
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
        'switchcontroller_lldpprofile': {
            'params': [
                'lldp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}'
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
        'switchcontroller_lldpprofile_customtlvs': {
            'params': [
                'lldp-profile',
                'custom-tlvs',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}'
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
        'switchcontroller_lldpprofile_mednetworkpolicy': {
            'params': [
                'lldp-profile',
                'med-network-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}'
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
        'switchcontroller_managedswitch': {
            'params': [
                'managed-switch',
                'adom'
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
        'switchcontroller_managedswitch_ports': {
            'params': [
                'managed-switch',
                'ports',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}'
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
        'switchcontroller_qos_dot1pmap': {
            'params': [
                'dot1p-map',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/dot1p-map/{dot1p-map}',
                '/pm/config/global/obj/switch-controller/qos/dot1p-map/{dot1p-map}'
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
        'switchcontroller_qos_ipdscpmap': {
            'params': [
                'ip-dscp-map',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}'
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
        'switchcontroller_qos_ipdscpmap_map': {
            'params': [
                'ip-dscp-map',
                'map',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}'
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
        'switchcontroller_qos_qospolicy': {
            'params': [
                'qos-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/qos-policy/{qos-policy}',
                '/pm/config/global/obj/switch-controller/qos/qos-policy/{qos-policy}'
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
        'switchcontroller_qos_queuepolicy': {
            'params': [
                'queue-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}',
                '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}'
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
        'switchcontroller_qos_queuepolicy_cosqueue': {
            'params': [
                'queue-policy',
                'cos-queue',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}',
                '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}'
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
        'switchcontroller_securitypolicy_8021x': {
            'params': [
                '802-1X',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/802-1X/{802-1X}',
                '/pm/config/global/obj/switch-controller/security-policy/802-1X/{802-1X}'
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
        'switchcontroller_securitypolicy_captiveportal': {
            'params': [
                'captive-portal',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/captive-portal/{captive-portal}',
                '/pm/config/global/obj/switch-controller/security-policy/captive-portal/{captive-portal}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True
            }
        },
        'switchcontroller_managedswitch_8021xsettings': {
            'params': [
                'device',
                'vdom',
                'managed-switch'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/802-1X-settings'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'switchcontroller_managedswitch_customcommand': {
            'params': [
                'managed-switch',
                'custom-command',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'switchcontroller_managedswitch_igmpsnooping': {
            'params': [
                'device',
                'vdom',
                'managed-switch'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/igmp-snooping'
            ],
            'revision': {
                '6.0.0': True
            }
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
            'revision': {
                '6.0.0': True
            }
        },
        'switchcontroller_managedswitch_stormcontrol': {
            'params': [
                'device',
                'vdom',
                'managed-switch'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/storm-control'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'switchcontroller_managedswitch_stpsettings': {
            'params': [
                'device',
                'vdom',
                'managed-switch'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/stp-settings'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'switchcontroller_managedswitch_switchlog': {
            'params': [
                'device',
                'vdom',
                'managed-switch'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/switch-log'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'switchcontroller_managedswitch_switchstpsettings': {
            'params': [
                'device',
                'vdom',
                'managed-switch'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/switch-stp-settings'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'sys_status': {
            'params': [
            ],
            'urls': [
                '/sys/status'
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
        'dvmdb_workspace_dirty': {
            'params': [
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/dirty',
                '/dvmdb/global/workspace/dirty'
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
        'dvmdb_workspace_dirty_dev': {
            'params': [
                'device_name',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/dirty/dev/{device_name}'
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
        'dvmdb_workspace_lockinfo': {
            'params': [
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/lockinfo',
                '/dvmdb/global/workspace/lockinfo'
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
        'dvmdb_workspace_lockinfo_dev': {
            'params': [
                'device_name',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/lockinfo/dev/{device_name}'
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
        'dvmdb_workspace_lockinfo_obj': {
            'params': [
                'object_url_name',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/lockinfo/obj/{object_url_name}',
                '/dvmdb/global/workspace/lockinfo/obj/{object_url_name}'
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
        'dvmdb_workspace_lockinfo_pkg': {
            'params': [
                'package_path_name',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/lockinfo/pkg/{package_path_name}',
                '/dvmdb/global/workspace/lockinfo/pkg/{package_path_name}'
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
        'system_metadata_admins': {
            'params': [
                'admins'
            ],
            'urls': [
                '/cli/global/system/metadata/admins/{admins}'
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
        'system_connector': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/connector'
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
        'task_task': {
            'params': [
                'task'
            ],
            'urls': [
                '/task/task/{task}'
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
        'task_task_history': {
            'params': [
                'task',
                'history'
            ],
            'urls': [
                '/task/task/{task}/history/{history}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'task_task_line': {
            'params': [
                'task',
                'line'
            ],
            'urls': [
                '/task/task/{task}/line/{line}'
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
                'pkg',
                'central-snat-map',
                'adom'
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
                'pkg',
                'DoS-policy',
                'adom'
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
        'pkg_firewall_dospolicy_anomaly': {
            'params': [
                'pkg',
                'DoS-policy',
                'anomaly',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{DoS-policy}/anomaly/{anomaly}'
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
                'pkg',
                'DoS-policy6',
                'adom'
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
        'pkg_firewall_dospolicy6_anomaly': {
            'params': [
                'pkg',
                'DoS-policy6',
                'anomaly',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}/anomaly/{anomaly}'
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
                'pkg',
                'interface-policy',
                'adom'
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
                'pkg',
                'interface-policy6',
                'adom'
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
                'pkg',
                'local-in-policy',
                'adom'
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
                'pkg',
                'local-in-policy6',
                'adom'
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
                'pkg',
                'multicast-policy',
                'adom'
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
                'pkg',
                'multicast-policy6',
                'adom'
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
                'pkg',
                'policy',
                'adom'
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
        'pkg_firewall_policy_vpndstnode': {
            'params': [
                'pkg',
                'policy',
                'vpn_dst_node',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_dst_node/{vpn_dst_node}'
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
        'pkg_firewall_policy_vpnsrcnode': {
            'params': [
                'pkg',
                'policy',
                'vpn_src_node',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_src_node/{vpn_src_node}'
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
        'pkg_firewall_policy46': {
            'params': [
                'pkg',
                'policy46',
                'adom'
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
                'pkg',
                'policy6',
                'adom'
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
                'pkg',
                'policy64',
                'adom'
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
                'pkg',
                'proxy-policy',
                'adom'
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
                'pkg',
                'shaping-policy',
                'adom'
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
        'fmupdate_multilayer': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/multilayer'
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
        'fmupdate_diskquota': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/disk-quota'
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
        'system_guiact': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/guiact'
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
        'pm_pkg_adom': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/pkg/adom/{adom}'
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
        'pm_pkg': {
            'params': [
                'pkg_path',
                'adom'
            ],
            'urls': [
                '/pm/pkg/adom/{adom}/{pkg_path}',
                '/pm/pkg/global/{pkg_path}'
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
        'pm_pkg_global': {
            'params': [
            ],
            'urls': [
                '/pm/pkg/global'
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
        'system_sql': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/sql'
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
        'system_sql_customindex': {
            'params': [
                'custom-index'
            ],
            'urls': [
                '/cli/global/system/sql/custom-index/{custom-index}'
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
        'system_sql_tsindexfield': {
            'params': [
                'ts-index-field'
            ],
            'urls': [
                '/cli/global/system/sql/ts-index-field/{ts-index-field}'
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
        'pm_pkg_schedule': {
            'params': [
                'pkg_name_path',
                'adom'
            ],
            'urls': [
                '/pm/pkg/adom/{adom}/{pkg_name_path}/schedule',
                '/pm/pkg/global/{pkg_name_path}/schedule'
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
        'pm_wanprof_adom': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/wanprof/adom/{adom}'
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
        'pm_wanprof': {
            'params': [
                'pkg_path',
                'adom'
            ],
            'urls': [
                '/pm/wanprof/adom/{adom}/{pkg_path}'
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
        'icap_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}',
                '/pm/config/global/obj/icap/profile/{profile}'
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
        'icap_server': {
            'params': [
                'server',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/server/{server}',
                '/pm/config/global/obj/icap/server/{server}'
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
        'fmupdate_customurllist': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/custom-url-list'
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
        'dvmdb_group': {
            'params': [
                'group',
                'adom'
            ],
            'urls': [
                '/dvmdb/adom/{adom}/group/{group}',
                '/dvmdb/group/{group}'
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
        'dnsfilter_domainfilter': {
            'params': [
                'domain-filter',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}',
                '/pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}'
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
                'domain-filter',
                'entries',
                'adom'
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
        'dnsfilter_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}',
                '/pm/config/global/obj/dnsfilter/profile/{profile}'
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
        'dnsfilter_profile_domainfilter': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/domain-filter',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/domain-filter'
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
        'dnsfilter_profile_ftgddns': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/ftgd-dns',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/ftgd-dns'
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
        'dnsfilter_profile_ftgddns_filters': {
            'params': [
                'profile',
                'filters',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/ftgd-dns/filters/{filters}',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/ftgd-dns/filters/{filters}'
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
        'system_fips': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/fips'
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
        'bleprofile': {
            'params': [
                'ble-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/ble-profile/{ble-profile}',
                '/pm/config/global/obj/wireless-controller/ble-profile/{ble-profile}'
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
        'bonjourprofile': {
            'params': [
                'bonjour-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile/{bonjour-profile}',
                '/pm/config/global/obj/wireless-controller/bonjour-profile/{bonjour-profile}'
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
                'bonjour-profile',
                'policy-list',
                'adom'
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
        'hotspot20_anqp3gppcellular': {
            'params': [
                'anqp-3gpp-cellular',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}'
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
        'hotspot20_anqp3gppcellular_mccmnclist': {
            'params': [
                'anqp-3gpp-cellular',
                'mcc-mnc-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}'
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
        'hotspot20_anqpipaddresstype': {
            'params': [
                'anqp-ip-address-type',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}'
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
        'hotspot20_anqpnairealm': {
            'params': [
                'anqp-nai-realm',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}'
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
        'hotspot20_anqpnairealm_nailist': {
            'params': [
                'anqp-nai-realm',
                'nai-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}'
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
        'hotspot20_anqpnairealm_nailist_eapmethod': {
            'params': [
                'anqp-nai-realm',
                'nai-list',
                'eap-method',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}'
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
        'hotspot20_anqpnairealm_nailist_eapmethod_authparam': {
            'params': [
                'anqp-nai-realm',
                'nai-list',
                'eap-method',
                'auth-param',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-param/{auth-param}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-param/{auth-param}'
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
        'hotspot20_anqpnetworkauthtype': {
            'params': [
                'anqp-network-auth-type',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}'
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
        'hotspot20_anqproamingconsortium': {
            'params': [
                'anqp-roaming-consortium',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}'
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
        'hotspot20_anqproamingconsortium_oilist': {
            'params': [
                'anqp-roaming-consortium',
                'oi-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}'
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
        'hotspot20_anqpvenuename': {
            'params': [
                'anqp-venue-name',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}'
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
        'hotspot20_anqpvenuename_valuelist': {
            'params': [
                'anqp-venue-name',
                'value-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}'
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
        'hotspot20_h2qpconncapability': {
            'params': [
                'h2qp-conn-capability',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}'
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
        'hotspot20_h2qpoperatorname': {
            'params': [
                'h2qp-operator-name',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}'
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
        'hotspot20_h2qpoperatorname_valuelist': {
            'params': [
                'h2qp-operator-name',
                'value-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}'
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
        'hotspot20_h2qposuprovider': {
            'params': [
                'h2qp-osu-provider',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}'
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
        'hotspot20_h2qposuprovider_friendlyname': {
            'params': [
                'h2qp-osu-provider',
                'friendly-name',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}'
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
        'hotspot20_h2qposuprovider_servicedescription': {
            'params': [
                'h2qp-osu-provider',
                'service-description',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-description}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-description}'
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
        'hotspot20_h2qpwanmetric': {
            'params': [
                'h2qp-wan-metric',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}'
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
        'hotspot20_hsprofile': {
            'params': [
                'hs-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}',
                '/pm/config/global/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}'
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
        'hotspot20_qosmap': {
            'params': [
                'qos-map',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}'
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
        'hotspot20_qosmap_dscpexcept': {
            'params': [
                'qos-map',
                'dscp-except',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}'
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
        'hotspot20_qosmap_dscprange': {
            'params': [
                'qos-map',
                'dscp-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}'
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
        'qosprofile': {
            'params': [
                'qos-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/qos-profile/{qos-profile}',
                '/pm/config/global/obj/wireless-controller/qos-profile/{qos-profile}'
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
        'vap': {
            'params': [
                'vap',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}'
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
        'vapgroup': {
            'params': [
                'vap-group',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap-group/{vap-group}',
                '/pm/config/global/obj/wireless-controller/vap-group/{vap-group}'
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
        'vap_dynamicmapping': {
            'params': [
                'vap',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/dynamic_mapping/{dynamic_mapping}'
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
        'vap_macfilterlist': {
            'params': [
                'vap',
                'mac-filter-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}'
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
        'vap_mpskkey': {
            'params': [
                'vap',
                'mpsk-key',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}'
            ],
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'vap_portalmessageoverrides': {
            'params': [
                'vap',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/portal-message-overrides',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/portal-message-overrides'
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
        'vap_vlanpool': {
            'params': [
                'vap',
                'vlan-pool',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}'
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
        'widsprofile': {
            'params': [
                'wids-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wids-profile/{wids-profile}',
                '/pm/config/global/obj/wireless-controller/wids-profile/{wids-profile}'
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
        'wtpprofile': {
            'params': [
                'wtp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}'
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
        'wtpprofile_denymaclist': {
            'params': [
                'wtp-profile',
                'deny-mac-list',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}'
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
        'wtpprofile_lan': {
            'params': [
                'wtp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/lan',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/lan'
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
        'wtpprofile_lbs': {
            'params': [
                'wtp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/lbs',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/lbs'
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
        'wtpprofile_platform': {
            'params': [
                'wtp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/platform',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/platform'
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
        'wtpprofile_radio1': {
            'params': [
                'wtp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-1',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-1'
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
        'wtpprofile_radio2': {
            'params': [
                'wtp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-2',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-2'
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
        'wtpprofile_splittunnelingacl': {
            'params': [
                'wtp-profile',
                'split-tunneling-acl',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}'
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
        'dlp_filepattern': {
            'params': [
                'filepattern',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}',
                '/pm/config/global/obj/dlp/filepattern/{filepattern}'
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
                'filepattern',
                'entries',
                'adom'
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
        'dlp_fpsensitivity': {
            'params': [
                'fp-sensitivity',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/fp-sensitivity/{fp-sensitivity}',
                '/pm/config/global/obj/dlp/fp-sensitivity/{fp-sensitivity}'
            ],
            'revision': {
                '6.0.0': True
            }
        },
        'dlp_sensor': {
            'params': [
                'sensor',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}',
                '/pm/config/global/obj/dlp/sensor/{sensor}'
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
                'sensor',
                'filter',
                'adom'
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
        'fsp_vlan': {
            'params': [
                'vlan',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}',
                '/pm/config/global/obj/fsp/vlan/{vlan}'
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
        'fsp_vlan_dhcpserver': {
            'params': [
                'vlan',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server'
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
        'fsp_vlan_dhcpserver_excluderange': {
            'params': [
                'vlan',
                'exclude-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range/{exclude-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range/{exclude-range}'
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
        'fsp_vlan_dhcpserver_iprange': {
            'params': [
                'vlan',
                'ip-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/ip-range/{ip-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/ip-range/{ip-range}'
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
        'fsp_vlan_dhcpserver_options': {
            'params': [
                'vlan',
                'options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/options/{options}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/options/{options}'
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
        'fsp_vlan_dhcpserver_reservedaddress': {
            'params': [
                'vlan',
                'reserved-address',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address/{reserved-address}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address/{reserved-address}'
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
        'fsp_vlan_dynamicmapping': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}'
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
        'fsp_vlan_dynamicmapping_dhcpserver': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server'
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
        'fsp_vlan_dynamicmapping_dhcpserver_excluderange': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'exclude-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range/{exclude-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range/{exclude-range}'
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
        'fsp_vlan_dynamicmapping_dhcpserver_iprange': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'ip-range',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}'
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
        'fsp_vlan_dynamicmapping_dhcpserver_options': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'options',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options/{options}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options/{options}'
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
        'fsp_vlan_dynamicmapping_dhcpserver_reservedaddress': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'reserved-address',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address/{reserved-address}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address/{reserved-address}'
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
        'fsp_vlan_dynamicmapping_interface': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface'
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
        'fsp_vlan_interface': {
            'params': [
                'vlan',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface'
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
        'fsp_vlan_interface_ipv6': {
            'params': [
                'vlan',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6'
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
        'fsp_vlan_interface_secondaryip': {
            'params': [
                'vlan',
                'secondaryip',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/secondaryip/{secondaryip}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/secondaryip/{secondaryip}'
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
        'fsp_vlan_interface_vrrp': {
            'params': [
                'vlan',
                'vrrp',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}'
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
        'pm_devprof_adom': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/devprof/adom/{adom}'
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
        'pm_devprof': {
            'params': [
                'pkg_path',
                'adom'
            ],
            'urls': [
                '/pm/devprof/adom/{adom}/{pkg_path}'
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
        'system_log_interfacestats': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/interface-stats'
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
        'user_krbkeytab': {
            'params': [
                'krb-keytab',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/krb-keytab/{krb-keytab}',
                '/pm/config/adom/{adom}/obj/user/krb-keytab/{krb-keytab}'
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
        'user_domaincontroller': {
            'params': [
                'domain-controller',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/domain-controller/{domain-controller}',
                '/pm/config/adom/{adom}/obj/user/domain-controller/{domain-controller}'
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
        'user_domaincontroller_extraserver': {
            'params': [
                'domain-controller',
                'extra-server',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/domain-controller/{domain-controller}/extra-server/{extra-server}',
                '/pm/config/adom/{adom}/obj/user/domain-controller/{domain-controller}/extra-server/{extra-server}'
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
        'user_exchange': {
            'params': [
                'exchange',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/exchange/{exchange}',
                '/pm/config/adom/{adom}/obj/user/exchange/{exchange}'
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
        'user_clearpass': {
            'params': [
                'clearpass',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/clearpass/{clearpass}',
                '/pm/config/adom/{adom}/obj/user/clearpass/{clearpass}'
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
        'user_nsx': {
            'params': [
                'nsx',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/nsx/{nsx}',
                '/pm/config/adom/{adom}/obj/user/nsx/{nsx}'
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
        'cifs_domaincontroller': {
            'params': [
                'domain-controller',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cifs/domain-controller/{domain-controller}',
                '/pm/config/adom/{adom}/obj/cifs/domain-controller/{domain-controller}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'cifs_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cifs/profile/{profile}',
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True
            }
        },
        'cifs_profile_filefilter': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cifs/profile/{profile}/file-filter',
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/file-filter'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
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
        'cifs_profile_serverkeytab': {
            'params': [
                'profile',
                'server-keytab',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/cifs/profile/{profile}/server-keytab/{server-keytab}',
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/server-keytab/{server-keytab}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True
            }
        },
        'pm_config_metafields_firewall_address': {
            'params': [
            ],
            'urls': [
                '/pm/config/_meta_fields/firewall/address'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pm_config_metafields_firewall_addrgrp': {
            'params': [
            ],
            'urls': [
                '/pm/config/_meta_fields/firewall/addrgrp'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pm_config_metafields_firewall_centralsnatmap': {
            'params': [
            ],
            'urls': [
                '/pm/config/_meta_fields/firewall/central-snat-map'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pm_config_metafields_firewall_policy': {
            'params': [
            ],
            'urls': [
                '/pm/config/_meta_fields/firewall/policy'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pm_config_metafields_firewall_service_custom': {
            'params': [
            ],
            'urls': [
                '/pm/config/_meta_fields/firewall/service/custom'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pm_config_metafields_firewall_service_group': {
            'params': [
            ],
            'urls': [
                '/pm/config/_meta_fields/firewall/service/group'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pm_config_adom_options': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/_adom/options'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pm_config_application_list': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/_application/list',
                '/pm/config/global/_application/list'
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
        'pm_config_category_list': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/_category/list',
                '/pm/config/global/_category/list'
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
        'pm_config_data_tablesize': {
            'params': [
                'tablesize',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/_data/tablesize/{tablesize}',
                '/pm/config/global/_data/tablesize/{tablesize}'
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
        'pm_config_data_tablesize_faz': {
            'params': [
                'faz',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/_data/tablesize/faz/{faz}',
                '/pm/config/global/_data/tablesize/faz/{faz}'
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
        'pm_config_data_tablesize_fmg': {
            'params': [
                'fmg',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/_data/tablesize/fmg/{fmg}',
                '/pm/config/global/_data/tablesize/fmg/{fmg}'
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
        'pm_config_data_tablesize_fos': {
            'params': [
                'fos',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/_data/tablesize/fos/{fos}',
                '/pm/config/global/_data/tablesize/fos/{fos}'
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
        'pm_config_data_tablesize_log': {
            'params': [
                'log',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/_data/tablesize/log/{log}',
                '/pm/config/global/_data/tablesize/log/{log}'
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
        'pm_config_fct_endpointcontrol_profile': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/_fct/endpoint-control/profile'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'pm_config_rule_list': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/_rule/list',
                '/pm/config/global/_rule/list'
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
        'authentication_scheme': {
            'params': [
                'scheme',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/authentication/scheme/{scheme}',
                '/pm/config/adom/{adom}/obj/authentication/scheme/{scheme}'
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
        'dnsfilter_profile_dnstranslation': {
            'params': [
                'profile',
                'dns-translation',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dnsfilter/profile/{profile}/dns-translation/{dns-translation}',
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/dns-translation/{dns-translation}'
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
        'emailfilter_bword': {
            'params': [
                'bword',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/bword/{bword}',
                '/pm/config/adom/{adom}/obj/emailfilter/bword/{bword}'
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
        'emailfilter_bwl': {
            'params': [
                'bwl',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/bwl/{bwl}',
                '/pm/config/adom/{adom}/obj/emailfilter/bwl/{bwl}'
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
        'emailfilter_mheader': {
            'params': [
                'mheader',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/mheader/{mheader}',
                '/pm/config/adom/{adom}/obj/emailfilter/mheader/{mheader}'
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
        'emailfilter_mheader_entries': {
            'params': [
                'mheader',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/mheader/{mheader}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/mheader/{mheader}/entries/{entries}'
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
        'emailfilter_dnsbl': {
            'params': [
                'dnsbl',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/dnsbl/{dnsbl}',
                '/pm/config/adom/{adom}/obj/emailfilter/dnsbl/{dnsbl}'
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
        'emailfilter_dnsbl_entries': {
            'params': [
                'dnsbl',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/dnsbl/{dnsbl}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/dnsbl/{dnsbl}/entries/{entries}'
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
        'emailfilter_iptrust': {
            'params': [
                'iptrust',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/iptrust/{iptrust}',
                '/pm/config/adom/{adom}/obj/emailfilter/iptrust/{iptrust}'
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
        'emailfilter_iptrust_entries': {
            'params': [
                'iptrust',
                'entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/iptrust/{iptrust}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/emailfilter/iptrust/{iptrust}/entries/{entries}'
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
        'emailfilter_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}'
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
        'emailfilter_profile_filefilter': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}/file-filter',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/file-filter'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
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
        'emailfilter_profile_imap': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}/imap',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/imap'
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
        'emailfilter_profile_pop3': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}/pop3',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/pop3'
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
        'emailfilter_profile_smtp': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}/smtp',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/smtp'
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
        'emailfilter_profile_mapi': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}/mapi',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/mapi'
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
        'emailfilter_profile_msnhotmail': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}/msn-hotmail',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/msn-hotmail'
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
        'emailfilter_profile_gmail': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}/gmail',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/gmail'
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
        'emailfilter_fortishield': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/fortishield',
                '/pm/config/adom/{adom}/obj/emailfilter/fortishield'
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
        'emailfilter_options': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/options',
                '/pm/config/adom/{adom}/obj/emailfilter/options'
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
        'switchcontroller_managedswitch_snmpsysinfo': {
            'params': [
                'managed-switch',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-sysinfo',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-sysinfo'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True
            }
        },
        'switchcontroller_managedswitch_snmptrapthreshold': {
            'params': [
                'managed-switch',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-trap-threshold',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-trap-threshold'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True
            }
        },
        'switchcontroller_managedswitch_snmpcommunity': {
            'params': [
                'managed-switch',
                'snmp-community',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True
            }
        },
        'switchcontroller_managedswitch_snmpcommunity_hosts': {
            'params': [
                'managed-switch',
                'snmp-community',
                'hosts',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts/{hosts}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts/{hosts}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True
            }
        },
        'switchcontroller_managedswitch_snmpuser': {
            'params': [
                'managed-switch',
                'snmp-user',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-user/{snmp-user}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-user/{snmp-user}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True
            }
        },
        'switchcontroller_managedswitch_remotelog': {
            'params': [
                'managed-switch',
                'remote-log',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/remote-log/{remote-log}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/remote-log/{remote-log}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True
            }
        },
        'switchcontroller_lldpprofile_medlocationservice': {
            'params': [
                'lldp-profile',
                'med-location-service',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/med-location-service/{med-location-service}',
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/med-location-service/{med-location-service}'
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
        'pkg_authentication_rule': {
            'params': [
                'pkg',
                'rule',
                'adom'
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
        'pkg_authentication_setting': {
            'params': [
                'pkg',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/authentication/setting'
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
        'webfilter_profile_filefilter': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/webfilter/profile/{profile}/file-filter',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/file-filter'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
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
        'devprof_log_fortianalyzercloud_setting': {
            'params': [
                'devprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/fortianalyzer-cloud/setting'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_address6_dynamicmapping_subnetsegment': {
            'params': [
                'address6',
                'dynamic_mapping',
                'subnet-segment',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment/{subnet-segment}',
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment/{subnet-segment}'
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
        'firewall_mmsprofile_outbreakprevention': {
            'params': [
                'mms-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/outbreak-prevention',
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/outbreak-prevention'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True
            }
        },
        'firewall_gtp_policyv2': {
            'params': [
                'gtp',
                'policy-v2',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/gtp/{gtp}/policy-v2/{policy-v2}',
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy-v2/{policy-v2}'
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
        'firewall_profileprotocoloptions_cifs': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs',
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs'
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
        'firewall_ssh_localca': {
            'params': [
                'local-ca',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/ssh/local-ca/{local-ca}',
                '/pm/config/adom/{adom}/obj/firewall/ssh/local-ca/{local-ca}'
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
        'icap_profile_icapheaders': {
            'params': [
                'profile',
                'icap-headers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/icap/profile/{profile}/icap-headers/{icap-headers}',
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/icap-headers/{icap-headers}'
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
        'pkg_firewall_consolidated_policy': {
            'params': [
                'pkg',
                'policy',
                'adom'
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
                'pkg',
                'security-policy',
                'adom'
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
        'antivirus_profile_outbreakprevention': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/antivirus/profile/{profile}/outbreak-prevention',
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/outbreak-prevention'
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
        'antivirus_profile_cifs': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/antivirus/profile/{profile}/cifs',
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/cifs'
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
        'dlp_sensitivity': {
            'params': [
                'sensitivity',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/sensitivity/{sensitivity}',
                '/pm/config/adom/{adom}/obj/dlp/sensitivity/{sensitivity}'
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
        'wanprof_system_virtualwanlink_neighbor': {
            'params': [
                'wanprof',
                'neighbor',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/neighbor/{neighbor}'
            ],
            'revision': {
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'fsp_vlan_interface_ipv6_ip6prefixlist': {
            'params': [
                'vlan',
                'ip6-prefix-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'fsp_vlan_interface_ipv6_ip6extraaddr': {
            'params': [
                'vlan',
                'ip6-extra-addr',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'fsp_vlan_interface_ipv6_ip6delegatedprefixlist': {
            'params': [
                'vlan',
                'ip6-delegated-prefix-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'fsp_vlan_interface_ipv6_vrrp6': {
            'params': [
                'vlan',
                'vrrp6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/vrrp6/{vrrp6}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/vrrp6/{vrrp6}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'fsp_vlan_dynamicmapping_interface_secondaryip': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'secondaryip',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip/{secondaryip}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip/{secondaryip}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'fsp_vlan_dynamicmapping_interface_ipv6': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6prefixlist': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'ip6-prefix-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6extraaddr': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'ip6-extra-addr',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'ip6-delegated-prefix-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_vrrp6': {
            'params': [
                'vlan',
                'dynamic_mapping',
                'vrrp6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6/{vrrp6}',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6/{vrrp6}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'wtpprofile_radio3': {
            'params': [
                'wtp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-3',
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-3'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'utmprofile': {
            'params': [
                'utm-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/utm-profile/{utm-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/utm-profile/{utm-profile}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'wagprofile': {
            'params': [
                'wag-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/wag-profile/{wag-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/wag-profile/{wag-profile}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_sql_customskipidx': {
            'params': [
                'custom-skipidx'
            ],
            'urls': [
                '/cli/global/system/sql/custom-skipidx/{custom-skipidx}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'dynamic_virtualwanlink_neighbor': {
            'params': [
                'neighbor',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dynamic/virtual-wan-link/neighbor/{neighbor}',
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/neighbor/{neighbor}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'dynamic_virtualwanlink_neighbor_dynamicmapping': {
            'params': [
                'neighbor',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dynamic/virtual-wan-link/neighbor/{neighbor}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/neighbor/{neighbor}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'dynamic_input_interface': {
            'params': [
                'interface',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dynamic/input/interface/{interface}',
                '/pm/config/adom/{adom}/obj/dynamic/input/interface/{interface}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'dynamic_input_interface_dynamicmapping': {
            'params': [
                'interface',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dynamic/input/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/adom/{adom}/obj/dynamic/input/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
            }
        },
        'fmupdate_fwmsetting': {
            'params': [
            ],
            'urls': [
                '/cli/global/fmupdate/fwm-setting'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_sniffer': {
            'params': [
                'sniffer'
            ],
            'urls': [
                '/cli/global/system/sniffer/{sniffer}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_profileprotocoloptions_ssh': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/ssh',
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/ssh'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_internetserviceaddition': {
            'params': [
                'internet-service-addition',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_internetserviceaddition_entry': {
            'params': [
                'internet-service-addition',
                'entry',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_internetserviceaddition_entry_portrange': {
            'params': [
                'internet-service-addition',
                'entry',
                'port-range',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}/port-range/{port-range}',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}/port-range/{port-range}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_trafficclass': {
            'params': [
                'traffic-class',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/traffic-class/{traffic-class}',
                '/pm/config/adom/{adom}/obj/firewall/traffic-class/{traffic-class}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'sshfilter_profile_filefilter': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/ssh-filter/profile/{profile}/file-filter',
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/file-filter'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True
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
        'system_mcpolicydisabledadoms': {
            'params': [
                'mc-policy-disabled-adoms'
            ],
            'urls': [
                '/cli/global/system/global/mc-policy-disabled-adoms/{mc-policy-disabled-adoms}'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'antivirus_profile_ssh': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/antivirus/profile/{profile}/ssh',
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/ssh'
            ],
            'revision': {
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'wtpprofile_radio4': {
            'params': [
                'wtp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-4',
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-4'
            ],
            'revision': {
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_docker': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/docker'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_geoipoverride_ip6range': {
            'params': [
                'geoip-override',
                'ip6-range',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/geoip-override/{geoip-override}/ip6-range/{ip6-range}',
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}/ip6-range/{ip6-range}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'application_list_entries_parameters_members': {
            'params': [
                'list',
                'entries',
                'parameters',
                'members',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters/{parameters}/members/{members}',
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters/{parameters}/members/{members}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'switchcontroller_managedswitch_ipsourceguard': {
            'params': [
                'managed-switch',
                'ip-source-guard',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}'
            ],
            'revision': {
                '6.4.0': True
            }
        },
        'switchcontroller_managedswitch_ipsourceguard_bindingentry': {
            'params': [
                'managed-switch',
                'ip-source-guard',
                'binding-entry',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry/{binding-entry}',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry/{binding-entry}'
            ],
            'revision': {
                '6.4.0': True
            }
        },
        'icap_profile_respmodforwardrules': {
            'params': [
                'profile',
                'respmod-forward-rules',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}',
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'icap_profile_respmodforwardrules_headergroup': {
            'params': [
                'profile',
                'respmod-forward-rules',
                'header-group',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}/header-group/{header-group}',
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}/header-group/{header-group}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'credentialstore_domaincontroller': {
            'params': [
                'domain-controller',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/credential-store/domain-controller/{domain-controller}',
                '/pm/config/adom/{adom}/obj/credential-store/domain-controller/{domain-controller}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True
            }
        },
        'system_saml_fabricidp': {
            'params': [
                'fabric-idp'
            ],
            'urls': [
                '/cli/global/system/saml/fabric-idp/{fabric-idp}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'webfilter_profile_antiphish': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'webfilter_profile_antiphish_inspectionentries': {
            'params': [
                'profile',
                'inspection-entries',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish/inspection-entries/{inspection-entries}',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish/inspection-entries/{inspection-entries}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'webfilter_profile_antiphish_custompatterns': {
            'params': [
                'profile',
                'custom-patterns',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish/custom-patterns/{custom-patterns}',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish/custom-patterns/{custom-patterns}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_internetservicename': {
            'params': [
                'internet-service-name',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/internet-service-name/{internet-service-name}',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-name/{internet-service-name}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'task_task_line_history': {
            'params': [
                'task',
                'line',
                'history'
            ],
            'urls': [
                '/task/task/{task}/line/{line}/history/{history}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'user_saml': {
            'params': [
                'saml',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/saml/{saml}',
                '/pm/config/adom/{adom}/obj/user/saml/{saml}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'user_vcenter': {
            'params': [
                'vcenter',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/vcenter/{vcenter}',
                '/pm/config/adom/{adom}/obj/user/vcenter/{vcenter}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'user_vcenter_rule': {
            'params': [
                'vcenter',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/vcenter/{vcenter}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/user/vcenter/{vcenter}/rule/{rule}'
            ],
            'revision': {
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'dvmdb_folder': {
            'params': [
                'folder',
                'adom'
            ],
            'urls': [
                '/dvmdb/folder/{folder}',
                '/dvmdb/adom/{adom}/folder/{folder}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'user_radius_dynamicmapping_accountingserver': {
            'params': [
                'radius',
                'dynamic_mapping',
                'accounting-server',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server/{accounting-server}',
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server/{accounting-server}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'filefilter_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/file-filter/profile/{profile}',
                '/pm/config/adom/{adom}/obj/file-filter/profile/{profile}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
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
        'mpskprofile': {
            'params': [
                'mpsk-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}'
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
        'firewall_profileprotocoloptions_cifs_filefilter': {
            'params': [
                'profile-protocol-options',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter',
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True
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
        'firewall_profileprotocoloptions_cifs_serverkeytab': {
            'params': [
                'profile-protocol-options',
                'server-keytab',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/server-keytab/{server-keytab}',
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/server-keytab/{server-keytab}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_decryptedtrafficmirror': {
            'params': [
                'decrypted-traffic-mirror',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/decrypted-traffic-mirror/{decrypted-traffic-mirror}',
                '/pm/config/adom/{adom}/obj/firewall/decrypted-traffic-mirror/{decrypted-traffic-mirror}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'vpn_ssl_settings': {
            'params': [
                'device',
                'vdom'
            ],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings'
            ],
            'revision': {
                '6.4.2': True
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
        'dynamic_interface_platformmapping': {
            'params': [
                'interface',
                'platform_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dynamic/interface/{interface}/platform_mapping/{platform_mapping}',
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/platform_mapping/{platform_mapping}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'emailfilter_profile_otherwebmails': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/profile/{profile}/other-webmails',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/other-webmails'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True
            }
        },
        'wanprof_system_sdwan': {
            'params': [
                'wanprof',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'wanprof_system_sdwan_duplication': {
            'params': [
                'wanprof',
                'duplication',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/duplication/{duplication}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'wanprof_system_sdwan_healthcheck': {
            'params': [
                'wanprof',
                'health-check',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check/{health-check}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'wanprof_system_sdwan_healthcheck_sla': {
            'params': [
                'wanprof',
                'health-check',
                'sla',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check/{health-check}/sla/{sla}'
            ],
            'revision': {
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'wanprof_system_sdwan_members': {
            'params': [
                'wanprof',
                'members',
                'adom'
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
        'wanprof_system_sdwan_neighbor': {
            'params': [
                'wanprof',
                'neighbor',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/neighbor/{neighbor}'
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
                'wanprof',
                'service',
                'adom'
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
                'wanprof',
                'service',
                'sla',
                'adom'
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
                'wanprof',
                'zone',
                'adom'
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
                'pkg',
                'dnat6',
                'adom'
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
        'extendercontroller_simprofile': {
            'params': [
                'sim_profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/sim_profile/{sim_profile}',
                '/pm/config/adom/{adom}/obj/extender-controller/sim_profile/{sim_profile}'
            ],
            'revision': {
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'extendercontroller_simprofile_autoswitchprofile': {
            'params': [
                'sim_profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/sim_profile/{sim_profile}/auto-switch_profile',
                '/pm/config/adom/{adom}/obj/extender-controller/sim_profile/{sim_profile}/auto-switch_profile'
            ],
            'revision': {
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'extendercontroller_dataplan': {
            'params': [
                'dataplan',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/dataplan/{dataplan}',
                '/pm/config/adom/{adom}/obj/extender-controller/dataplan/{dataplan}'
            ],
            'revision': {
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_log_devicedisable': {
            'params': [
                'device-disable'
            ],
            'urls': [
                '/cli/global/system/log/device-disable/{device-disable}'
            ],
            'revision': {
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_log_ratelimit': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/ratelimit'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_log_ratelimit_device': {
            'params': [
                'device'
            ],
            'urls': [
                '/cli/global/system/log/ratelimit/device/{device}'
            ],
            'revision': {
                '7.0.0': True
            }
        },
        'firewall_sslsshprofile_dot': {
            'params': [
                'ssl-ssh-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/dot',
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/dot'
            ],
            'revision': {
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
        'firewall_accessproxy_apigateway': {
            'params': [
                'access-proxy',
                'api-gateway',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_accessproxy_apigateway_realservers': {
            'params': [
                'access-proxy',
                'api-gateway',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/realservers/{realservers}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_accessproxy_apigateway_sslciphersuites': {
            'params': [
                'access-proxy',
                'api-gateway',
                'ssl-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'firewall_accessproxy_serverpubkeyauthsettings': {
            'params': [
                'access-proxy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings'
            ],
            'revision': {
                '7.0.0': True
            }
        },
        'firewall_accessproxy_serverpubkeyauthsettings_certextension': {
            'params': [
                'access-proxy',
                'cert-extension',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings/cert-extension/{cert-extension}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings/cert-extension/{cert-extension}'
            ],
            'revision': {
                '7.0.0': True
            }
        },
        'firewall_accessproxy_realservers': {
            'params': [
                'access-proxy',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/realservers/{realservers}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/realservers/{realservers}'
            ],
            'revision': {
                '7.0.0': True
            }
        },
        'emailfilter_blockallowlist': {
            'params': [
                'block-allow-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/emailfilter/block-allow-list/{block-allow-list}',
                '/pm/config/adom/{adom}/obj/emailfilter/block-allow-list/{block-allow-list}'
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
        'region': {
            'params': [
                'region',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/region/{region}',
                '/pm/config/adom/{adom}/obj/wireless-controller/region/{region}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'apcfgprofile': {
            'params': [
                'apcfg-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/apcfg-profile/{apcfg-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile/{apcfg-profile}'
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
        'extendercontroller_template': {
            'params': [
                'template',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/template/{template}',
                '/pm/config/adom/{adom}/obj/extender-controller/template/{template}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_socfabric': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/soc-fabric'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'switchcontroller_customcommand': {
            'params': [
                'custom-command',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/custom-command/{custom-command}',
                '/pm/config/adom/{adom}/obj/switch-controller/custom-command/{custom-command}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'system_replacemsggroup_automation': {
            'params': [
                'replacemsg-group',
                'automation',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/automation/{automation}',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/automation/{automation}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'videofilter_youtubechannelfilter': {
            'params': [
                'youtube-channel-filter',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}',
                '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}'
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
        'videofilter_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/videofilter/profile/{profile}',
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}'
            ],
            'revision': {
                '7.0.0': True,
                '7.2.0': True
            }
        },
        'videofilter_profile_fortiguardcategory': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/videofilter/profile/{profile}/fortiguard-category',
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/fortiguard-category'
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
        'fmg_variable': {
            'params': [
                'variable',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fmg/variable/{variable}',
                '/pm/config/adom/{adom}/obj/fmg/variable/{variable}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'fmg_variable_dynamicmapping': {
            'params': [
                'variable',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fmg/variable/{variable}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/adom/{adom}/obj/fmg/variable/{variable}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'fmg_device_blueprint': {
            'params': [
                'blueprint',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/fmg/device/blueprint/{blueprint}',
                '/pm/config/adom/{adom}/obj/fmg/device/blueprint/{blueprint}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'user_group_dynamicmapping': {
            'params': [
                'group',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'user_group_dynamicmapping_sslvpnoschecklist': {
            'params': [
                'group',
                'dynamic_mapping',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/sslvpn-os-check-list',
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/sslvpn-os-check-list'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'user_group_dynamicmapping_match': {
            'params': [
                'group',
                'dynamic_mapping',
                'match',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/match/{match}',
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/match/{match}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'user_group_dynamicmapping_guest': {
            'params': [
                'group',
                'dynamic_mapping',
                'guest',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest/{guest}',
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest/{guest}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'user_connector': {
            'params': [
                'connector',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/connector/{connector}',
                '/pm/config/adom/{adom}/obj/user/connector/{connector}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'user_nsx_service': {
            'params': [
                'nsx',
                'service',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/user/nsx/{nsx}/service/{service}',
                '/pm/config/adom/{adom}/obj/user/nsx/{nsx}/service/{service}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_sslciphersuites': {
            'params': [
                'ssl-cipher-suites'
            ],
            'urls': [
                '/cli/global/system/global/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'pm_config_pblock_firewall_policy': {
            'params': [
                'pblock',
                'policy',
                'adom'
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
                'pkg',
                'acl',
                'adom'
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
                'pkg',
                'acl6',
                'adom'
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
                'pblock',
                'security-policy',
                'adom'
            ],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/security-policy/{security-policy}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_log_fospolicystats': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/fos-policy-stats'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_log_ratelimit_ratelimits': {
            'params': [
                'ratelimits'
            ],
            'urls': [
                '/cli/global/system/log/ratelimit/ratelimits/{ratelimits}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_log_topology': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/log/topology'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_ha_monitoredinterfaces': {
            'params': [
                'monitored-interfaces'
            ],
            'urls': [
                '/cli/global/system/ha/monitored-interfaces/{monitored-interfaces}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_ha_monitoredips': {
            'params': [
                'monitored-ips'
            ],
            'urls': [
                '/cli/global/system/ha/monitored-ips/{monitored-ips}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'firewall_vip6_dynamicmapping_realservers': {
            'params': [
                'vip6',
                'dynamic_mapping',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}',
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'firewall_vip6_dynamicmapping_sslciphersuites': {
            'params': [
                'vip6',
                'dynamic_mapping',
                'ssl-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}'
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
        'firewall_accessproxy_apigateway6': {
            'params': [
                'access-proxy',
                'api-gateway6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'firewall_accessproxy_apigateway6_realservers': {
            'params': [
                'access-proxy',
                'api-gateway6',
                'realservers',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'firewall_accessproxy_apigateway6_sslciphersuites': {
            'params': [
                'access-proxy',
                'api-gateway6',
                'ssl-cipher-suites',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}'
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
        'system_interface_member': {
            'params': [
                'interface',
                'member'
            ],
            'urls': [
                '/cli/global/system/interface/{interface}/member/{member}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'vpn_ipsec_fec': {
            'params': [
                'fec',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/vpn/ipsec/fec/{fec}',
                '/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{fec}'
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
        'voip_profile_msrp': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/voip/profile/{profile}/msrp',
                '/pm/config/adom/{adom}/obj/voip/profile/{profile}/msrp'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_localinpolicy6': {
            'params': [
                'local-in-policy6'
            ],
            'urls': [
                '/cli/global/system/local-in-policy6/{local-in-policy6}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_hascheduledcheck': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/ha-scheduled-check'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'extendercontroller_extenderprofile': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'extendercontroller_extenderprofile_cellular': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'extendercontroller_extenderprofile_cellular_controllerreport': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/controller-report',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/controller-report'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'extendercontroller_extenderprofile_cellular_smsnotification': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'extendercontroller_extenderprofile_cellular_smsnotification_alert': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/alert',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/alert'
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
        'extendercontroller_extenderprofile_cellular_modem1': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem1',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem1'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'extendercontroller_extenderprofile_cellular_modem1_autoswitch': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem1/auto-switch',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem1/auto-switch'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'extendercontroller_extenderprofile_cellular_modem2': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem2',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem2'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'extendercontroller_extenderprofile_cellular_modem2_autoswitch': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem2/auto-switch',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem2/auto-switch'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'extendercontroller_extenderprofile_lanextension': {
            'params': [
                'extender-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/lan-extension',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/lan-extension'
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
        'wtpprofile_eslsesdongle': {
            'params': [
                'wtp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/esl-ses-dongle',
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/esl-ses-dongle'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'hotspot20_icon': {
            'params': [
                'icon',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/icon/{icon}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/icon/{icon}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'hotspot20_icon_iconlist': {
            'params': [
                'icon',
                'icon-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/icon/{icon}/icon-list/{icon-list}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/icon/{icon}/icon-list/{icon-list}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'arrpprofile': {
            'params': [
                'arrp-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/arrp-profile/{arrp-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/arrp-profile/{arrp-profile}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'nacprofile': {
            'params': [
                'nac-profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/nac-profile/{nac-profile}',
                '/pm/config/adom/{adom}/obj/wireless-controller/nac-profile/{nac-profile}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'hotspot20_anqpvenueurl': {
            'params': [
                'anqp-venue-url',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'hotspot20_anqpvenueurl_valuelist': {
            'params': [
                'anqp-venue-url',
                'value-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list/{value-list}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list/{value-list}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'hotspot20_h2qpadviceofcharge': {
            'params': [
                'h2qp-advice-of-charge',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'hotspot20_h2qpadviceofcharge_aoclist': {
            'params': [
                'h2qp-advice-of-charge',
                'aoc-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'hotspot20_h2qpadviceofcharge_aoclist_planinfo': {
            'params': [
                'h2qp-advice-of-charge',
                'aoc-list',
                'plan-info',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info/{plan-info}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info/{plan-info}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'hotspot20_h2qposuprovidernai': {
            'params': [
                'h2qp-osu-provider-nai',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'hotspot20_h2qposuprovidernai_nailist': {
            'params': [
                'h2qp-osu-provider-nai',
                'nai-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list/{nai-list}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list/{nai-list}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'hotspot20_h2qptermsandconditions': {
            'params': [
                'h2qp-terms-and-conditions',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-terms-and-conditions/{h2qp-terms-and-conditions}',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-terms-and-conditions/{h2qp-terms-and-conditions}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_localinpolicy': {
            'params': [
                'local-in-policy'
            ],
            'urls': [
                '/cli/global/system/local-in-policy/{local-in-policy}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'switchcontroller_dsl_policy': {
            'params': [
                'policy',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/switch-controller/dsl/policy/{policy}',
                '/pm/config/adom/{adom}/obj/switch-controller/dsl/policy/{policy}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_npu': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu',
                '/pm/config/adom/{adom}/obj/system/npu'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_npu_portnpumap': {
            'params': [
                'port-npu-map',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/port-npu-map/{port-npu-map}',
                '/pm/config/adom/{adom}/obj/system/npu/port-npu-map/{port-npu-map}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_npu_portcpumap': {
            'params': [
                'port-cpu-map',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/port-cpu-map/{port-cpu-map}',
                '/pm/config/adom/{adom}/obj/system/npu/port-cpu-map/{port-cpu-map}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_npu_isfnpqueues': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/isf-np-queues',
                '/pm/config/adom/{adom}/obj/system/npu/isf-np-queues'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_npu_fpanomaly': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/fp-anomaly',
                '/pm/config/adom/{adom}/obj/system/npu/fp-anomaly'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_npu_priorityprotocol': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/priority-protocol',
                '/pm/config/adom/{adom}/obj/system/npu/priority-protocol'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'system_npu_swehhash': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/system/npu/sw-eh-hash',
                '/pm/config/adom/{adom}/obj/system/npu/sw-eh-hash'
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
        'system_webproxy': {
            'params': [
            ],
            'urls': [
                '/cli/global/system/web-proxy'
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
        'dlp_datatype': {
            'params': [
                'data-type',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/data-type/{data-type}',
                '/pm/config/adom/{adom}/obj/dlp/data-type/{data-type}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'dlp_dictionary': {
            'params': [
                'dictionary',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/dictionary/{dictionary}',
                '/pm/config/adom/{adom}/obj/dlp/dictionary/{dictionary}'
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
        'dlp_profile': {
            'params': [
                'profile',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/dlp/profile/{profile}',
                '/pm/config/adom/{adom}/obj/dlp/profile/{profile}'
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
        },
        'pm_pblock_adom': {
            'params': [
                'adom'
            ],
            'urls': [
                '/pm/pblock/adom/{adom}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'pm_pblock': {
            'params': [
                'pkg_path',
                'adom'
            ],
            'urls': [
                '/pm/pblock/adom/{adom}/{pkg_path}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_accesslist': {
            'params': [
                'access-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/access-list/{access-list}',
                '/pm/config/adom/{adom}/obj/router/access-list/{access-list}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_accesslist_rule': {
            'params': [
                'access-list',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/access-list/{access-list}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/access-list/{access-list}/rule/{rule}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_aspathlist': {
            'params': [
                'aspath-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/aspath-list/{aspath-list}',
                '/pm/config/adom/{adom}/obj/router/aspath-list/{aspath-list}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_aspathlist_rule': {
            'params': [
                'aspath-list',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/aspath-list/{aspath-list}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/aspath-list/{aspath-list}/rule/{rule}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_prefixlist': {
            'params': [
                'prefix-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/prefix-list/{prefix-list}',
                '/pm/config/adom/{adom}/obj/router/prefix-list/{prefix-list}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_prefixlist_rule': {
            'params': [
                'prefix-list',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/prefix-list/{prefix-list}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/prefix-list/{prefix-list}/rule/{rule}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_communitylist': {
            'params': [
                'community-list',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/community-list/{community-list}',
                '/pm/config/adom/{adom}/obj/router/community-list/{community-list}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_communitylist_rule': {
            'params': [
                'community-list',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/community-list/{community-list}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/community-list/{community-list}/rule/{rule}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_routemap': {
            'params': [
                'route-map',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/route-map/{route-map}',
                '/pm/config/adom/{adom}/obj/router/route-map/{route-map}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_routemap_rule': {
            'params': [
                'route-map',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/route-map/{route-map}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/route-map/{route-map}/rule/{rule}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_accesslist6': {
            'params': [
                'access-list6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/access-list6/{access-list6}',
                '/pm/config/adom/{adom}/obj/router/access-list6/{access-list6}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_accesslist6_rule': {
            'params': [
                'access-list6',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/access-list6/{access-list6}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/access-list6/{access-list6}/rule/{rule}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_prefixlist6': {
            'params': [
                'prefix-list6',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/prefix-list6/{prefix-list6}',
                '/pm/config/adom/{adom}/obj/router/prefix-list6/{prefix-list6}'
            ],
            'revision': {
                '7.2.0': True
            }
        },
        'router_prefixlist6_rule': {
            'params': [
                'prefix-list6',
                'rule',
                'adom'
            ],
            'urls': [
                '/pm/config/global/obj/router/prefix-list6/{prefix-list6}/rule/{rule}',
                '/pm/config/adom/{adom}/obj/router/prefix-list6/{prefix-list6}/rule/{rule}'
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
        'export_playbooks': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'list',
                    'choices': [
                        'all',
                        'fmupdate_fctservices',
                        'footer_consolidated_policy',
                        'footer_policy',
                        'footer_policy_identitybasedpolicy',
                        'footer_policy6',
                        'footer_policy6_identitybasedpolicy6',
                        'footer_shapingpolicy',
                        'header_consolidated_policy',
                        'header_policy',
                        'header_policy_identitybasedpolicy',
                        'header_policy6',
                        'header_policy6_identitybasedpolicy6',
                        'header_shapingpolicy',
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
                        'vpnmgr_node',
                        'vpnmgr_node_iprange',
                        'vpnmgr_node_ipv4excluderange',
                        'vpnmgr_node_protectedsubnet',
                        'vpnmgr_node_summaryaddr',
                        'vpnmgr_vpntable',
                        'dvmdb_revision',
                        'system_ntp',
                        'system_ntp_ntpserver',
                        'user_adgrp',
                        'user_device',
                        'user_devicecategory',
                        'user_devicegroup',
                        'user_devicegroup_dynamicmapping',
                        'user_devicegroup_tagging',
                        'user_device_dynamicmapping',
                        'user_device_tagging',
                        'user_fortitoken',
                        'user_fsso',
                        'user_fssopolling',
                        'user_fssopolling_adgrp',
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
                        'system_syslog',
                        'fmupdate_avips_advancedlog',
                        'fmupdate_avips_webproxy',
                        'log_customfield',
                        'fmupdate_serveraccesspriorities',
                        'fmupdate_serveraccesspriorities_privateserver',
                        'system_saml',
                        'system_saml_serviceproviders',
                        'devprof_log_fortianalyzer_setting',
                        'devprof_log_syslogd_filter',
                        'devprof_log_syslogd_setting',
                        'devprof_device_profile_fortianalyzer',
                        'devprof_device_profile_fortiguard',
                        'ips_custom',
                        'ips_sensor',
                        'ips_sensor_entries',
                        'ips_sensor_entries_exemptip',
                        'ips_sensor_filter',
                        'ips_sensor_override',
                        'ips_sensor_override_exemptip',
                        'fmupdate_publicnetwork',
                        'template',
                        'templategroup',
                        'system_global',
                        'antivirus_mmschecksum',
                        'antivirus_mmschecksum_entries',
                        'antivirus_notification',
                        'antivirus_notification_entries',
                        'antivirus_profile',
                        'antivirus_profile_contentdisarm',
                        'antivirus_profile_ftp',
                        'antivirus_profile_http',
                        'antivirus_profile_imap',
                        'antivirus_profile_mapi',
                        'antivirus_profile_nacquar',
                        'antivirus_profile_nntp',
                        'antivirus_profile_pop3',
                        'antivirus_profile_smb',
                        'antivirus_profile_smtp',
                        'application_categories',
                        'application_custom',
                        'application_group',
                        'application_list',
                        'application_list_entries',
                        'application_list_entries_parameters',
                        'waf_mainclass',
                        'waf_profile',
                        'waf_profile_addresslist',
                        'waf_profile_constraint',
                        'waf_profile_constraint_contentlength',
                        'waf_profile_constraint_exception',
                        'waf_profile_constraint_headerlength',
                        'waf_profile_constraint_hostname',
                        'waf_profile_constraint_linelength',
                        'waf_profile_constraint_malformed',
                        'waf_profile_constraint_maxcookie',
                        'waf_profile_constraint_maxheaderline',
                        'waf_profile_constraint_maxrangesegment',
                        'waf_profile_constraint_maxurlparam',
                        'waf_profile_constraint_method',
                        'waf_profile_constraint_paramlength',
                        'waf_profile_constraint_urlparamlength',
                        'waf_profile_constraint_version',
                        'waf_profile_method',
                        'waf_profile_method_methodpolicy',
                        'waf_profile_signature',
                        'waf_profile_signature_customsignature',
                        'waf_profile_signature_mainclass',
                        'waf_profile_urlaccess',
                        'waf_profile_urlaccess_accesspattern',
                        'waf_signature',
                        'waf_subclass',
                        'system_status',
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
                        'spamfilter_profile_gmail',
                        'spamfilter_profile_imap',
                        'spamfilter_profile_mapi',
                        'spamfilter_profile_msnhotmail',
                        'spamfilter_profile_pop3',
                        'spamfilter_profile_smtp',
                        'spamfilter_profile_yahoomail',
                        'fmupdate_fdssetting',
                        'fmupdate_fdssetting_pushoverride',
                        'fmupdate_fdssetting_pushoverridetoclient',
                        'fmupdate_fdssetting_pushoverridetoclient_announceip',
                        'fmupdate_fdssetting_serveroverride',
                        'fmupdate_fdssetting_serveroverride_servlist',
                        'fmupdate_fdssetting_updateschedule',
                        'system_dns',
                        'dvmdb_device',
                        'dvmdb_device_haslave',
                        'dvmdb_device_vdom',
                        'system_mail',
                        'system_alertemail',
                        'fmupdate_service',
                        'system_logfetch_clientprofile',
                        'system_logfetch_clientprofile_devicefilter',
                        'system_logfetch_clientprofile_logfilter',
                        'system_logfetch_serversettings',
                        'system_customlanguage',
                        'system_dhcp_server',
                        'system_dhcp_server_excluderange',
                        'system_dhcp_server_iprange',
                        'system_dhcp_server_options',
                        'system_dhcp_server_reservedaddress',
                        'system_externalresource',
                        'system_fortiguard',
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
                        'system_sdnconnector_route',
                        'system_sdnconnector_routetable',
                        'system_sdnconnector_routetable_route',
                        'system_smsserver',
                        'system_virtualwirepair',
                        'sys_ha_status',
                        'fmupdate_webspam_fgdsetting',
                        'fmupdate_webspam_fgdsetting_serveroverride',
                        'fmupdate_webspam_fgdsetting_serveroverride_servlist',
                        'fmupdate_webspam_webproxy',
                        'dvmdb_workflow',
                        'dvmdb_workflow_wflog',
                        'system_autodelete',
                        'system_autodelete_dlpfilesautodeletion',
                        'system_autodelete_logautodeletion',
                        'system_autodelete_quarantinefilesautodeletion',
                        'system_autodelete_reportautodeletion',
                        'sshfilter_profile',
                        'sshfilter_profile_shellcommands',
                        'system_alertevent',
                        'system_alertevent_alertdestination',
                        'system_interface',
                        'system_interface_ipv6',
                        'system_locallog_disk_filter',
                        'system_locallog_disk_setting',
                        'system_locallog_fortianalyzer_filter',
                        'system_locallog_fortianalyzer_setting',
                        'system_locallog_fortianalyzer2_filter',
                        'system_locallog_fortianalyzer2_setting',
                        'system_locallog_fortianalyzer3_filter',
                        'system_locallog_fortianalyzer3_setting',
                        'system_locallog_memory_filter',
                        'system_locallog_memory_setting',
                        'system_locallog_setting',
                        'system_locallog_syslogd_filter',
                        'system_locallog_syslogd_setting',
                        'system_locallog_syslogd2_filter',
                        'system_locallog_syslogd2_setting',
                        'system_locallog_syslogd3_filter',
                        'system_locallog_syslogd3_setting',
                        'system_workflow_approvalmatrix',
                        'system_workflow_approvalmatrix_approver',
                        'system_report_autocache',
                        'system_report_estbrowsetime',
                        'system_report_group',
                        'system_report_group_chartalternative',
                        'system_report_group_groupby',
                        'system_report_setting',
                        'system_passwordpolicy',
                        'certificate_template',
                        'system_backup_allsettings',
                        'dvmdb_adom',
                        'system_snmp_community',
                        'system_snmp_community_hosts',
                        'system_snmp_community_hosts6',
                        'system_snmp_sysinfo',
                        'system_snmp_user',
                        'system_performance',
                        'system_route6',
                        'voip_profile',
                        'voip_profile_sccp',
                        'voip_profile_sip',
                        'metafields_system_admin_user',
                        'fmupdate_analyzer_virusreport',
                        'webfilter_categories',
                        'webfilter_content',
                        'webfilter_contentheader',
                        'webfilter_contentheader_entries',
                        'webfilter_content_entries',
                        'webfilter_ftgdlocalcat',
                        'webfilter_ftgdlocalrating',
                        'webfilter_profile',
                        'webfilter_profile_ftgdwf',
                        'webfilter_profile_ftgdwf_filters',
                        'webfilter_profile_ftgdwf_quota',
                        'webfilter_profile_override',
                        'webfilter_profile_urlextraction',
                        'webfilter_profile_web',
                        'webfilter_profile_youtubechannelfilter',
                        'webfilter_urlfilter',
                        'webfilter_urlfilter_entries',
                        'system_alertconsole',
                        'firewall_address',
                        'firewall_address_dynamicmapping',
                        'firewall_address_list',
                        'firewall_address_tagging',
                        'firewall_address6',
                        'firewall_address6template',
                        'firewall_address6template_subnetsegment',
                        'firewall_address6template_subnetsegment_values',
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
                        'firewall_gtp_ievalidation',
                        'firewall_gtp_imsi',
                        'firewall_gtp_ippolicy',
                        'firewall_gtp_messageratelimit',
                        'firewall_gtp_messageratelimitv0',
                        'firewall_gtp_messageratelimitv1',
                        'firewall_gtp_messageratelimitv2',
                        'firewall_gtp_noippolicy',
                        'firewall_gtp_perapnshaper',
                        'firewall_gtp_policy',
                        'firewall_identitybasedroute',
                        'firewall_identitybasedroute_rule',
                        'firewall_internetservice',
                        'firewall_internetservicecustom',
                        'firewall_internetservicecustomgroup',
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
                        'firewall_mmsprofile_dupe',
                        'firewall_mmsprofile_flood',
                        'firewall_mmsprofile_notifmsisdn',
                        'firewall_mmsprofile_notification',
                        'firewall_multicastaddress',
                        'firewall_multicastaddress_tagging',
                        'firewall_multicastaddress6',
                        'firewall_multicastaddress6_tagging',
                        'firewall_profilegroup',
                        'firewall_profileprotocoloptions',
                        'firewall_profileprotocoloptions_dns',
                        'firewall_profileprotocoloptions_ftp',
                        'firewall_profileprotocoloptions_http',
                        'firewall_profileprotocoloptions_imap',
                        'firewall_profileprotocoloptions_mailsignature',
                        'firewall_profileprotocoloptions_mapi',
                        'firewall_profileprotocoloptions_nntp',
                        'firewall_profileprotocoloptions_pop3',
                        'firewall_profileprotocoloptions_smtp',
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
                        'firewall_sslsshprofile_ftps',
                        'firewall_sslsshprofile_https',
                        'firewall_sslsshprofile_imaps',
                        'firewall_sslsshprofile_pop3s',
                        'firewall_sslsshprofile_smtps',
                        'firewall_sslsshprofile_ssh',
                        'firewall_sslsshprofile_ssl',
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
                        'webproxy_forwardserver',
                        'webproxy_forwardservergroup',
                        'webproxy_forwardservergroup_serverlist',
                        'webproxy_profile',
                        'webproxy_profile_headers',
                        'webproxy_wisp',
                        'system_route',
                        'dvmdb_script',
                        'dvmdb_script_scriptschedule',
                        'dvmdb_script_log_latest',
                        'dvmdb_script_log_latest_device',
                        'dvmdb_script_log_list',
                        'dvmdb_script_log_list_device',
                        'dvmdb_script_log_output_device_logid',
                        'dvmdb_script_log_output_logid',
                        'dvmdb_script_log_summary',
                        'dvmdb_script_log_summary_device',
                        'system_fortiview_autocache',
                        'system_fortiview_setting',
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
                        'vpnsslweb_portal_oschecklist',
                        'vpnsslweb_portal_splitdns',
                        'vpnsslweb_realm',
                        'fmupdate_serveroverridestatus',
                        'pkg_central_dnat',
                        'wanprof_system_virtualwanlink',
                        'wanprof_system_virtualwanlink_healthcheck',
                        'wanprof_system_virtualwanlink_healthcheck_sla',
                        'wanprof_system_virtualwanlink_members',
                        'wanprof_system_virtualwanlink_service',
                        'wanprof_system_virtualwanlink_service_sla',
                        'devprof_system_centralmanagement',
                        'devprof_system_centralmanagement_serverlist',
                        'devprof_system_dns',
                        'devprof_system_emailserver',
                        'devprof_system_global',
                        'devprof_system_ntp',
                        'devprof_system_ntp_ntpserver',
                        'devprof_system_replacemsg_admin',
                        'devprof_system_replacemsg_alertmail',
                        'devprof_system_replacemsg_auth',
                        'devprof_system_replacemsg_devicedetectionportal',
                        'devprof_system_replacemsg_ec',
                        'devprof_system_replacemsg_fortiguardwf',
                        'devprof_system_replacemsg_ftp',
                        'devprof_system_replacemsg_http',
                        'devprof_system_replacemsg_mail',
                        'devprof_system_replacemsg_mms',
                        'devprof_system_replacemsg_nacquar',
                        'devprof_system_replacemsg_nntp',
                        'devprof_system_replacemsg_spam',
                        'devprof_system_replacemsg_sslvpn',
                        'devprof_system_replacemsg_trafficquota',
                        'devprof_system_replacemsg_utm',
                        'devprof_system_replacemsg_webproxy',
                        'devprof_system_snmp_community',
                        'devprof_system_snmp_community_hosts',
                        'devprof_system_snmp_community_hosts6',
                        'devprof_system_snmp_sysinfo',
                        'devprof_system_snmp_user',
                        'dvmdb_metafields_adom',
                        'dvmdb_metafields_device',
                        'dvmdb_metafields_group',
                        'gtp_apn',
                        'gtp_apngrp',
                        'gtp_iewhitelist',
                        'gtp_iewhitelist_entries',
                        'gtp_messagefilterv0v1',
                        'gtp_messagefilterv2',
                        'gtp_tunnellimit',
                        'wanopt_authgroup',
                        'wanopt_peer',
                        'wanopt_profile',
                        'wanopt_profile_cifs',
                        'wanopt_profile_ftp',
                        'wanopt_profile_http',
                        'wanopt_profile_mapi',
                        'wanopt_profile_tcp',
                        'system_ha',
                        'system_ha_peer',
                        'system_admin_group',
                        'system_admin_group_member',
                        'system_admin_ldap',
                        'system_admin_ldap_adom',
                        'system_admin_profile',
                        'system_admin_profile_datamaskcustomfields',
                        'system_admin_radius',
                        'system_admin_setting',
                        'system_admin_tacacs',
                        'system_admin_user',
                        'system_admin_user_adom',
                        'system_admin_user_adomexclude',
                        'system_admin_user_appfilter',
                        'system_admin_user_dashboard',
                        'system_admin_user_dashboardtabs',
                        'system_admin_user_ipsfilter',
                        'system_admin_user_metadata',
                        'system_admin_user_policypackage',
                        'system_admin_user_restrictdevvdom',
                        'system_admin_user_webfilter',
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
                        'system_certificate_ca',
                        'system_certificate_crl',
                        'system_certificate_local',
                        'system_certificate_oftp',
                        'system_certificate_remote',
                        'system_certificate_ssh',
                        'system_log_alert',
                        'system_log_ioc',
                        'system_log_maildomain',
                        'system_log_settings',
                        'system_log_settings_rollinganalyzer',
                        'system_log_settings_rollinglocal',
                        'system_log_settings_rollingregular',
                        'system_dm',
                        'adom_options',
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
                        'switchcontroller_managedswitch_8021xsettings',
                        'switchcontroller_managedswitch_customcommand',
                        'switchcontroller_managedswitch_igmpsnooping',
                        'switchcontroller_managedswitch_mirror',
                        'switchcontroller_managedswitch_stormcontrol',
                        'switchcontroller_managedswitch_stpsettings',
                        'switchcontroller_managedswitch_switchlog',
                        'switchcontroller_managedswitch_switchstpsettings',
                        'sys_status',
                        'dvmdb_workspace_dirty',
                        'dvmdb_workspace_dirty_dev',
                        'dvmdb_workspace_lockinfo',
                        'dvmdb_workspace_lockinfo_dev',
                        'dvmdb_workspace_lockinfo_obj',
                        'dvmdb_workspace_lockinfo_pkg',
                        'system_metadata_admins',
                        'system_connector',
                        'task_task',
                        'task_task_history',
                        'task_task_line',
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
                        'fmupdate_multilayer',
                        'fmupdate_diskquota',
                        'system_guiact',
                        'pm_pkg_adom',
                        'pm_pkg',
                        'pm_pkg_global',
                        'system_sql',
                        'system_sql_customindex',
                        'system_sql_tsindexfield',
                        'pm_pkg_schedule',
                        'pm_wanprof_adom',
                        'pm_wanprof',
                        'icap_profile',
                        'icap_server',
                        'fmupdate_customurllist',
                        'dvmdb_group',
                        'dnsfilter_domainfilter',
                        'dnsfilter_domainfilter_entries',
                        'dnsfilter_profile',
                        'dnsfilter_profile_domainfilter',
                        'dnsfilter_profile_ftgddns',
                        'dnsfilter_profile_ftgddns_filters',
                        'system_fips',
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
                        'vap',
                        'vapgroup',
                        'vap_dynamicmapping',
                        'vap_macfilterlist',
                        'vap_mpskkey',
                        'vap_portalmessageoverrides',
                        'vap_vlanpool',
                        'widsprofile',
                        'wtpprofile',
                        'wtpprofile_denymaclist',
                        'wtpprofile_lan',
                        'wtpprofile_lbs',
                        'wtpprofile_platform',
                        'wtpprofile_radio1',
                        'wtpprofile_radio2',
                        'wtpprofile_splittunnelingacl',
                        'dlp_filepattern',
                        'dlp_filepattern_entries',
                        'dlp_fpsensitivity',
                        'dlp_sensor',
                        'dlp_sensor_filter',
                        'fsp_vlan',
                        'fsp_vlan_dhcpserver',
                        'fsp_vlan_dhcpserver_excluderange',
                        'fsp_vlan_dhcpserver_iprange',
                        'fsp_vlan_dhcpserver_options',
                        'fsp_vlan_dhcpserver_reservedaddress',
                        'fsp_vlan_dynamicmapping',
                        'fsp_vlan_dynamicmapping_dhcpserver',
                        'fsp_vlan_dynamicmapping_dhcpserver_excluderange',
                        'fsp_vlan_dynamicmapping_dhcpserver_iprange',
                        'fsp_vlan_dynamicmapping_dhcpserver_options',
                        'fsp_vlan_dynamicmapping_dhcpserver_reservedaddress',
                        'fsp_vlan_dynamicmapping_interface',
                        'fsp_vlan_interface',
                        'fsp_vlan_interface_ipv6',
                        'fsp_vlan_interface_secondaryip',
                        'fsp_vlan_interface_vrrp',
                        'pm_devprof_adom',
                        'pm_devprof',
                        'system_log_interfacestats',
                        'user_krbkeytab',
                        'user_domaincontroller',
                        'user_domaincontroller_extraserver',
                        'user_exchange',
                        'user_clearpass',
                        'user_nsx',
                        'cifs_domaincontroller',
                        'cifs_profile',
                        'cifs_profile_filefilter',
                        'cifs_profile_filefilter_entries',
                        'cifs_profile_serverkeytab',
                        'pm_config_metafields_firewall_address',
                        'pm_config_metafields_firewall_addrgrp',
                        'pm_config_metafields_firewall_centralsnatmap',
                        'pm_config_metafields_firewall_policy',
                        'pm_config_metafields_firewall_service_custom',
                        'pm_config_metafields_firewall_service_group',
                        'pm_config_adom_options',
                        'pm_config_application_list',
                        'pm_config_category_list',
                        'pm_config_data_tablesize',
                        'pm_config_data_tablesize_faz',
                        'pm_config_data_tablesize_fmg',
                        'pm_config_data_tablesize_fos',
                        'pm_config_data_tablesize_log',
                        'pm_config_fct_endpointcontrol_profile',
                        'pm_config_rule_list',
                        'application_list_defaultnetworkservices',
                        'authentication_scheme',
                        'dnsfilter_profile_dnstranslation',
                        'emailfilter_bword',
                        'emailfilter_bword_entries',
                        'emailfilter_bwl',
                        'emailfilter_bwl_entries',
                        'emailfilter_mheader',
                        'emailfilter_mheader_entries',
                        'emailfilter_dnsbl',
                        'emailfilter_dnsbl_entries',
                        'emailfilter_iptrust',
                        'emailfilter_iptrust_entries',
                        'emailfilter_profile',
                        'emailfilter_profile_filefilter',
                        'emailfilter_profile_filefilter_entries',
                        'emailfilter_profile_imap',
                        'emailfilter_profile_pop3',
                        'emailfilter_profile_smtp',
                        'emailfilter_profile_mapi',
                        'emailfilter_profile_msnhotmail',
                        'emailfilter_profile_gmail',
                        'emailfilter_fortishield',
                        'emailfilter_options',
                        'switchcontroller_managedswitch_snmpsysinfo',
                        'switchcontroller_managedswitch_snmptrapthreshold',
                        'switchcontroller_managedswitch_snmpcommunity',
                        'switchcontroller_managedswitch_snmpcommunity_hosts',
                        'switchcontroller_managedswitch_snmpuser',
                        'switchcontroller_managedswitch_remotelog',
                        'switchcontroller_lldpprofile_medlocationservice',
                        'pkg_authentication_rule',
                        'pkg_authentication_setting',
                        'webfilter_profile_filefilter',
                        'webfilter_profile_filefilter_entries',
                        'devprof_log_fortianalyzercloud_setting',
                        'firewall_address6_dynamicmapping_subnetsegment',
                        'firewall_mmsprofile_outbreakprevention',
                        'firewall_gtp_policyv2',
                        'firewall_profileprotocoloptions_cifs',
                        'firewall_ssh_localca',
                        'icap_profile_icapheaders',
                        'pkg_firewall_consolidated_policy',
                        'pkg_firewall_securitypolicy',
                        'antivirus_profile_outbreakprevention',
                        'antivirus_profile_cifs',
                        'dlp_sensitivity',
                        'wanprof_system_virtualwanlink_neighbor',
                        'fsp_vlan_interface_ipv6_ip6prefixlist',
                        'fsp_vlan_interface_ipv6_ip6extraaddr',
                        'fsp_vlan_interface_ipv6_ip6delegatedprefixlist',
                        'fsp_vlan_interface_ipv6_vrrp6',
                        'fsp_vlan_dynamicmapping_interface_secondaryip',
                        'fsp_vlan_dynamicmapping_interface_ipv6',
                        'fsp_vlan_dynamicmapping_interface_ipv6_ip6prefixlist',
                        'fsp_vlan_dynamicmapping_interface_ipv6_ip6extraaddr',
                        'fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist',
                        'fsp_vlan_dynamicmapping_interface_ipv6_vrrp6',
                        'wtpprofile_radio3',
                        'utmprofile',
                        'wagprofile',
                        'system_sql_customskipidx',
                        'dynamic_virtualwanlink_neighbor',
                        'dynamic_virtualwanlink_neighbor_dynamicmapping',
                        'dynamic_input_interface',
                        'dynamic_input_interface_dynamicmapping',
                        'fmupdate_fwmsetting',
                        'system_sniffer',
                        'firewall_profileprotocoloptions_ssh',
                        'firewall_internetserviceaddition',
                        'firewall_internetserviceaddition_entry',
                        'firewall_internetserviceaddition_entry_portrange',
                        'firewall_trafficclass',
                        'sshfilter_profile_filefilter',
                        'sshfilter_profile_filefilter_entries',
                        'system_mcpolicydisabledadoms',
                        'antivirus_profile_ssh',
                        'wtpprofile_radio4',
                        'system_docker',
                        'system_geoipoverride_ip6range',
                        'application_list_entries_parameters_members',
                        'switchcontroller_managedswitch_ipsourceguard',
                        'switchcontroller_managedswitch_ipsourceguard_bindingentry',
                        'icap_profile_respmodforwardrules',
                        'icap_profile_respmodforwardrules_headergroup',
                        'credentialstore_domaincontroller',
                        'system_saml_fabricidp',
                        'webfilter_profile_antiphish',
                        'webfilter_profile_antiphish_inspectionentries',
                        'webfilter_profile_antiphish_custompatterns',
                        'firewall_internetservicename',
                        'task_task_line_history',
                        'user_saml',
                        'user_vcenter',
                        'user_vcenter_rule',
                        'dvmdb_folder',
                        'user_radius_dynamicmapping_accountingserver',
                        'filefilter_profile',
                        'filefilter_profile_rules',
                        'mpskprofile',
                        'mpskprofile_mpskgroup',
                        'mpskprofile_mpskgroup_mpskkey',
                        'firewall_profileprotocoloptions_cifs_filefilter',
                        'firewall_profileprotocoloptions_cifs_filefilter_entries',
                        'firewall_profileprotocoloptions_cifs_serverkeytab',
                        'firewall_decryptedtrafficmirror',
                        'vpn_ssl_settings',
                        'vpn_ssl_settings_authenticationrule',
                        'dynamic_interface_platformmapping',
                        'emailfilter_profile_otherwebmails',
                        'wanprof_system_sdwan',
                        'wanprof_system_sdwan_duplication',
                        'wanprof_system_sdwan_healthcheck',
                        'wanprof_system_sdwan_healthcheck_sla',
                        'wanprof_system_sdwan_members',
                        'wanprof_system_sdwan_neighbor',
                        'wanprof_system_sdwan_service',
                        'wanprof_system_sdwan_service_sla',
                        'wanprof_system_sdwan_zone',
                        'pkg_central_dnat6',
                        'extendercontroller_simprofile',
                        'extendercontroller_simprofile_autoswitchprofile',
                        'extendercontroller_dataplan',
                        'system_log_devicedisable',
                        'system_log_ratelimit',
                        'system_log_ratelimit_device',
                        'firewall_sslsshprofile_dot',
                        'firewall_accessproxy',
                        'firewall_accessproxy_apigateway',
                        'firewall_accessproxy_apigateway_realservers',
                        'firewall_accessproxy_apigateway_sslciphersuites',
                        'firewall_accessproxy_serverpubkeyauthsettings',
                        'firewall_accessproxy_serverpubkeyauthsettings_certextension',
                        'firewall_accessproxy_realservers',
                        'emailfilter_blockallowlist',
                        'emailfilter_blockallowlist_entries',
                        'region',
                        'apcfgprofile',
                        'apcfgprofile_commandlist',
                        'extendercontroller_template',
                        'system_socfabric',
                        'switchcontroller_customcommand',
                        'system_replacemsggroup_automation',
                        'videofilter_youtubechannelfilter',
                        'videofilter_youtubechannelfilter_entries',
                        'videofilter_profile',
                        'videofilter_profile_fortiguardcategory',
                        'videofilter_profile_fortiguardcategory_filters',
                        'fmg_variable',
                        'fmg_variable_dynamicmapping',
                        'fmg_device_blueprint',
                        'user_group_dynamicmapping',
                        'user_group_dynamicmapping_sslvpnoschecklist',
                        'user_group_dynamicmapping_match',
                        'user_group_dynamicmapping_guest',
                        'user_connector',
                        'user_nsx_service',
                        'system_sslciphersuites',
                        'pm_config_pblock_firewall_policy',
                        'pkg_firewall_acl',
                        'pkg_firewall_acl6',
                        'pm_config_pblock_firewall_securitypolicy',
                        'system_log_fospolicystats',
                        'system_log_ratelimit_ratelimits',
                        'system_log_topology',
                        'system_ha_monitoredinterfaces',
                        'system_ha_monitoredips',
                        'firewall_vip6_dynamicmapping_realservers',
                        'firewall_vip6_dynamicmapping_sslciphersuites',
                        'firewall_accessproxyvirtualhost',
                        'firewall_accessproxy_apigateway6',
                        'firewall_accessproxy_apigateway6_realservers',
                        'firewall_accessproxy_apigateway6_sslciphersuites',
                        'endpointcontrol_fctems',
                        'system_interface_member',
                        'vpn_ipsec_fec',
                        'vpn_ipsec_fec_mappings',
                        'voip_profile_msrp',
                        'system_localinpolicy6',
                        'system_hascheduledcheck',
                        'extendercontroller_extenderprofile',
                        'extendercontroller_extenderprofile_cellular',
                        'extendercontroller_extenderprofile_cellular_controllerreport',
                        'extendercontroller_extenderprofile_cellular_smsnotification',
                        'extendercontroller_extenderprofile_cellular_smsnotification_alert',
                        'extendercontroller_extenderprofile_cellular_smsnotification_receiver',
                        'extendercontroller_extenderprofile_cellular_modem1',
                        'extendercontroller_extenderprofile_cellular_modem1_autoswitch',
                        'extendercontroller_extenderprofile_cellular_modem2',
                        'extendercontroller_extenderprofile_cellular_modem2_autoswitch',
                        'extendercontroller_extenderprofile_lanextension',
                        'extendercontroller_extenderprofile_lanextension_backhaul',
                        'vap_vlanname',
                        'wtpprofile_eslsesdongle',
                        'hotspot20_icon',
                        'hotspot20_icon_iconlist',
                        'arrpprofile',
                        'nacprofile',
                        'hotspot20_anqpvenueurl',
                        'hotspot20_anqpvenueurl_valuelist',
                        'hotspot20_h2qpadviceofcharge',
                        'hotspot20_h2qpadviceofcharge_aoclist',
                        'hotspot20_h2qpadviceofcharge_aoclist_planinfo',
                        'hotspot20_h2qposuprovidernai',
                        'hotspot20_h2qposuprovidernai_nailist',
                        'hotspot20_h2qptermsandconditions',
                        'system_localinpolicy',
                        'switchcontroller_dsl_policy',
                        'system_npu',
                        'system_npu_portnpumap',
                        'system_npu_portcpumap',
                        'system_npu_isfnpqueues',
                        'system_npu_fpanomaly',
                        'system_npu_priorityprotocol',
                        'system_npu_swehhash',
                        'system_sdnconnector_gcpprojectlist',
                        'system_sdnconnector_forwardingrule',
                        'system_sdnconnector_externalaccountlist',
                        'system_webproxy',
                        'dlp_sensor_entries',
                        'dlp_datatype',
                        'dlp_dictionary',
                        'dlp_dictionary_entries',
                        'dlp_profile',
                        'dlp_profile_rule',
                        'pm_pblock_adom',
                        'pm_pblock',
                        'router_accesslist',
                        'router_accesslist_rule',
                        'router_aspathlist',
                        'router_aspathlist_rule',
                        'router_prefixlist',
                        'router_prefixlist_rule',
                        'router_communitylist',
                        'router_communitylist_rule',
                        'router_routemap',
                        'router_routemap_rule',
                        'router_accesslist6',
                        'router_accesslist6_rule',
                        'router_prefixlist6',
                        'router_prefixlist6_rule'
                    ]
                },
                'path': {
                    'required': False,
                    'default': './',
                    'type': 'str'
                },
                'params': {
                    'required': False,
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
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(None, None, None, None, module, connection)
        fmgr.process_export(export_metadata)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
