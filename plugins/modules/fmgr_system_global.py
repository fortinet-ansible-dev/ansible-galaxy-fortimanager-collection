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
module: fmgr_system_global
short_description: Global range attributes.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    system_global:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            admin-lockout-duration:
                type: int
                description: Deprecated, please rename it to admin_lockout_duration. Lockout duration
            admin-lockout-threshold:
                type: int
                description: Deprecated, please rename it to admin_lockout_threshold. Lockout threshold for administration.
            adom-mode:
                type: str
                description:
                    - Deprecated, please rename it to adom_mode.
                    - ADOM mode.
                    - normal - Normal ADOM mode.
                    - advanced - Advanced ADOM mode.
                choices:
                    - 'normal'
                    - 'advanced'
            adom-rev-auto-delete:
                type: str
                description:
                    - Deprecated, please rename it to adom_rev_auto_delete.
                    - Auto delete features for old ADOM revisions.
                    - disable - Disable auto delete function for ADOM revision.
                    - by-revisions - Auto delete ADOM revisions by maximum number of revisions.
                    - by-days - Auto delete ADOM revisions by maximum days.
                choices:
                    - 'disable'
                    - 'by-revisions'
                    - 'by-days'
            adom-rev-max-backup-revisions:
                type: int
                description: Deprecated, please rename it to adom_rev_max_backup_revisions. Maximum number of ADOM revisions to backup.
            adom-rev-max-days:
                type: int
                description: Deprecated, please rename it to adom_rev_max_days. Number of days to keep old ADOM revisions.
            adom-rev-max-revisions:
                type: int
                description: Deprecated, please rename it to adom_rev_max_revisions. Maximum number of ADOM revisions to keep.
            adom-select:
                type: str
                description:
                    - Deprecated, please rename it to adom_select.
                    - Enable/disable select ADOM after login.
                    - disable - Disable select ADOM after login.
                    - enable - Enable select ADOM after login.
                choices:
                    - 'disable'
                    - 'enable'
            adom-status:
                type: str
                description:
                    - Deprecated, please rename it to adom_status.
                    - ADOM status.
                    - disable - Disable ADOM mode.
                    - enable - Enable ADOM mode.
                choices:
                    - 'disable'
                    - 'enable'
            clt-cert-req:
                type: str
                description:
                    - Deprecated, please rename it to clt_cert_req.
                    - Require client certificate for GUI login.
                    - disable - Disable setting.
                    - enable - Require client certificate for GUI login.
                    - optional - Optional client certificate for GUI login.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'optional'
            console-output:
                type: str
                description:
                    - Deprecated, please rename it to console_output.
                    - Console output mode.
                    - standard - Standard output.
                    - more - More page output.
                choices:
                    - 'standard'
                    - 'more'
            country-flag:
                type: str
                description:
                    - Deprecated, please rename it to country_flag.
                    - Country flag Status.
                    - disable - Disable country flag icon beside ip address.
                    - enable - Enable country flag icon beside ip address.
                choices:
                    - 'disable'
                    - 'enable'
            create-revision:
                type: str
                description:
                    - Deprecated, please rename it to create_revision.
                    - Enable/disable create revision by default.
                    - disable - Disable create revision by default.
                    - enable - Enable create revision by default.
                choices:
                    - 'disable'
                    - 'enable'
            daylightsavetime:
                type: str
                description:
                    - Enable/disable daylight saving time.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            default-disk-quota:
                type: int
                description: Deprecated, please rename it to default_disk_quota. Default disk quota for registered device
            detect-unregistered-log-device:
                type: str
                description:
                    - Deprecated, please rename it to detect_unregistered_log_device.
                    - Detect unregistered logging device from log message.
                    - disable - Disable attribute function.
                    - enable - Enable attribute function.
                choices:
                    - 'disable'
                    - 'enable'
            device-view-mode:
                type: str
                description:
                    - Deprecated, please rename it to device_view_mode.
                    - Set devices/groups view mode.
                    - regular - Regular view mode.
                    - tree - Tree view mode.
                choices:
                    - 'regular'
                    - 'tree'
            dh-params:
                type: str
                description:
                    - Deprecated, please rename it to dh_params.
                    - Minimum size of Diffie-Hellman prime for SSH/HTTPS
                    - 1024 - 1024 bits.
                    - 1536 - 1536 bits.
                    - 2048 - 2048 bits.
                    - 3072 - 3072 bits.
                    - 4096 - 4096 bits.
                    - 6144 - 6144 bits.
                    - 8192 - 8192 bits.
                choices:
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
                    - '6144'
                    - '8192'
            disable-module:
                type: list
                elements: str
                description:
                    - Deprecated, please rename it to disable_module.
                    - Disable module list.
                    - fortiview-noc - FortiView/NOC-SOC module.
                    - fortirecorder - FortiRecorder module.
                    - siem - SIEM module.
                    - soc - SOC module.
                    - ai - AI module.
                choices:
                    - 'fortiview-noc'
                    - 'none'
                    - 'fortirecorder'
                    - 'siem'
                    - 'soc'
                    - 'ai'
            enc-algorithm:
                type: str
                description:
                    - Deprecated, please rename it to enc_algorithm.
                    - SSL communication encryption algorithms.
                    - low - SSL communication using all available encryption algorithms.
                    - medium - SSL communication using high and medium encryption algorithms.
                    - high - SSL communication using high encryption algorithms.
                choices:
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'custom'
            faz-status:
                type: str
                description:
                    - Deprecated, please rename it to faz_status.
                    - FAZ status.
                    - disable - Disable FAZ feature.
                    - enable - Enable FAZ feature.
                choices:
                    - 'disable'
                    - 'enable'
            fgfm-local-cert:
                type: str
                description: Deprecated, please rename it to fgfm_local_cert. Set the fgfm local certificate.
            fgfm-ssl-protocol:
                type: str
                description:
                    - Deprecated, please rename it to fgfm_ssl_protocol.
                    - set the lowest SSL protocols for fgfmsd.
                    - sslv3 - set SSLv3 as the lowest version.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                choices:
                    - 'sslv3'
                    - 'tlsv1.0'
                    - 'tlsv1.1'
                    - 'tlsv1.2'
                    - 'tlsv1.3'
            ha-member-auto-grouping:
                type: str
                description:
                    - Deprecated, please rename it to ha_member_auto_grouping.
                    - Enable/disable automatically group HA members feature
                    - disable - Disable automatically grouping HA members feature.
                    - enable - Enable automatically grouping HA members only when group name is unique in your network.
                choices:
                    - 'disable'
                    - 'enable'
            hitcount_concurrent:
                type: int
                description: The number of FortiGates that FortiManager polls at one time
            hitcount_interval:
                type: int
                description: The interval for getting hit count from managed FortiGate devices, in seconds
            hostname:
                type: str
                description: System hostname.
            import-ignore-addr-cmt:
                type: str
                description:
                    - Deprecated, please rename it to import_ignore_addr_cmt.
                    - Enable/Disable import ignore of address comments.
                    - disable - Disable import ignore of address comments.
                    - enable - Enable import ignore of address comments.
                choices:
                    - 'disable'
                    - 'enable'
            language:
                type: str
                description:
                    - System global language.
                    - english - English
                    - simch - Simplified Chinese
                    - japanese - Japanese
                    - korean - Korean
                    - spanish - Spanish
                    - trach - Traditional Chinese
                choices:
                    - 'english'
                    - 'simch'
                    - 'japanese'
                    - 'korean'
                    - 'spanish'
                    - 'trach'
            latitude:
                type: str
                description: Fmg location latitude
            ldap-cache-timeout:
                type: int
                description: Deprecated, please rename it to ldap_cache_timeout. LDAP browser cache timeout
            ldapconntimeout:
                type: int
                description: LDAP connection timeout
            lock-preempt:
                type: str
                description:
                    - Deprecated, please rename it to lock_preempt.
                    - Enable/disable ADOM lock override.
                    - disable - Disable lock preempt.
                    - enable - Enable lock preempt.
                choices:
                    - 'disable'
                    - 'enable'
            log-checksum:
                type: str
                description:
                    - Deprecated, please rename it to log_checksum.
                    - Record log file hash value, timestamp, and authentication code at transmission or rolling.
                    - none - No record log file checksum.
                    - md5 - Record log files MD5 hash value only.
                    - md5-auth - Record log files MD5 hash value and authentication code.
                choices:
                    - 'none'
                    - 'md5'
                    - 'md5-auth'
            log-forward-cache-size:
                type: int
                description: Deprecated, please rename it to log_forward_cache_size. Log forwarding disk cache size
            longitude:
                type: str
                description: Fmg location longitude
            max-log-forward:
                type: int
                description: Deprecated, please rename it to max_log_forward. Maximum number of log-forward and aggregation settings.
            max-running-reports:
                type: int
                description: Deprecated, please rename it to max_running_reports. Maximum number of reports generating at one time.
            oftp-ssl-protocol:
                type: str
                description:
                    - Deprecated, please rename it to oftp_ssl_protocol.
                    - set the lowest SSL protocols for oftpd.
                    - sslv3 - set SSLv3 as the lowest version.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                choices:
                    - 'sslv3'
                    - 'tlsv1.0'
                    - 'tlsv1.1'
                    - 'tlsv1.2'
                    - 'tlsv1.3'
            partial-install:
                type: str
                description:
                    - Deprecated, please rename it to partial_install.
                    - Enable/Disable partial install
                    - disable - Disable partial install function.
                    - enable - Enable partial install function.
                choices:
                    - 'disable'
                    - 'enable'
            partial-install-force:
                type: str
                description:
                    - Deprecated, please rename it to partial_install_force.
                    - Enable/Disable partial install when devdb is modified.
                    - disable - Disable partial install when devdb is modified.
                    - enable - Enable partial install when devdb is modified.
                choices:
                    - 'disable'
                    - 'enable'
            partial-install-rev:
                type: str
                description:
                    - Deprecated, please rename it to partial_install_rev.
                    - Enable/Disable auto creating adom revision for partial install.
                    - disable - Disable partial install revision.
                    - enable - Enable partial install revision.
                choices:
                    - 'disable'
                    - 'enable'
            perform-improve-by-ha:
                type: str
                description:
                    - Deprecated, please rename it to perform_improve_by_ha.
                    - Enable/Disable performance improvement by distributing tasks to HA slaves.
                    - disable - Disable performance improvement by HA.
                    - enable - Enable performance improvement by HA.
                choices:
                    - 'disable'
                    - 'enable'
            policy-hit-count:
                type: str
                description:
                    - Deprecated, please rename it to policy_hit_count.
                    - show policy hit count.
                    - disable - Disable policy hit count.
                    - enable - Enable policy hit count.
                choices:
                    - 'disable'
                    - 'enable'
            policy-object-in-dual-pane:
                type: str
                description:
                    - Deprecated, please rename it to policy_object_in_dual_pane.
                    - show policies and objects in dual pane.
                    - disable - Disable polices and objects in dual pane.
                    - enable - Enable polices and objects in dual pane.
                choices:
                    - 'disable'
                    - 'enable'
            pre-login-banner:
                type: str
                description:
                    - Deprecated, please rename it to pre_login_banner.
                    - Enable/disable pre-login banner.
                    - disable - Disable pre-login banner.
                    - enable - Enable pre-login banner.
                choices:
                    - 'disable'
                    - 'enable'
            pre-login-banner-message:
                type: str
                description: Deprecated, please rename it to pre_login_banner_message. Pre-login banner message.
            remoteauthtimeout:
                type: int
                description: Remote authentication
            search-all-adoms:
                type: str
                description:
                    - Deprecated, please rename it to search_all_adoms.
                    - Enable/Disable Search all ADOMs for where-used query.
                    - disable - Disable search all ADOMs for where-used queries.
                    - enable - Enable search all ADOMs for where-used queries.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-low-encryption:
                type: str
                description:
                    - Deprecated, please rename it to ssl_low_encryption.
                    - SSL low-grade encryption.
                    - disable - Disable SSL low-grade encryption.
                    - enable - Enable SSL low-grade encryption.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-protocol:
                type: list
                elements: str
                description:
                    - Deprecated, please rename it to ssl_protocol.
                    - SSL protocols.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                    - sslv3 - Enable SSLv3.
                choices:
                    - 'tlsv1.2'
                    - 'tlsv1.1'
                    - 'tlsv1.0'
                    - 'sslv3'
                    - 'tlsv1.3'
            ssl-static-key-ciphers:
                type: str
                description:
                    - Deprecated, please rename it to ssl_static_key_ciphers.
                    - Enable/disable SSL static key ciphers.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            task-list-size:
                type: int
                description: Deprecated, please rename it to task_list_size. Maximum number of completed tasks to keep.
            tftp:
                type: str
                description:
                    - Enable/disable TFTP in `exec restore image` command
                    - disable - Disable TFTP
                    - enable - Enable TFTP
                choices:
                    - 'disable'
                    - 'enable'
            timezone:
                type: str
                description:
                    - Time zone.
                    - 00 -
                    - 01 -
                    - 02 -
                    - 03 -
                    - 04 -
                    - 05 -
                    - 06 -
                    - 07 -
                    - 08 -
                    - 09 -
                    - 10 -
                    - 11 -
                    - 12 -
                    - 13 -
                    - 14 -
                    - 15 -
                    - 16 -
                    - 17 -
                    - 18 -
                    - 19 -
                    - 20 -
                    - 21 -
                    - 22 -
                    - 23 -
                    - 24 -
                    - 25 -
                    - 26 -
                    - 27 -
                    - 28 -
                    - 29 -
                    - 30 -
                    - 31 -
                    - 32 -
                    - 33 -
                    - 34 -
                    - 35 -
                    - 36 -
                    - 37 -
                    - 38 -
                    - 39 -
                    - 40 -
                    - 41 -
                    - 42 -
                    - 43 -
                    - 44 -
                    - 45 -
                    - 46 -
                    - 47 -
                    - 48 -
                    - 49 -
                    - 50 -
                    - 51 -
                    - 52 -
                    - 53 -
                    - 54 -
                    - 55 -
                    - 56 -
                    - 57 -
                    - 58 -
                    - 59 -
                    - 60 -
                    - 61 -
                    - 62 -
                    - 63 -
                    - 64 -
                    - 65 -
                    - 66 -
                    - 67 -
                    - 68 -
                    - 69 -
                    - 70 -
                    - 71 -
                    - 72 -
                    - 73 -
                    - 74 -
                    - 75 -
                    - 76 -
                    - 77 -
                    - 78 -
                    - 79 -
                    - 80 -
                    - 81 -
                    - 82 -
                    - 83 -
                    - 84 -
                    - 85 -
                    - 86 -
                    - 87 -
                    - 88 -
                    - 89 -
                choices:
                    - '00'
                    - '01'
                    - '02'
                    - '03'
                    - '04'
                    - '05'
                    - '06'
                    - '07'
                    - '08'
                    - '09'
                    - '10'
                    - '11'
                    - '12'
                    - '13'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '22'
                    - '23'
                    - '24'
                    - '25'
                    - '26'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
                    - '33'
                    - '34'
                    - '35'
                    - '36'
                    - '37'
                    - '38'
                    - '39'
                    - '40'
                    - '41'
                    - '42'
                    - '43'
                    - '44'
                    - '45'
                    - '46'
                    - '47'
                    - '48'
                    - '49'
                    - '50'
                    - '51'
                    - '52'
                    - '53'
                    - '54'
                    - '55'
                    - '56'
                    - '57'
                    - '58'
                    - '59'
                    - '60'
                    - '61'
                    - '62'
                    - '63'
                    - '64'
                    - '65'
                    - '66'
                    - '67'
                    - '68'
                    - '69'
                    - '70'
                    - '71'
                    - '72'
                    - '73'
                    - '74'
                    - '75'
                    - '76'
                    - '77'
                    - '78'
                    - '79'
                    - '80'
                    - '81'
                    - '82'
                    - '83'
                    - '84'
                    - '85'
                    - '86'
                    - '87'
                    - '88'
                    - '89'
                    - '90'
                    - '91'
            tunnel-mtu:
                type: int
                description: Deprecated, please rename it to tunnel_mtu. Maximum transportation unit
            usg:
                type: str
                description:
                    - Enable/disable Fortiguard server restriction.
                    - disable - Contact any Fortiguard server
                    - enable - Contact Fortiguard server in USA only
                choices:
                    - 'disable'
                    - 'enable'
            vdom-mirror:
                type: str
                description:
                    - Deprecated, please rename it to vdom_mirror.
                    - VDOM mirror.
                    - disable - Disable VDOM mirror function.
                    - enable - Enable VDOM mirror function.
                choices:
                    - 'disable'
                    - 'enable'
            webservice-proto:
                type: list
                elements: str
                description:
                    - Deprecated, please rename it to webservice_proto.
                    - Web Service connection support SSL protocols.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                    - sslv3 - Web Service connection using SSLv3 protocol.
                    - sslv2 - Web Service connection using SSLv2 protocol.
                choices:
                    - 'tlsv1.2'
                    - 'tlsv1.1'
                    - 'tlsv1.0'
                    - 'sslv3'
                    - 'sslv2'
                    - 'tlsv1.3'
            workflow-max-sessions:
                type: int
                description: Deprecated, please rename it to workflow_max_sessions. Maximum number of workflow sessions per ADOM
            workspace-mode:
                type: str
                description:
                    - Deprecated, please rename it to workspace_mode.
                    - Set workspace mode
                    - disabled - Workspace disabled.
                    - normal - Workspace lock mode.
                    - workflow - Workspace workflow mode.
                choices:
                    - 'disabled'
                    - 'normal'
                    - 'workflow'
                    - 'per-adom'
            clone-name-option:
                type: str
                description:
                    - Deprecated, please rename it to clone_name_option.
                    - set the clone object names option.
                    - default - Add a prefix of Clone of to the clone name.
                    - keep - Keep the original name for user to edit.
                choices:
                    - 'default'
                    - 'keep'
            fgfm-ca-cert:
                type: str
                description: Deprecated, please rename it to fgfm_ca_cert. Set the extra fgfm CA certificates.
            mc-policy-disabled-adoms:
                type: list
                elements: dict
                description: Deprecated, please rename it to mc_policy_disabled_adoms. Mc-Policy-Disabled-Adoms.
                suboptions:
                    adom-name:
                        type: str
                        description: Deprecated, please rename it to adom_name. Adom names.
            policy-object-icon:
                type: str
                description:
                    - Deprecated, please rename it to policy_object_icon.
                    - show icons of policy objects.
                    - disable - Disable icon of policy objects.
                    - enable - Enable icon of policy objects.
                choices:
                    - 'disable'
                    - 'enable'
            private-data-encryption:
                type: str
                description:
                    - Deprecated, please rename it to private_data_encryption.
                    - Enable/disable private data encryption using an AES 128-bit key.
                    - disable - Disable private data encryption using an AES 128-bit key.
                    - enable - Enable private data encryption using an AES 128-bit key.
                choices:
                    - 'disable'
                    - 'enable'
            per-policy-lock:
                type: str
                description:
                    - Deprecated, please rename it to per_policy_lock.
                    - Enable/Disable per policy lock.
                    - disable - Disable per policy lock.
                    - enable - Enable per policy lock.
                choices:
                    - 'disable'
                    - 'enable'
            multiple-steps-upgrade-in-autolink:
                type: str
                description:
                    - Deprecated, please rename it to multiple_steps_upgrade_in_autolink.
                    - Enable/disable multiple steps upgade in autolink process
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            object-revision-db-max:
                type: int
                description: Deprecated, please rename it to object_revision_db_max. Maximum revisions for a single database
            object-revision-mandatory-note:
                type: str
                description:
                    - Deprecated, please rename it to object_revision_mandatory_note.
                    - Enable/disable mandatory note when create revision.
                    - disable - Disable object revision.
                    - enable - Enable object revision.
                choices:
                    - 'disable'
                    - 'enable'
            object-revision-object-max:
                type: int
                description: Deprecated, please rename it to object_revision_object_max. Maximum revisions for a single object
            object-revision-status:
                type: str
                description:
                    - Deprecated, please rename it to object_revision_status.
                    - Enable/disable create revision when modify objects.
                    - disable - Disable object revision.
                    - enable - Enable object revision.
                choices:
                    - 'disable'
                    - 'enable'
            normalized-intf-zone-only:
                type: str
                description:
                    - Deprecated, please rename it to normalized_intf_zone_only.
                    - allow normalized interface to be zone only.
                    - disable - Disable SSL low-grade encryption.
                    - enable - Enable SSL low-grade encryption.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-cipher-suites:
                type: list
                elements: dict
                description: Deprecated, please rename it to ssl_cipher_suites.
                suboptions:
                    cipher:
                        type: str
                        description: Cipher name
                    priority:
                        type: int
                        description: SSL/TLS cipher suites priority.
                    version:
                        type: str
                        description:
                            - SSL/TLS version the cipher suite can be used with.
                            - tls1.
                            - tls1.
                        choices:
                            - 'tls1.2-or-below'
                            - 'tls1.3'
            gui-curl-timeout:
                type: int
                description: Deprecated, please rename it to gui_curl_timeout. GUI curl timeout in seconds
            table-entry-blink:
                type: str
                description:
                    - Deprecated, please rename it to table_entry_blink.
                    - Enable/disable table entry blink in GUI
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            contentpack-fgt-install:
                type: str
                description:
                    - Deprecated, please rename it to contentpack_fgt_install.
                    - Enable/disable outbreak alert auto install for FGT ADOMS .
                    - disable - Disable the sql report auto outbreak auto install.
                    - enable - Enable the sql report auto outbreak auto install.
                choices:
                    - 'disable'
                    - 'enable'
            gui-polling-interval:
                type: int
                description: Deprecated, please rename it to gui_polling_interval. GUI polling interval in seconds
            no-copy-permission-check:
                type: str
                description:
                    - Deprecated, please rename it to no_copy_permission_check.
                    - Do not perform permission check to block object changes in different adom during copy and install.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            ssh-enc-algo:
                type: list
                elements: str
                description: Deprecated, please rename it to ssh_enc_algo.
                choices:
                    - 'chacha20-poly1305@openssh.com'
                    - 'aes128-ctr'
                    - 'aes192-ctr'
                    - 'aes256-ctr'
                    - 'arcfour256'
                    - 'arcfour128'
                    - 'aes128-cbc'
                    - '3des-cbc'
                    - 'blowfish-cbc'
                    - 'cast128-cbc'
                    - 'aes192-cbc'
                    - 'aes256-cbc'
                    - 'arcfour'
                    - 'rijndael-cbc@lysator.liu.se'
                    - 'aes128-gcm@openssh.com'
                    - 'aes256-gcm@openssh.com'
            ssh-hostkey-algo:
                type: list
                elements: str
                description: Deprecated, please rename it to ssh_hostkey_algo.
                choices:
                    - 'ssh-rsa'
                    - 'ecdsa-sha2-nistp521'
                    - 'rsa-sha2-256'
                    - 'rsa-sha2-512'
                    - 'ssh-ed25519'
            ssh-kex-algo:
                type: list
                elements: str
                description: Deprecated, please rename it to ssh_kex_algo.
                choices:
                    - 'diffie-hellman-group1-sha1'
                    - 'diffie-hellman-group14-sha1'
                    - 'diffie-hellman-group14-sha256'
                    - 'diffie-hellman-group16-sha512'
                    - 'diffie-hellman-group18-sha512'
                    - 'diffie-hellman-group-exchange-sha1'
                    - 'diffie-hellman-group-exchange-sha256'
                    - 'curve25519-sha256@libssh.org'
                    - 'ecdh-sha2-nistp256'
                    - 'ecdh-sha2-nistp384'
                    - 'ecdh-sha2-nistp521'
            ssh-mac-algo:
                type: list
                elements: str
                description: Deprecated, please rename it to ssh_mac_algo.
                choices:
                    - 'hmac-md5'
                    - 'hmac-md5-etm@openssh.com'
                    - 'hmac-md5-96'
                    - 'hmac-md5-96-etm@openssh.com'
                    - 'hmac-sha1'
                    - 'hmac-sha1-etm@openssh.com'
                    - 'hmac-sha2-256'
                    - 'hmac-sha2-256-etm@openssh.com'
                    - 'hmac-sha2-512'
                    - 'hmac-sha2-512-etm@openssh.com'
                    - 'hmac-ripemd160'
                    - 'hmac-ripemd160@openssh.com'
                    - 'hmac-ripemd160-etm@openssh.com'
                    - 'umac-64@openssh.com'
                    - 'umac-128@openssh.com'
                    - 'umac-64-etm@openssh.com'
                    - 'umac-128-etm@openssh.com'
            ssh-strong-crypto:
                type: str
                description:
                    - Deprecated, please rename it to ssh_strong_crypto.
                    - Only allow strong ciphers for SSH when enabled.
                    - disable - Disable strong crypto for SSH.
                    - enable - Enable strong crypto for SSH.
                choices:
                    - 'disable'
                    - 'enable'
            fgfm-cert-exclusive:
                type: str
                description:
                    - Deprecated, please rename it to fgfm_cert_exclusive.
                    - set if the local or CA certificates should be used exclusively.
                    - disable - Used certificate best-effort.
                    - enable - Used certificate exclusive.
                choices:
                    - 'disable'
                    - 'enable'
            fgfm-deny-unknown:
                type: str
                description:
                    - Deprecated, please rename it to fgfm_deny_unknown.
                    - set if allow devices with unknown SN actively register as an unauthorized device.
                    - disable - Allow devices with unknown SN to actively register as an unauthorized device.
                    - enable - Deny devices with unknown SN to actively register as an unauthorized device.
                choices:
                    - 'disable'
                    - 'enable'
            fgfm-peercert-withoutsn:
                type: str
                description:
                    - Deprecated, please rename it to fgfm_peercert_withoutsn.
                    - set if the subject CN or SAN of peer&apos;s SSL certificate sent in FGFM should include the serial number of the device.
                    - disable - Peer&apos;s certificate must include serial number in subject CN or SAN.
                    - enable - Peer&apos;s certificate might not include serial number in subject CN or SAN.
                choices:
                    - 'disable'
                    - 'enable'
            admin-lockout-method:
                type: str
                description:
                    - Deprecated, please rename it to admin_lockout_method.
                    - Lockout method for administration.
                    - ip - Lockout by IP
                    - user - Lockout by user
                choices:
                    - 'ip'
                    - 'user'
            workspace-unlock-after-install:
                type: str
                description:
                    - Deprecated, please rename it to workspace_unlock_after_install.
                    - Enable/disable ADOM auto-unlock after device installation.
                    - disable - Disable automatically unlock adom after device installation.
                    - enable - Enable automatically unlock adom after device installation.
                choices:
                    - 'disable'
                    - 'enable'
            log-checksum-upload:
                type: str
                description:
                    - Deprecated, please rename it to log_checksum_upload.
                    - Enable/disable upload log checksum with log files.
                    - disable - Disable attribute function.
                    - enable - Enable attribute function.
                choices:
                    - 'disable'
                    - 'enable'
            apache-mode:
                type: str
                description:
                    - Deprecated, please rename it to apache_mode.
                    - Set apache mode.
                    - event - Apache event mode.
                    - prefork - Apache prefork mode.
                choices:
                    - 'event'
                    - 'prefork'
            no-vip-value-check:
                type: str
                description:
                    - Deprecated, please rename it to no_vip_value_check.
                    - Enable/disable skipping policy instead of throwing error when vip has no default or dynamic mapping during policy copy
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            fortiservice-port:
                type: int
                description: Deprecated, please rename it to fortiservice_port. FortiService port
            management-ip:
                type: str
                description: Deprecated, please rename it to management_ip. Management IP address of this FortiGate.
            management-port:
                type: int
                description: Deprecated, please rename it to management_port. Overriding port for management connection
            save-last-hit-in-adomdb:
                type: str
                description:
                    - Deprecated, please rename it to save_last_hit_in_adomdb.
                    - Enable/Disable save last-hit value in adomdb.
                    - disable - Disable save last-hit value in adomdb.
                    - enable - Enable save last-hit value in adomdb.
                choices:
                    - 'disable'
                    - 'enable'
            api-ip-binding:
                type: str
                description:
                    - Deprecated, please rename it to api_ip_binding.
                    - Enable/disable source IP check for JSON API request.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Enable workspace mode
      fortinet.fortimanager.fmgr_system_global:
        system_global:
          adom-status: enable
          workspace-mode: normal

    - name: Script table.
      fortinet.fortimanager.fmgr_dvmdb_script:
        bypass_validation: false
        adom: root
        state: present
        workspace_locking_adom: "root"
        dvmdb_script:
          content: "ansiblt-test"
          name: "fooscript000"
          target: device_database
          type: cli

    - name: Verify script table
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "dvmdb_script"
          params:
            adom: "root"
            script: "fooscript000"
      register: info
      failed_when: info.meta.response_code != 0

    - name: Restore workspace mode
      fortinet.fortimanager.fmgr_system_global:
        system_global:
          adom-status: enable
          workspace-mode: disabled
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    jrpc_urls = [
        '/cli/global/system/global'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/global/{global}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'system_global': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'admin-lockout-duration': {'type': 'int'},
                'admin-lockout-threshold': {'type': 'int'},
                'adom-mode': {'choices': ['normal', 'advanced'], 'type': 'str'},
                'adom-rev-auto-delete': {'choices': ['disable', 'by-revisions', 'by-days'], 'type': 'str'},
                'adom-rev-max-backup-revisions': {'type': 'int'},
                'adom-rev-max-days': {'type': 'int'},
                'adom-rev-max-revisions': {'type': 'int'},
                'adom-select': {'choices': ['disable', 'enable'], 'type': 'str'},
                'adom-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'clt-cert-req': {'choices': ['disable', 'enable', 'optional'], 'type': 'str'},
                'console-output': {'choices': ['standard', 'more'], 'type': 'str'},
                'country-flag': {'choices': ['disable', 'enable'], 'type': 'str'},
                'create-revision': {'choices': ['disable', 'enable'], 'type': 'str'},
                'daylightsavetime': {'choices': ['disable', 'enable'], 'type': 'str'},
                'default-disk-quota': {'v_range': [['6.0.0', '6.2.0']], 'type': 'int'},
                'detect-unregistered-log-device': {'choices': ['disable', 'enable'], 'type': 'str'},
                'device-view-mode': {'choices': ['regular', 'tree'], 'type': 'str'},
                'dh-params': {'choices': ['1024', '1536', '2048', '3072', '4096', '6144', '8192'], 'type': 'str'},
                'disable-module': {'type': 'list', 'choices': ['fortiview-noc', 'none', 'fortirecorder', 'siem', 'soc', 'ai'], 'elements': 'str'},
                'enc-algorithm': {'choices': ['low', 'medium', 'high', 'custom'], 'type': 'str'},
                'faz-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fgfm-local-cert': {'type': 'str'},
                'fgfm-ssl-protocol': {'choices': ['sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'], 'type': 'str'},
                'ha-member-auto-grouping': {'choices': ['disable', 'enable'], 'type': 'str'},
                'hitcount_concurrent': {'v_range': [['6.0.0', '6.4.2']], 'type': 'int'},
                'hitcount_interval': {'v_range': [['6.0.0', '6.4.2']], 'type': 'int'},
                'hostname': {'type': 'str'},
                'import-ignore-addr-cmt': {'choices': ['disable', 'enable'], 'type': 'str'},
                'language': {'choices': ['english', 'simch', 'japanese', 'korean', 'spanish', 'trach'], 'type': 'str'},
                'latitude': {'type': 'str'},
                'ldap-cache-timeout': {'type': 'int'},
                'ldapconntimeout': {'type': 'int'},
                'lock-preempt': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log-checksum': {'choices': ['none', 'md5', 'md5-auth'], 'type': 'str'},
                'log-forward-cache-size': {'type': 'int'},
                'longitude': {'type': 'str'},
                'max-log-forward': {'type': 'int'},
                'max-running-reports': {'type': 'int'},
                'oftp-ssl-protocol': {'choices': ['sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'], 'type': 'str'},
                'partial-install': {'choices': ['disable', 'enable'], 'type': 'str'},
                'partial-install-force': {'choices': ['disable', 'enable'], 'type': 'str'},
                'partial-install-rev': {'choices': ['disable', 'enable'], 'type': 'str'},
                'perform-improve-by-ha': {'choices': ['disable', 'enable'], 'type': 'str'},
                'policy-hit-count': {'v_range': [['6.0.0', '6.4.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'policy-object-in-dual-pane': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pre-login-banner': {'choices': ['disable', 'enable'], 'type': 'str'},
                'pre-login-banner-message': {'type': 'str'},
                'remoteauthtimeout': {'type': 'int'},
                'search-all-adoms': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-low-encryption': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-protocol': {'type': 'list', 'choices': ['tlsv1.2', 'tlsv1.1', 'tlsv1.0', 'sslv3', 'tlsv1.3'], 'elements': 'str'},
                'ssl-static-key-ciphers': {'choices': ['disable', 'enable'], 'type': 'str'},
                'task-list-size': {'type': 'int'},
                'tftp': {'choices': ['disable', 'enable'], 'type': 'str'},
                'timezone': {
                    'choices': [
                        '00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20',
                        '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41',
                        '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62',
                        '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83',
                        '84', '85', '86', '87', '88', '89', '90', '91'
                    ],
                    'type': 'str'
                },
                'tunnel-mtu': {'type': 'int'},
                'usg': {'choices': ['disable', 'enable'], 'type': 'str'},
                'vdom-mirror': {'choices': ['disable', 'enable'], 'type': 'str'},
                'webservice-proto': {'type': 'list', 'choices': ['tlsv1.2', 'tlsv1.1', 'tlsv1.0', 'sslv3', 'sslv2', 'tlsv1.3'], 'elements': 'str'},
                'workflow-max-sessions': {'type': 'int'},
                'workspace-mode': {'choices': ['disabled', 'normal', 'workflow', 'per-adom'], 'type': 'str'},
                'clone-name-option': {'v_range': [['6.2.2', '']], 'choices': ['default', 'keep'], 'type': 'str'},
                'fgfm-ca-cert': {'v_range': [['6.2.3', '']], 'type': 'str'},
                'mc-policy-disabled-adoms': {
                    'v_range': [['6.2.3', '']],
                    'type': 'list',
                    'options': {'adom-name': {'v_range': [['6.2.3', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'policy-object-icon': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'private-data-encryption': {'v_range': [['6.2.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'per-policy-lock': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'multiple-steps-upgrade-in-autolink': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'object-revision-db-max': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'object-revision-mandatory-note': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'object-revision-object-max': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'object-revision-status': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'normalized-intf-zone-only': {'v_range': [['6.4.7', '6.4.14'], ['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-cipher-suites': {
                    'v_range': [['6.4.8', '6.4.14'], ['7.0.2', '']],
                    'type': 'list',
                    'options': {
                        'cipher': {'v_range': [['6.4.8', '6.4.14'], ['7.0.2', '']], 'type': 'str'},
                        'priority': {'v_range': [['6.4.8', '6.4.14'], ['7.0.2', '']], 'type': 'int'},
                        'version': {'v_range': [['6.4.8', '6.4.14'], ['7.0.2', '']], 'choices': ['tls1.2-or-below', 'tls1.3'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'gui-curl-timeout': {'v_range': [['6.4.11', '6.4.14'], ['7.0.7', '7.0.12'], ['7.2.2', '']], 'type': 'int'},
                'table-entry-blink': {'v_range': [['7.0.4', '7.0.12'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'contentpack-fgt-install': {'v_range': [['7.0.5', '7.0.12'], ['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-polling-interval': {'v_range': [['7.0.5', '7.0.12'], ['7.2.1', '']], 'type': 'int'},
                'no-copy-permission-check': {'v_range': [['7.0.8', '7.0.12'], ['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-enc-algo': {
                    'v_range': [['7.0.11', '7.0.12'], ['7.2.5', '7.2.5'], ['7.4.2', '']],
                    'type': 'list',
                    'choices': [
                        'chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'arcfour256', 'arcfour128', 'aes128-cbc', '3des-cbc',
                        'blowfish-cbc', 'cast128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour', 'rijndael-cbc@lysator.liu.se', 'aes128-gcm@openssh.com',
                        'aes256-gcm@openssh.com'
                    ],
                    'elements': 'str'
                },
                'ssh-hostkey-algo': {
                    'v_range': [['7.0.11', '7.0.12'], ['7.2.5', '7.2.5'], ['7.4.2', '']],
                    'type': 'list',
                    'choices': ['ssh-rsa', 'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519'],
                    'elements': 'str'
                },
                'ssh-kex-algo': {
                    'v_range': [['7.0.11', '7.0.12'], ['7.2.5', '7.2.5'], ['7.4.2', '']],
                    'type': 'list',
                    'choices': [
                        'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group14-sha256', 'diffie-hellman-group16-sha512',
                        'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group-exchange-sha256',
                        'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521'
                    ],
                    'elements': 'str'
                },
                'ssh-mac-algo': {
                    'v_range': [['7.0.11', '7.0.12'], ['7.2.5', '7.2.5'], ['7.4.2', '']],
                    'type': 'list',
                    'choices': [
                        'hmac-md5', 'hmac-md5-etm@openssh.com', 'hmac-md5-96', 'hmac-md5-96-etm@openssh.com', 'hmac-sha1', 'hmac-sha1-etm@openssh.com',
                        'hmac-sha2-256', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-512-etm@openssh.com', 'hmac-ripemd160',
                        'hmac-ripemd160@openssh.com', 'hmac-ripemd160-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com',
                        'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com'
                    ],
                    'elements': 'str'
                },
                'ssh-strong-crypto': {
                    'v_range': [['7.0.11', '7.0.12'], ['7.2.5', '7.2.5'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'fgfm-cert-exclusive': {'v_range': [['7.0.12', '7.0.12'], ['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fgfm-deny-unknown': {'v_range': [['7.0.12', '7.0.12'], ['7.2.5', '7.2.5']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fgfm-peercert-withoutsn': {'v_range': [['7.0.12', '7.0.12'], ['7.2.5', '7.2.5']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-lockout-method': {'v_range': [['7.2.2', '']], 'choices': ['ip', 'user'], 'type': 'str'},
                'workspace-unlock-after-install': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-checksum-upload': {'v_range': [['7.2.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'apache-mode': {'v_range': [['7.2.4', '7.2.5'], ['7.4.1', '']], 'choices': ['event', 'prefork'], 'type': 'str'},
                'no-vip-value-check': {'v_range': [['7.2.4', '7.2.5'], ['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiservice-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'management-ip': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'management-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'save-last-hit-in-adomdb': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'api-ip-binding': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_global'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
