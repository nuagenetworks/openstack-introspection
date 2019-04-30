# Copyright 2019 Nokia
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""****************************************************************************
File: introspect_deployment.py

Purpose:
1. Check the mapping between vsd unmanaged l2domains and os subnets.
2. Check the setting of pat model

Requirement:
    This script require two configuration files.
    1. nuage_plugin.ini : which has details to connect to VSD
    2. neutron.conf : which has details to connect to neutron database.
Run:
    python introspect_deployment.py --neutron-conf <neutron.conf>
      --nuage-conf <nuage_plugin.ini>
****************************************************************************"""
import argparse
import json
import logging
import os
import sys

from collections import defaultdict

from neutron.common import config
from neutron.db.migration.cli import CURRENT_RELEASE
from neutron.db.models_v2 import Subnet
from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common.nuage_models import SubnetL2Domain
from oslo_config import cfg

from utils import nuage_logging
from utils.restproxy import RESTProxyServer

try:
    from neutron import context as neutron_context
except ImportError:
    from neutron_lib import context as neutron_context
try:
    from neutron.conf.db.l3_gwmode_db import L3GWMODE_OPTS
except ImportError:
    from neutron.db.l3_gwmode_db import OPTS as L3GWMODE_OPTS

script_name = 'introspect_deployment.py'
report_name = 'introspection.json'

LOG = logging.getLogger(script_name)


class IntrospectDeployment(object):
    def __init__(self, restproxy):
        self.restproxy = restproxy

        cfg.CONF.register_opts(L3GWMODE_OPTS)
        self.nuage_pat = cfg.CONF.RESTPROXY.nuage_pat
        self.nuage_underlay_default = cfg.CONF.RESTPROXY.nuage_underlay_default
        self.enable_snat_default = cfg.CONF.enable_snat_by_default

    @nuage_logging.step(description="Introspecting the target deployment")
    def check(self):
        context = neutron_context.get_admin_context()
        session = context.session
        vsd_unmgd_output = self.check_unmanaged_subnets(session)
        pat_model_output = self.check_pat_model()
        output = {
            'neutron_version': CURRENT_RELEASE,
            'vsd_unmanaged_subnets': vsd_unmgd_output,
            'pat_model': pat_model_output
        }
        with open(report_name, 'w') as outfile:
            json.dump(output, outfile, indent=4, sort_keys=True)

    @nuage_logging.step(description="Checking VSD unmanaged subnets")
    def check_unmanaged_subnets(self, session):
        # Check unmanaged
        vsd_unmgd_output = []
        # Get all vsd managed subnets
        vsd_mgd_sub_mappings = session.query(SubnetL2Domain).filter_by(
            nuage_managed_subnet=True).all()
        vsd_unmgd_subs = defaultdict(list)

        # Get os subnets for vsd dhcp unmanaged subnets
        for vsd_mgd_sub_mapping in vsd_mgd_sub_mappings:
            nuage_subnet_id = vsd_mgd_sub_mapping['nuage_subnet_id']
            subnet_id = vsd_mgd_sub_mapping['subnet_id']
            dhcp_unmgd_subnet = session.query(Subnet).filter_by(
                enable_dhcp=False, id=subnet_id).all()
            if dhcp_unmgd_subnet:
                vsd_unmgd_subs[nuage_subnet_id].append(dhcp_unmgd_subnet[0])

        # Create output data
        for vsd_sub_id in vsd_unmgd_subs:
            subnets = vsd_unmgd_subs[vsd_sub_id]
            cidr_ipv4 = set()
            cidr_ipv6 = set()
            num_ipv4 = num_ipv6 = 0
            for sub in subnets:
                if sub['ip_version'] == 4:
                    cidr_ipv4.add(sub['cidr'])
                    num_ipv4 += 1
                else:
                    cidr_ipv6.add(sub['cidr'])
                    num_ipv6 += 1

            vsd_unmgd_output.append({
                'vsd_unmanaged_l2domain': vsd_sub_id,
                'os_subnets': {
                    'unique_ipv4_cidrs': len(cidr_ipv4),
                    'unique_ipv6_cidrs': len(cidr_ipv6),
                    'total_ipv4_subnets': num_ipv4,
                    'total_ipv6_subnets': num_ipv6
                }
            })
        return vsd_unmgd_output

    @nuage_logging.step(description="Checking pat model")
    def check_pat_model(self):
        pat_data = {
            'nuage_pat': self.nuage_pat,
            'nuage_underlay_default': self.nuage_underlay_default,
            'enable_snat_by_default': self.enable_snat_default
        }
        cms_id = cfg.CONF.RESTPROXY.cms_id
        headers = {
            'X-NUAGE-FilterType': "predicate",
            'X-Nuage-Filter': ("externalID ENDSWITH '@{cms_id}' and "
                               "PATEnabled IS '{is_pat_enabled}' and "
                               "underlayEnabled IS '{is_underlay_enabled}'"
                               .format(cms_id=cms_id,
                                       is_pat_enabled='ENABLED',
                                       is_underlay_enabled='ENABLED'))
        }
        response = self.restproxy.get(resource='/domains',
                                      extra_headers=headers)
        if response[0] not in self.restproxy.success_codes:
            msg = ("Cannot communicate with Nuage VSD. Please check your "
                   "connection with the Nuage VSD")
            raise Exception(msg)
        else:
            pat_data.update({'pat_l3domain_num': len(response[3])})
        return pat_data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--neutron-conf",
                        required=True,
                        help="File path to the neutron configuration file")
    parser.add_argument("--nuage-conf",
                        required=True,
                        help="File path to the nuage plugin configuration "
                             "file")
    args = parser.parse_args()

    if not nuage_logging.log_file:
        nuage_logging.init_logging(script_name, 'introspect')

    conf_list = []
    for conf_file in (args.neutron_conf, args.nuage_conf):
        if not os.path.isfile(conf_file):
            LOG.user('File "%s" cannot be found.' % conf_file)
            sys.exit(1)
        conf_list.append('--config-file')
        conf_list.append(conf_file)

    config.init(conf_list)
    nuage_config.nuage_register_cfg_opts()

    server = cfg.CONF.RESTPROXY.server
    serverauth = cfg.CONF.RESTPROXY.serverauth
    serverssl = cfg.CONF.RESTPROXY.serverssl
    base_uri = cfg.CONF.RESTPROXY.base_uri
    auth_resource = cfg.CONF.RESTPROXY.auth_resource
    organization = cfg.CONF.RESTPROXY.organization

    try:
        restproxy = RESTProxyServer(server=server,
                                    base_uri=base_uri,
                                    serverssl=serverssl,
                                    serverauth=serverauth,
                                    auth_resource=auth_resource,
                                    organization=organization)

    except Exception as e:
        LOG.user("Error in connecting to VSD: %s", str(e), exc_info=True)
        sys.exit(1)

    try:
        LOG.user("Introspecting the target deployment")
        IntrospectDeployment(restproxy).check()
        LOG.user("Script executed successfully.\n"
                 "Please find the report in {}".format(report_name))

    except Exception as e:
        LOG.user("\n\nThe following error occurred:\n  %(error_msg)s\n"
                 "For more information, please find the log file at "
                 "%(log_file)s and contact your vendor.",
                 {'error_msg': e.message,
                  'log_file': nuage_logging.log_file},
                 exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()