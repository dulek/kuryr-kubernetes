# Copyright 2019 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_log import log as logging

from kuryr_kubernetes import clients
from kuryr_kubernetes import constants
from kuryr_kubernetes import exceptions
from kuryr_kubernetes.handlers import k8s_base
from kuryr_kubernetes import utils

LOG = logging.getLogger(__name__)


class KuryrNetPolicyHandler(k8s_base.ResourceEventHandler):
    """Controller side of KuryrNetPolicy process for Kubernetes pods.

    `KuryrNetPolicyHandler` runs on the Kuryr-Kubernetes controller and is
    responsible for deleting associated security groups upon namespace
    deletion.
    """
    OBJECT_KIND = constants.K8S_OBJ_KURYRNETPOLICY
    OBJECT_WATCH_PATH = constants.K8S_API_CRD_KURYRNETPOLICIES

    def __init__(self):
        super(KuryrNetPolicyHandler, self).__init__()

    def _convert_to_kuryrnetworkpolicy(self, netpolicy):
        # TODO(dulek): We might want this in a driver.
        new_networkpolicy = {
            'metadata': {
                'namespace': netpolicy['metadata']['namespace'],
                'name': netpolicy['metadata']['name'],
            },
            'spec': {
                'podSelector': netpolicy['spec']['podSelector'],
                'egressSgRules': netpolicy['spec']['egressSgRules'],
                'ingressSgRules': netpolicy['spec']['ingressSgRules'],
                # TODO(dulek): We should probably prune IDs from SG rules,
                #              but K8s will prune them anyway, so good for now.
            },
            'status': {
                'securityGroupId': netpolicy['spec']['securityGroupId'],
                'securityGroupRules': (netpolicy['spec']['egressSgRules'] +
                                       netpolicy['spec']['ingressSgRules']),
            },
        }

        return new_networkpolicy

    def on_present(self, netpolicy):
        k8s = clients.get_kubernetes_client()
        new_networkpolicy = self._convert_to_kuryrnetworkpolicy(netpolicy)

        # TODO(dulek): We need to generate ports too.

        try:
            k8s.post(constants.K8S_API_CRD_KURYRNETWORKPOLICIES,
                     new_networkpolicy)
        except exceptions.K8sConflict:
            LOG.warning('KuryrNetworkPolicy %s already existed when '
                        'converting KuryrNetPolicy %s. Ignoring.',
                        utils.get_unique_name(new_networkpolicy),
                        utils.get_unique_name(netpolicy))
        k8s.delete(netpolicy['metadata']['selfLink'])
