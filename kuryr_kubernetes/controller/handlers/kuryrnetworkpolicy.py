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

from openstack import exceptions as os_exc
from oslo_log import log as logging

from kuryr_kubernetes import clients
from kuryr_kubernetes import constants
from kuryr_kubernetes.controller import drivers
from kuryr_kubernetes.controller.drivers import utils as driver_utils
from kuryr_kubernetes import exceptions
from kuryr_kubernetes.handlers import k8s_base
from kuryr_kubernetes import utils

LOG = logging.getLogger(__name__)


class KuryrNetworkPolicyHandler(k8s_base.ResourceEventHandler):
    """Controller side of KuryrNetPolicy process for Kubernetes pods.

    `KuryrNetPolicyHandler` runs on the Kuryr-Kubernetes controller and is
    responsible for deleting associated security groups upon namespace
    deletion.
    """
    OBJECT_KIND = constants.K8S_OBJ_KURYRNETWORKPOLICY
    OBJECT_WATCH_PATH = constants.K8S_API_CRD_KURYRNETWORKPOLICIES

    def __init__(self):
        super(KuryrNetworkPolicyHandler, self).__init__()
        self.os_net = clients.get_network_client()
        self.k8s = clients.get_kubernetes_client()
        self._drv_project = drivers.NetworkPolicyProjectDriver.get_instance()
        self._drv_policy = drivers.NetworkPolicyDriver.get_instance()

    def _patch_kuryrnetworkpolicy_crd(self, knp, field, data, action='replace'):
        name = knp['metadata']['name']
        LOG.debug('Patching KuryrNet CRD %s', name)
        try:
            status = self.k8s.patch_crd(field, knp['metadata']['selfLink'],
                                        data, action=action)
        except exceptions.K8sResourceNotFound:
            LOG.debug('KuryrNetworkPolicy CRD not found %s', name)
            return None
        except exceptions.K8sClientException:
            LOG.exception('Error updating KuryrNetworkPolicy CRD %s', name)
            raise

        knp['status'] = status
        return knp

    def _compare_sgs(self, a, b):
        for k in [k for k in a.keys() if k != 'id']:
            if a[k] != b[k]:
                return False
        return True

    def on_present(self, knp):
        if not knp['status'].get('securityGroupId'):
            # FIXME(dulek): Do this right, why do we have a project driver per
            #               resource?! This one expects policy, not knp, but it
            #               ignores it anyway!
            project_id = self._drv_project.get_project(knp)
            sg_id = self._drv_policy.create_security_group(knp, project_id)
            knp = self._patch_kuryrnetworkpolicy_crd(
                knp, 'status', {'securityGroupId': sg_id})
        else:
            # TODO(dulek): Check if it really exists, recreate if not.
            pass

        # First update SG rules as we want to apply updated ones
        current = knp['status']['securityGroupRules']
        required = knp['spec']['ingressSgRules'] + knp['spec']['egressSgRules']
        required = [r['security_group_rule'] for r in required]

        # FIXME(dulek): This *might* be prone to race conditions if failure
        #               happens between SG rule is created/deleted and status
        #               is annotated. We don't however need to revert on failed
        #               K8s operations - creation, deletion of SG rules and
        #               attaching or detaching SG from ports are idempotent
        #               so we can repeat them. What worries me is losing track
        #               of an update due to restart. The only way to do it
        #               would be to periodically check if what's in `status`
        #               is the reality in OpenStack API. That should be just
        #               two Neutron API calls + possible resync.
        to_add = []
        to_remove = []
        for r in required:
            if r not in current:
                to_add.append(r)

        for i, c in enumerate(current):
            if c not in required:
                to_remove.append((i, c))

        for sg_rule in to_add:
            sgr_id = driver_utils.create_security_group_rule(sg_rule)
            sg_rule['id'] = sgr_id
            knp = self._patch_kuryrnetworkpolicy_crd(
                knp, 'status', {'securityGroupRules': sg_rule}, 'add')

        # We need to remove starting from the last one in order to maintain
        # indexes.
        to_remove.reverse()

        for i, sg_rule in to_remove:
            driver_utils.delete_security_group_rule(sg_rule)
            knp = self._patch_kuryrnetworkpolicy_crd(
                knp, 'status/securityGroupRules', i, 'remove')

    def on_finalize(self, knp):
        sg_id = knp['status'].get('securityGroupId')
        if sg_id:
            self._drv_policy.delete_np_sg(sg_id)

        ns = knp['metadata']['namespace']
        name = knp['metadata']['name']
        self.k8s.patch_crd(
            'metadata/finalizers',
            f'{constants.K8S_API_POLICIES}/namespaces/{ns}/{name}',
            constants.KURYRNETWORKPOLICY_FINALIZER, action='remove')
        self.k8s.patch_crd(
            'metadata/finalizers', knp['metadata']['selfLink'],
            constants.KURYRNETWORKPOLICY_FINALIZER, action='remove')
