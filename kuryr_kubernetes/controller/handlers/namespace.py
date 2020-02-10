# Copyright 2018 Red Hat, Inc.
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
from kuryr_kubernetes.controller.drivers import base as drivers
from kuryr_kubernetes import exceptions
from kuryr_kubernetes.handlers import k8s_base
from kuryr_kubernetes import utils


LOG = logging.getLogger(__name__)


class NamespaceHandler(k8s_base.ResourceEventHandler):
    OBJECT_KIND = constants.K8S_OBJ_NAMESPACE
    OBJECT_WATCH_PATH = constants.K8S_API_NAMESPACES

    def __init__(self):
        super(NamespaceHandler, self).__init__()
        self._drv_project = drivers.NamespaceProjectDriver.get_instance()
        self._upgrade_crds()

    def _upgrade_crds(self):
        k8s = clients.get_kubernetes_client()
        try:
            net_crds = k8s.get(constants.K8S_API_CRD_KURYRNETS)
            namespaces = k8s.get(constants.K8S_API_NAMESPACES)
        except exceptions.K8sResourceNotFound:
            return
        except exceptions.K8sClientException:
            LOG.warning("Error retriving namespace information")
            raise

        ns_dict = {'ns-' + ns['metadata']['name']: ns
                   for ns in namespaces.get('items')}

        for net_crd in net_crds.get('items'):
            try:
                ns = ns_dict[net_crd['metadata']['name']]
            except KeyError:
                # Note(ltomasbo): The CRD does not have an associated
                # namespace. It must be deleted
                LOG.debug('No namespace associated, deleting kuryrnet crd: '
                          '%s', net_crd)
            else:
                try:
                    ns_net_annotations = ns['metadata']['annotations'][
                        constants.K8S_ANNOTATION_NET_CRD]
                except KeyError:
                    LOG.debug('Namespace associated is not annotated: %s', ns)
                else:
                    LOG.debug('Removing annotation: %', ns_net_annotations)
                    k8s.remove_annotations(ns['metadata']['selfLink'],
                                           constants.K8S_ANNOTATION_NET_CRD)
            try:
                k8s.delete(net_crd['metadata']['selfLink'])
            except exceptions.K8sResourceNotFound:
                LOG.debug('Kuryrnet object already deleted: %s', net_crd)

    def on_present(self, namespace):
        ns_labels = namespace['metadata'].get('labels', {})
        ns_name = namespace['metadata']['name']
        kns_name = 'ns-' + ns_name
        kns_crd = self._get_kns_crd(kns_name, ns_name)
        if kns_crd:
            LOG.debug("Previous CRD existing at the new namespace.")
            self._update_labels(kns_crd, ns_labels)
            return

        # KuryrNetwork CRD does not exist, needs to be created
        try:
            ns_annotations = namespace['metadata']['annotations']
            net_crd_id = ns_annotations[constants.K8S_ANNOTATION_NETWORK_CRD]
            LOG.debug('KuryrNetwork CRD associated to namespace is %s',
                      net_crd_id)
        except KeyError:
            try:
                self._set_net_crd(namespace, kns_name)
            except exceptions.K8sResourceNotFound:
                LOG.debug("Namespace not found, it may have been deleted: %s",
                          namespace)
                return
            except exceptions.K8sClientException:
                LOG.exception("Kubernetes Client Exception.")
                raise exceptions.ResourceNotReady(namespace)
        try:
            self._add_kuryrnet_crd(ns_name, kns_name, ns_labels)
        except exceptions.K8sClientException:
            LOG.exception("Kuryrnetwork CRD creation failed.")
            raise exceptions.ResourceNotReady(namespace)

    def on_deleted(self, namespace):
        LOG.debug("Deleting namespace: %s", namespace)
        ns_name = namespace['metadata']['name']
        kns_name = 'ns-' + ns_name
        kns_crd = self._get_kns_crd(kns_name, ns_name)

        if not kns_crd:
            LOG.warning("This should not happen. Probably this event is "
                        "processed twice due to a restart or etcd is not "
                        "in sync")
            # NOTE(ltomasbo): We should rely on etcd properly behaving, so
            # we are returning here to prevent duplicated events processing
            # but not to prevent etcd failures.
            return

        kns_name = kns_crd['metadata']['name']
        ns = kns_crd['metadata']['namespace']
        self._del_kuryrnet_crd(kns_name, ns)

    def _update_labels(self, kns_crd, ns_labels):
        kns_status = kns_crd.get('status')
        if kns_status:
            kns_crd_labels = kns_crd['status'].get('nsLabels', {})
            if kns_crd_labels == ns_labels:
                # Labels are already up to date, nothing to do
                return

        kubernetes = clients.get_kubernetes_client()
        LOG.debug('Patching KuryrNetwork CRD %s', kns_crd)
        try:
            kubernetes.patch_crd('spec', kns_crd['metadata']['selfLink'],
                                 {'nsLabels': ns_labels})
        except exceptions.K8sResourceNotFound:
            LOG.debug('KuryrNetwork CRD not found %s', kns_crd)
        except exceptions.K8sClientException:
            LOG.exception('Error updating kuryrnetwork CRD %s', kns_crd)
            raise

    def _get_kns_crd(self, kns_name, namespace):
        k8s = clients.get_kubernetes_client()
        try:
            kuryrnet_crd = k8s.get('{}/{}/kuryrnetworks/{}'.format(
                constants.K8S_API_CRD_NAMESPACES, namespace,
                kns_name))
        except exceptions.K8sResourceNotFound:
            return None
        except exceptions.K8sClientException:
            LOG.exception("Kubernetes Client Exception.")
            raise
        return kuryrnet_crd

    def _set_net_crd(self, namespace, kns_name):
        LOG.debug("Setting CRD annotations: %s", kns_name)
        k8s = clients.get_kubernetes_client()
        k8s.annotate(namespace['metadata']['selfLink'],
                     {constants.K8S_ANNOTATION_NETWORK_CRD: kns_name},
                     resource_version=namespace['metadata']['resourceVersion'])

    def _add_kuryrnet_crd(self, namespace, kns_name, ns_labels):
        project_id = self._drv_project.get_project(namespace)
        kubernetes = clients.get_kubernetes_client()

        kns_crd = {
            'apiVersion': 'openstack.org/v1',
            'kind': 'KuryrNetwork',
            'metadata': {
                'name': kns_name,
                'finalizers': [constants.KURYRNETWORK_FINALIZER]
            },
            'spec': {
                'nsName': namespace,
                'projectId': project_id,
                'nsLabels': ns_labels,
            }
        }
        try:
            kubernetes.post('{}/{}/kuryrnetworks'.format(
                constants.K8S_API_CRD_NAMESPACES, namespace), kns_crd)
        except exceptions.K8sClientException:
            LOG.exception("Kubernetes Client Exception creating kuryrnetwork "
                          "CRD.")
            raise

    def _del_kuryrnet_crd(self, kns_name, namespace):
        kubernetes = clients.get_kubernetes_client()
        try:
            kubernetes.delete('{}/{}/kuryrnetworks/{}'.format(
                constants.K8S_API_CRD_NAMESPACES, namespace, kns_name))
        except exceptions.K8sResourceNotFound:
            LOG.debug("KuryrNetwork CRD not found: %s", kns_name)
        except exceptions.K8sClientException:
            LOG.exception("Kubernetes Client Exception deleting kuryrnetwork "
                          "CRD.")
            raise

    def is_ready(self, quota):
        if not utils.has_kuryr_crd(constants.K8S_API_CRD_KURYRNETS):
            return False
        return self._check_quota(quota)

    def _check_quota(self, quota):
        resources = ('subnets', 'networks', 'security_groups')

        for resource in resources:
            resource_quota = quota[resource]
            if utils.has_limit(resource_quota):
                if not utils.is_available(resource, resource_quota):
                    return False
        return True
