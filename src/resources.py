# Copyright 2021 Canonical
# See LICENSE file for licensing details.
import logging

from kubernetes import kubernetes
import os
import glob

logger = logging.getLogger(__name__)


class K8sDashboardResources:
    """Class to handle the creation and deletion of those Kubernetes resources
    required by the Kubernetes Dashboard, but not automatically handled by Juju"""

    def __init__(self, charm):
        self.model = charm.model
        self.app = charm.app
        self.config = charm.config
        self.namespace = charm.namespace
        # Setup some Kubernetes API clients we'll need
        kcl = kubernetes.client.ApiClient()
        self.apps_api = kubernetes.client.AppsV1Api(kcl)
        self.core_api = kubernetes.client.CoreV1Api(kcl)
        self.auth_api = kubernetes.client.RbacAuthorizationV1Api(kcl)

    def apply(self) -> None:
        """Create the required Kubernetes resources for the dashboard"""
        # Create required Kubernetes Service Accounts
        for sa in self._service_accounts:
            svc_accounts = self.core_api.list_namespaced_service_account(
                namespace=sa["namespace"],
                field_selector=f"metadata.name={sa['body'].metadata.name}",
            )
            if not svc_accounts.items:
                self.core_api.create_namespaced_service_account(**sa)
            else:
                logger.info(
                    "service account '%s' in namespace '%s' exists, patching",
                    sa["body"].metadata.name,
                    sa["namespace"],
                )
                self.core_api.patch_namespaced_service_account(name=sa["body"].metadata.name, **sa)

        # Create Kubernetes Secrets
        for secret in self._secrets:
            s = self.core_api.list_namespaced_secret(
                namespace=secret["namespace"],
                field_selector=f"metadata.name={secret['body'].metadata.name}",
            )
            if not s.items:
                self.core_api.create_namespaced_secret(**secret)
            else:
                logger.info(
                    "secret '%s' in namespace '%s' exists, not creating",
                    secret["body"].metadata.name,
                    secret["namespace"],
                )

        # Create Kubernetes Services
        for service in self._services:
            s = self.core_api.list_namespaced_service(
                namespace=service["namespace"],
                field_selector=f"metadata.name={service['body'].metadata.name}",
            )
            if not s.items:
                self.core_api.create_namespaced_service(**service)
            else:
                logger.info(
                    "service '%s' in namespace '%s' exists, patching",
                    service["body"].metadata.name,
                    service["namespace"],
                )
                self.core_api.patch_namespaced_service(
                    name=service["body"].metadata.name, **service
                )

        # Create Kubernetes ConfigMaps
        for cm in self._configmaps:
            s = self.core_api.list_namespaced_config_map(
                namespace=cm["namespace"],
                field_selector=f"metadata.name={cm['body'].metadata.name}",
            )
            if not s.items:
                self.core_api.create_namespaced_config_map(**cm)
            else:
                logger.info(
                    "configmap '%s' in namespace '%s' exists, patching",
                    cm["body"].metadata.name,
                    cm["namespace"],
                )
                self.core_api.patch_namespaced_config_map(name=cm["body"].metadata.name, **cm)

        # Create Kubernetes Roles
        for role in self._roles:
            r = self.auth_api.list_namespaced_role(
                namespace=role["namespace"],
                field_selector=f"metadata.name={role['body'].metadata.name}",
            )
            if not r.items:
                self.auth_api.create_namespaced_role(**role)
            else:
                logger.info(
                    "role '%s' in namespace '%s' exists, patching",
                    role["body"].metadata.name,
                    role["namespace"],
                )
                self.auth_api.patch_namespaced_role(name=role["body"].metadata.name, **role)

        # Create Kubernetes Role Bindings
        for rb in self._rolebindings:
            r = self.auth_api.list_namespaced_role_binding(
                namespace=rb["namespace"],
                field_selector=f"metadata.name={rb['body'].metadata.name}",
            )
            if not r.items:
                self.auth_api.create_namespaced_role_binding(**rb)
            else:
                logger.info(
                    "role binding '%s' in namespace '%s' exists, patching",
                    rb["body"].metadata.name,
                    rb["namespace"],
                )
                self.auth_api.patch_namespaced_role_binding(name=rb["body"].metadata.name, **rb)

        # Create Kubernetes Cluster Roles
        for cr in self._clusterroles:
            r = self.auth_api.list_cluster_role(
                field_selector=f"metadata.name={cr['body'].metadata.name}",
            )
            if not r.items:
                self.auth_api.create_cluster_role(**cr)
            else:
                logger.info("cluster role '%s' exists, patching", cr["body"].metadata.name)
                self.auth_api.patch_cluster_role(name=cr["body"].metadata.name, **cr)

        # Create Kubernetes Cluster Role Bindings
        for crb in self._clusterrolebindings:
            r = self.auth_api.list_cluster_role_binding(
                field_selector=f"metadata.name={crb['body'].metadata.name}",
            )
            if not r.items:
                self.auth_api.create_cluster_role_binding(**crb)
            else:
                logger.info(
                    "cluster role binding '%s' exists, patching", crb["body"].metadata.name
                )
                self.auth_api.patch_cluster_role_binding(name=crb["body"].metadata.name, **crb)

        logger.info("Created additional Kubernetes resources")

    def delete(self) -> None:
        """Delete all of the Kubernetes resources created by the apply method"""
        # Delete service accounts
        for sa in self._service_accounts:
            self.core_api.delete_namespaced_service_account(
                namespace=sa["namespace"], name=sa["body"].metadata.name
            )
        # Delete Kubernetes secrets
        for secret in self._secrets:
            self.core_api.delete_namespaced_secret(
                namespace=secret["namespace"], name=secret["body"].metadata.name
            )
        # Delete Kubernetes services
        for service in self._services:
            self.core_api.delete_namespaced_service(
                namespace=service["namespace"], name=service["body"].metadata.name
            )
        # Delete Kubernetes configmaps
        for cm in self._configmaps:
            self.core_api.delete_namespaced_config_map(
                namespace=cm["namespace"], name=cm["body"].metadata.name
            )
        # Delete Kubernetes roles
        for role in self._roles:
            self.auth_api.delete_namespaced_role(
                namespace=role["namespace"], name=role["body"].metadata.name
            )
        # Delete Kubernetes role bindings
        for rb in self._rolebindings:
            self.auth_api.delete_namespaced_role_binding(
                namespace=rb["namespace"], name=rb["body"].metadata.name
            )
        # Delete Kubernetes cluster roles
        for cr in self._clusterroles:
            self.auth_api.delete_cluster_role(name=cr["body"].metadata.name)
        # Delete Kubernetes cluster role bindings
        for crb in self._clusterrolebindings:
            self.auth_api.delete_cluster_role_binding(name=crb["body"].metadata.name)

        logger.info("Deleted additional Kubernetes resources")

    @property
    def dashboard_volumes(self) -> dict:
        """Returns the additional volumes required by the Dashboard"""
        # Get the service account details so we can reference it's token
        service_account = self.core_api.read_namespaced_service_account(
            name="kubernetes-dashboard", namespace=self.namespace
        )
        return [
            kubernetes.client.V1Volume(
                name="kubernetes-dashboard-service-account",
                secret=kubernetes.client.V1SecretVolumeSource(
                    secret_name=service_account.secrets[0].name
                ),
            ),
            # kubernetes.client.V1Volume(
            #     name="kubernetes-dashboard-certs",
            #     secret=kubernetes.client.V1SecretVolumeSource(
            #         secret_name="kubernetes-dashboard-certs"
            #     ),
            # ),
            kubernetes.client.V1Volume(
                name="tmp-volume-metrics",
                empty_dir=kubernetes.client.V1EmptyDirVolumeSource(medium="Memory"),
            ),
            kubernetes.client.V1Volume(
                name="tmp-volume-dashboard",
                empty_dir=kubernetes.client.V1EmptyDirVolumeSource(),
            ),
        ]

    @property
    def dashboard_volume_mounts(self) -> dict:
        """Returns the additional volume mounts for the dashboard containers"""
        return [
            kubernetes.client.V1VolumeMount(mount_path="/tmp", name="tmp-volume-dashboard"),
            # kubernetes.client.V1VolumeMount(
            #     mount_path="/certs", name="kubernetes-dashboard-certs"
            # ),
            kubernetes.client.V1VolumeMount(
                mount_path="/var/run/secrets/kubernetes.io/serviceaccount",
                name="kubernetes-dashboard-service-account",
            ),
        ]

    @property
    def metrics_scraper_volume_mounts(self) -> dict:
        """Returns the additional volume mounts for the scraper containers"""
        return [
            kubernetes.client.V1VolumeMount(mount_path="/tmp", name="tmp-volume-metrics"),
            kubernetes.client.V1VolumeMount(
                mount_path="/var/run/secrets/kubernetes.io/serviceaccount",
                name="kubernetes-dashboard-service-account",
            ),
        ]

    @property
    def _service_accounts(self) -> list:
        """Return a dictionary containing parameters for the dashboard svc account"""
        return [
            {
                "namespace": self.namespace,
                "body": kubernetes.client.V1ServiceAccount(
                    api_version="v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        namespace=self.namespace,
                        name="kubernetes-dashboard",
                        labels={"app.kubernetes.io/name": self.app.name},
                    ),
                ),
            }
        ]

    @property
    def _secrets(self) -> list:
        """Return a list of secrets needed by the Kubernetes Dashboard"""
        return [
            {
                "namespace": self.namespace,
                "body": kubernetes.client.V1Secret(
                    api_version="v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        namespace=self.namespace,
                        name="kubernetes-dashboard-key-holder",
                        labels={"app.kubernetes.io/name": self.app.name},
                    ),
                    type="Opaque",
                ),
            },
            {
                "namespace": self.namespace,
                "body": kubernetes.client.V1Secret(
                    api_version="v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        namespace=self.namespace,
                        name="kubernetes-dashboard-csrf",
                        labels={"app.kubernetes.io/name": self.app.name},
                    ),
                    type="Opaque",
                    data={"csrf": ""},
                ),
            },
            # {
            #     "namespace": self.namespace,
            #     "body": kubernetes.client.V1Secret(
            #         api_version="v1",
            #         metadata=kubernetes.client.V1ObjectMeta(
            #             namespace=self.namespace,
            #             name="kubernetes-dashboard-certs",
            #             labels={"app.kubernetes.io/name": self.app.name},
            #         ),
            #         type="Opaque",
            #     ),
            # },
        ]

    @property
    def _services(self) -> list:
        """Return a list of Kubernetes services needed by the Kubernetes Dashboard"""
        # Note that this service is actually created by Juju, we are patching
        # it here to include the correct port mapping
        # TODO: Update when support improves in Juju

        return [
            {
                "namespace": self.namespace,
                "body": kubernetes.client.V1Service(
                    api_version="v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        namespace=self.namespace,
                        name=self.app.name,
                        labels={"app.kubernetes.io/name": self.app.name},
                    ),
                    spec=kubernetes.client.V1ServiceSpec(
                        ports=[
                            kubernetes.client.V1ServicePort(
                                name="dashboard-http",
                                port=80,
                                target_port=9090,
                            ),
                            kubernetes.client.V1ServicePort(
                                name="dashboard-https",
                                port=443,
                                target_port=8443,
                            ),
                        ],
                        selector={"app.kubernetes.io/name": self.app.name},
                    ),
                ),
            },
            {
                "namespace": self.namespace,
                "body": kubernetes.client.V1Service(
                    api_version="v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        namespace=self.namespace,
                        name="dashboard-metrics-scraper",
                        labels={"app.kubernetes.io/name": self.app.name},
                    ),
                    spec=kubernetes.client.V1ServiceSpec(
                        ports=[
                            kubernetes.client.V1ServicePort(
                                name="metrics-scraper", port=8000, target_port=8000
                            )
                        ],
                        selector={"app.kubernetes.io/name": self.app.name},
                    ),
                ),
            },
        ]

    def _loadfile(self, file_name):
        with open(file_name, 'r') as f:
            data = f.read()
            f.close()
            return data

    @property
    def _configmaps(self) -> list:
        """Return a list of ConfigMaps needed by the Kubernetes Dashboard"""
        dicts = {}
        for filePath in glob.glob("src/files/scripts/*.*"):
            fileData = self._loadfile(filePath)
            fileName = os.path.basename(filePath)
            dicts[fileName] = fileData
        return [
            {
                "namespace": self.namespace,
                "body": kubernetes.client.V1ConfigMap(
                    api_version="v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        namespace=self.namespace,
                        name="kubernetes-dashboard-settings",
                        labels={
                            "app.kubernetes.io/name": self.app.name,
                            "app": self.app.name
                        },
                    ),
                    data=dicts,
                ),
            }
        ]

    @property
    def _roles(self) -> list:
        """Return a list of Roles required by the Kubernetes Dsahboard"""
        return [
            {
                "namespace": self.namespace,
                "body": kubernetes.client.V1Role(
                    api_version="rbac.authorization.k8s.io/v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        namespace=self.namespace,
                        name="kubernetes-dashboard",
                        labels={"app.kubernetes.io/name": self.app.name},
                    ),
                    rules=[
                        # Allow Dashboard to get, update and delete Dashboard exclusive secrets.
                        kubernetes.client.V1PolicyRule(
                            api_groups=[""],
                            resources=["secrets"],
                            resource_names=[
                                "kubernetes-dashboard-key-holder",
                                "kubernetes-dashboard-certs",
                                "kubernetes-dashboard-csrf",
                            ],
                            verbs=["get", "update", "delete"],
                        ),
                        # Allow Dashboard to update 'kubernetes-dashboard-settings' config map.
                        kubernetes.client.V1PolicyRule(
                            api_groups=[""],
                            resources=["configmaps"],
                            resource_names=["kubernetes-dashboard-settings"],
                            verbs=["get", "update"],
                        ),
                        # Allow Dashboard to get metrics.
                        kubernetes.client.V1PolicyRule(
                            api_groups=[""],
                            resources=["services"],
                            resource_names=["heapster", "dashboard-metrics-scraper"],
                            verbs=["proxy"],
                        ),
                        kubernetes.client.V1PolicyRule(
                            api_groups=[""],
                            resources=["services/proxy"],
                            resource_names=[
                                "heapster",
                                "http:heapster:",
                                "https:heapster:",
                                "dashboard-metrics-scraper",
                                "http:dashboard-metrics-scraper",
                            ],
                            verbs=["get"],
                        ),
                    ],
                ),
            }
        ]

    @property
    def _rolebindings(self) -> list:
        """Return a list of Role Bindings required by the Kubernetes Dsahboard"""
        return [
            {
                "namespace": self.namespace,
                "body": kubernetes.client.V1RoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        namespace=self.namespace,
                        name="kubernetes-dashboard",
                        labels={"app.kubernetes.io/name": self.app.name},
                    ),
                    role_ref=kubernetes.client.V1RoleRef(
                        api_group="rbac.authorization.k8s.io",
                        kind="Role",
                        name="kubernetes-dashboard",
                    ),
                    subjects=[
                        kubernetes.client.V1Subject(
                            kind="ServiceAccount",
                            name="kubernetes-dashboard",
                            namespace=self.namespace,
                        )
                    ],
                ),
            }
        ]

    @property
    def _clusterroles(self) -> list:
        """Return a list of Cluster Roles required by the Kubernetes Dsahboard"""
        return [
            {
                "body": kubernetes.client.V1ClusterRole(
                    api_version="rbac.authorization.k8s.io/v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="kubernetes-dashboard",
                        labels={"app.kubernetes.io/name": self.app.name},
                    ),
                    rules=[
                        # Allow Metrics Scraper to get metrics from the Metrics server
                        kubernetes.client.V1PolicyRule(
                            api_groups=["metrics.k8s.io"],
                            resources=["pods", "nodes"],
                            verbs=["get", "list", "watch"],
                        ),
                    ],
                )
            }
        ]

    @property
    def _clusterrolebindings(self) -> list:
        """Return a list of Cluster Role Bindings required by the Kubernetes Dsahboard"""
        return [
            {
                "body": kubernetes.client.V1ClusterRoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="kubernetes-dashboard",
                        labels={"app.kubernetes.io/name": self.app.name},
                    ),
                    role_ref=kubernetes.client.V1RoleRef(
                        api_group="rbac.authorization.k8s.io",
                        kind="ClusterRole",
                        name="kubernetes-dashboard",
                    ),
                    subjects=[
                        kubernetes.client.V1Subject(
                            kind="ServiceAccount",
                            name="kubernetes-dashboard",
                            namespace=self.namespace,
                        )
                    ],
                )
            }
        ]
