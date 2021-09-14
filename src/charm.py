#!/usr/bin/env python3
# Copyright 2021 Canonical
# See LICENSE file for licensing details.

import datetime
import logging
import os
from ipaddress import IPv4Address
from pathlib import Path
from subprocess import check_output
from typing import Optional

from cryptography import x509
from kubernetes import kubernetes
from ops.charm import CharmBase, InstallEvent, RemoveEvent
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus
from ops.pebble import ConnectionError

import cert
import resources

logger = logging.getLogger(__name__)

# Reduce the log output from the Kubernetes library
logging.getLogger("kubernetes").setLevel(logging.INFO)


class KubernetesDashboardCharm(CharmBase):
    """Charm the service."""

    _authed = False
    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(self.on.delete_resources_action, self._on_delete_resources_action)

        self._stored.set_default(dashboard_cmd="")

    def _on_install(self, event: InstallEvent) -> None:
        """Handle the install event, create Kubernetes resources"""
        if not self._k8s_auth():
            event.defer()
            return
        self.unit.status = MaintenanceStatus("creating k8s resources")
        # Create the Kubernetes resources needed for the Dashboard
        r = resources.K8sDashboardResources(self)
        r.apply()

    def _on_remove(self, event: RemoveEvent) -> None:
        """Cleanup Kubernetes resources"""
        # Authenticate with the Kubernetes API
        if not self._k8s_auth():
            event.defer()
            return
        # Remove created Kubernetes resources
        r = resources.K8sDashboardResources(self)
        r.delete()

    def _on_config_changed(self, event) -> None:
        # Defer the config-changed event if we do not have sufficient privileges
        if not self._k8s_auth():
            event.defer()
            return

        # Default StatefulSet needs patching for extra volume mounts. Ensure that
        # the StatefulSet is patched on each invocation.
        if not self._statefulset_patched:
            self._patch_stateful_set()
            self.unit.status = MaintenanceStatus("waiting for changes to apply")

        try:
            # Configure and start the Metrics Scraper
            self._config_scraper()
            # Configure and start the Kubernetes Dashboard
            self._config_dashboard()

            v1 = kubernetes.client.CoreV1Api()
            pod_list = v1.list_namespaced_pod("kube-system")
            for pod in pod_list.items:
                print("%s\t%s\t%s" % (pod.metadata.name,
                                      pod.status.phase,
                                      pod.status.pod_ip))
        except ConnectionError:
            logger.info("pebble socket not available, deferring config-changed")
            event.defer()
            return

        self.unit.status = ActiveStatus()

    def _config_scraper(self) -> dict:
        """Configure Pebble to start the Kubernetes Metrics Scraper"""
        # Define a simple layer
        layer = {
            "services": {"scraper": {"override": "replace", "command": "/metrics-sidecar"}},
        }
        # Add a Pebble config layer to the scraper container
        container = self.unit.get_container("scraper")
        container.add_layer("scraper", layer, combine=True)
        # Check if the scraper service is already running and start it if not
        if not container.get_service("scraper").is_running():
            container.start("scraper")
            logger.info("Scraper service started")

    def _config_dashboard(self) -> None:
        """Configure Pebble to start the Kubernetes Dashboard"""
        # Generate a command for the dashboard
        cmd = self._dashboard_cmd()
        # Check if anything has changed in the layer
        if cmd != self._stored.dashboard_cmd:
            # Add a Pebble config layer to the dashboard container
            container = self.unit.get_container("dashboard")
            # Create a new layer
            layer = {
                "services": {"dashboard": {"override": "replace", "command": cmd}},
            }
            container.add_layer("dashboard", layer, combine=True)
            # Store the command used in the StoredState
            self._stored.dashboard_cmd = cmd

            # Check if the dashboard service is already running and start it if not
            if container.get_service("dashboard").is_running():
                container.stop("dashboard")
                logger.info("Dashboard service stopped")

            # Check if we're running on HTTPS or HTTP
            if not self.config["bind-insecure"]:
                # Validate or generate TLS certs
                self._check_tls_certs()

            logger.debug("Starting Dashboard with command: %s", cmd)
            container.start("dashboard")
            logger.info("Dashboard service started")

    def _dashboard_cmd(self) -> str:
        """Build a command to start the Kubernetes Dashboard based on config"""
        # Base command and arguments
        cmd = [
            "/dashboard",
            "--bind-address=0.0.0.0",
            "--sidecar-host=http://localhost:8000",
            f"--namespace={self.namespace}",
        ]

        if self.config["bind-insecure"]:
            cmd.extend(
                [
                    "--insecure-bind-address=0.0.0.0",
                    "--default-cert-dir=/null",
                ]
            )
        else:
            cmd.extend(
                [
                    "--default-cert-dir=/certs",
                    "--tls-cert-file=tls.crt",
                    "--tls-key-file=tls.key",
                ]
            )
        # TODO: Add "--enable-insecure-login", when relation is made
        return " ".join(cmd)

    def _on_delete_resources_action(self, event) -> None:
        """Action event handler to remove all extra kubernetes resources"""
        if self._k8s_auth():
            # Remove created Kubernetes resources
            r = resources.K8sDashboardResources(self)
            r.delete()
            event.set_results({"message": "successfully deleted kubernetes resources"})

    def _check_tls_certs(self) -> None:
        """Create a self-signed certificate for the Dashboard if required"""
        # TODO: Add a branch here for if a secret is specified in config
        # Make the directory we'll use for certs if it doesn't exist
        container = self.unit.get_container("dashboard")
        container.make_dir("/certs", make_parents=True)

        if "tls.crt" in [x.name for x in container.list_files("/certs")]:
            # Pull the tls.crt file from the workload container
            file = container.pull("/certs/tls.crt")
            # Create an x509 Certificate object with the contents of the file
            c = x509.load_pem_x509_certificate(file.read().encode())
            # Get the list of IP Addresses in the SAN field
            cert_san_ips = c.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.IPAddress)
            # If the cert is valid and pod IP is already in the cert, we're good
            if self.pod_ip in cert_san_ips and c.not_valid_after >= datetime.datetime.utcnow():
                return

        # If we get this far, the cert is either not present, or invalid
        # Set the FQDN of the certificate
        fqdn = f"{self.app.name}.{self.namespace}.svc.cluster.local"

        # Get the service IP for the auto-created kubernetes service
        api = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient())
        svc = api.read_namespaced_service(name=self.app.name, namespace=self.namespace)
        svc_ip = IPv4Address(svc.spec.cluster_ip)

        # Generate a valid self-signed certificate, set the Pod IP/Svc IP as SANs
        tls = cert.SelfSignedCert([fqdn], [self.pod_ip, svc_ip])
        # Write the generated certificate and key to file
        container.push("/certs/tls.crt", tls.cert)
        container.push("/certs/tls.key", tls.key)
        logger.info("New self-signed TLS certificate generated for the Kubernetes Dashboard")

    @property
    def _statefulset_patched(self) -> bool:
        """Slightly naive check to see if the StatefulSet has already been patched"""
        # Get an API client
        apps_api = kubernetes.client.AppsV1Api(kubernetes.client.ApiClient())
        # Get the StatefulSet for the deployed application
        s = apps_api.read_namespaced_stateful_set(name=self.app.name, namespace=self.namespace)
        # Create a volume mount that we expect to be present after patching the StatefulSet
        expected = kubernetes.client.V1VolumeMount(mount_path="/tmp", name="tmp-volume-dashboard")
        return expected in s.spec.template.spec.containers[1].volume_mounts

    def _patch_stateful_set(self) -> None:
        """Patch the StatefulSet to include specific ServiceAccount and Secret mounts"""
        self.unit.status = MaintenanceStatus("patching StatefulSet for additional k8s permissions")
        # Get an API client
        api = kubernetes.client.AppsV1Api(kubernetes.client.ApiClient())
        r = resources.K8sDashboardResources(self)
        # Read the StatefulSet we're deployed into
        s = api.read_namespaced_stateful_set(name=self.app.name, namespace=self.namespace)
        # Add the required volumes to the StatefulSet spec
        s.spec.template.spec.volumes.extend(r.dashboard_volumes)
        # Add the required volume mounts to the Dashboard container spec
        s.spec.template.spec.containers[1].volume_mounts.extend(r.dashboard_volume_mounts)
        # Add the required volume mounts to the Scraper container spec
        s.spec.template.spec.containers[2].volume_mounts.extend(r.metrics_scraper_volume_mounts)

        new_init = kubernetes.client.V1Container(
                name  = "mme-load-sctp-module",
                command = ["bash", "-xc"],
                args = ["if chroot /mnt/host-rootfs modinfo nf_conntrack_proto_sctp > /dev/null 2>&1; then chroot /mnt/host-rootfs modprobe nf_conntrack_proto_sctp; fi; chroot /mnt/host-rootfs modprobe tipc"],
                image = "docker.io/omecproject/pod-init:1.0.0",
                image_pull_policy = "IfNotPresent",
                security_context = kubernetes.client.V1SecurityContext(
                    privileged = True,
                    run_as_user = 0,
                ),
                volume_mounts = kubernetes.client.V1VolumeMount(
                    mount_path="/mnt/host-rootfs",
                    name="host-rootfs",
                ),
        )


        s.spec.template.spec.init_containers.append(new_init)

        sctp_volume=kubernetes.client.V1Volume(
                name="host-rootfs",
                host_path=kubernetes.client.V1HostPathVolumeSource(path="/"),
        )

        s.spec.template.spec.volumes.append(sctp_volume)


        # Patch the StatefulSet with our modified object
        api.patch_namespaced_stateful_set(name=self.app.name, namespace=self.namespace, body=s)
        logger.info("Patched StatefulSet to include additional volumes and mounts")

    def _k8s_auth(self) -> bool:
        """Authenticate to kubernetes."""
        if self._authed:
            return True
        # Remove os.environ.update when lp:1892255 is FIX_RELEASED.
        os.environ.update(
            dict(
                e.split("=")
                for e in Path("/proc/1/environ").read_text().split("\x00")
                if "KUBERNETES_SERVICE" in e
            )
        )
        # Authenticate against the Kubernetes API using a mounted ServiceAccount token
        kubernetes.config.load_incluster_config()
        # Test the service account we've got for sufficient perms
        auth_api = kubernetes.client.RbacAuthorizationV1Api(kubernetes.client.ApiClient())

        try:
            auth_api.list_cluster_role()
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 403:
                # If we can't read a cluster role, we don't have enough permissions
                self.unit.status = BlockedStatus("Run juju trust on this application to continue")
                return False
            else:
                raise e

        self._authed = True
        return True

    @property
    def namespace(self) -> str:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r") as f:
            return f.read().strip()

    @property
    def pod_ip(self) -> Optional[IPv4Address]:
        return IPv4Address(check_output(["unit-get", "private-address"]).decode().strip())


if __name__ == "__main__":
    main(KubernetesDashboardCharm, use_juju_for_storage=True)
