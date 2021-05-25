#!/usr/bin/env python3
# Copyright 2021 Canonical
# See LICENSE file for licensing details.

import datetime
import logging
import os
from ipaddress import IPv4Address
from pathlib import Path
from subprocess import check_output

from charms.nginx_ingress_integrator.v0.ingress import IngressRequires
from cryptography import x509
from kubernetes import kubernetes
from ops.charm import CharmBase, InstallEvent, StopEvent
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

import cert
import resources

logger = logging.getLogger(__name__)


class KubernetesDashboardCharm(CharmBase):
    """Charm the service."""

    _authed = False
    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.dashboard_pebble_ready, self._on_config_changed)
        self.framework.observe(self.on.scraper_pebble_ready, self._on_config_changed)
        self.framework.observe(self.on.stop, self._on_stop)
        self.framework.observe(self.on.delete_resources_action, self._on_delete_resources_action)

        # Basic ingress config for the relation
        ingress_config = {
            "service-hostname": "dashboard.juju",
            "service-port": 9090,
            "service-name": self.app.name,
        }
        # If there is a TLS seret provided in config, pass it to the ingress too
        if self.config["tls-secret-name"]:
            ingress_config.update({"tls-secret-name": self.config["tls-secret-name"]})

        # Initialise the Ingress library
        self.ingress = IngressRequires(self, ingress_config)

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

    def _on_stop(self, event: StopEvent) -> None:
        """Cleanup Kubernetes resources"""
        # Authenticate with the Kubernetes API
        if not self._k8s_auth():
            event.defer()
            return
        # Remove created Kubernetes resources
        r = resources.K8sDashboardResources(self)
        r.delete()

    def _on_config_changed(self, event) -> None:
        """Handle the pebble_ready event for the dashboard container"""
        # Defer the config-changed event if we do not have sufficient privileges
        if not self._k8s_auth():
            event.defer()
            return

        # Default StatefulSet needs patching for extra volume mounts. Ensure that
        # the StatefulSet is patched on each invocation.
        if not self._statefulset_patched:
            self._patch_stateful_set()
            self.unit.status = MaintenanceStatus("waiting for changes to apply")

        # Configure and start the Metrics Scraper
        self._config_scraper()
        # Configure and start the Kubernetes Dashboard
        self._config_dashboard()

        self.unit.status = ActiveStatus()

    def _config_scraper(self) -> None:
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
            f"--namespace={self.model.name}",
        ]

        # If the ingress relation is established
        if self.model.get_relation("ingress"):
            # Bind to insecure only, let the ingress handle tls termination
            cmd.extend(
                [
                    "--insecure-bind-address=0.0.0.0",
                    "--default-cert-dir=/null",
                    "--enable-insecure-login",
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
        return " ".join(cmd)

    def _on_delete_resources_action(self, event):
        """Action event handler to remove all extra kubernetes resources"""
        if self._k8s_auth():
            # Remove created Kubernetes resources
            r = resources.K8sDashboardResources(self)
            r.delete()
            event.set_results({"message": "successfully deleted kubernetes resources"})

    def _check_tls_certs(self):
        """Create a self-signed certificate for the Dashboard if required"""
        # Setup the required FQDN and Pod IP for any cert in use or to be generated
        pod_ip = IPv4Address(check_output(["unit-get", "private-address"]).decode().strip())

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
            if pod_ip in cert_san_ips and c.not_valid_after >= datetime.datetime.utcnow():
                return

        # If we get this far, the cert is either not present, or invalid
        # Set the FQDN of the certificate
        fqdn = f"{self.app.name}.{self.model.name}.svc.cluster.local"

        # Get the service IP for the auto-created kubernetes service
        api = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient())
        svc = api.read_namespaced_service(name=self.app.name, namespace=self.model.name)
        svc_ip = IPv4Address(svc.spec.cluster_ip)

        # Generate a valid self-signed certificate, set the Pod IP/Svc IP as SANs
        tls = cert.SelfSignedCert([fqdn], [pod_ip, svc_ip])
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
        s = apps_api.read_namespaced_stateful_set(name=self.app.name, namespace=self.model.name)
        # Create a volume mount that we expect to be present after patching the StatefulSet
        expected = kubernetes.client.V1VolumeMount(mount_path="/tmp", name="tmp-volume-dashboard")
        return expected in s.spec.template.spec.containers[1].volume_mounts

    def _patch_stateful_set(self) -> None:
        """Patch the StatefulSet created by Juju to include specific ServiceAccount and Secret mounts"""
        self.unit.status = MaintenanceStatus("patching StatefulSet for additional k8s permissions")
        # Get an API client
        api = kubernetes.client.AppsV1Api(kubernetes.client.ApiClient())
        r = resources.K8sDashboardResources(self)
        # Read the StatefulSet we're deployed into
        s = api.read_namespaced_stateful_set(name=self.app.name, namespace=self.model.name)
        # Add the required volumes to the StatefulSet spec
        s.spec.template.spec.volumes.extend(r.dashboard_volumes)
        # Add the required volume mounts to the Dashboard container spec
        s.spec.template.spec.containers[1].volume_mounts.extend(r.dashboard_volume_mounts)
        # Add the required volume mounts to the Scraper container spec
        s.spec.template.spec.containers[2].volume_mounts.extend(r.metrics_scraper_volume_mounts)

        # Patch the StatefulSet with our modified object
        api.patch_namespaced_stateful_set(name=self.app.name, namespace=self.model.name, body=s)
        logger.info("Patched StatefulSet to include additional volumes and mounts")

    def _k8s_auth(self):
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


if __name__ == "__main__":
    main(KubernetesDashboardCharm, use_juju_for_storage=True)
