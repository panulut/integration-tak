"""Check that deployment overlays register a valid cluster-scoped integration."""

from pathlib import Path
import shutil
import subprocess  # nosec B404 - Render trusted repository manifests with kubectl.

import pytest
import yaml

from lib_opendefence_core.models.v1alpha1 import Integration
from opendefence_integration_tak import __version__


@pytest.mark.parametrize("overlay", ["integration", "overlays/local-dev", "overlays/production"])
def test_integration_registration(overlay: str) -> None:
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        pytest.skip("kubectl is required to render deployment manifests")
    root = Path(__file__).resolve().parents[1]
    rendered = subprocess.check_output(  # nosec B603 - Fixed command and repository paths; no shell.
        [kubectl, "kustomize", str(root / "k8s" / overlay)], text=True, timeout=30
    )
    resources = list(yaml.safe_load_all(rendered))
    assert not [
        item["metadata"]["name"]
        for item in resources
        if item["kind"] == "CustomResourceDefinition" and item["spec"]["group"] == "platform.opendefence.fi"
    ], "Core owns its shared CRDs; integration packages must not install or remove them"
    registrations = [item for item in resources if item["kind"] == "Integration"]
    assert len(registrations) == 1
    integration = Integration.model_validate(registrations[0])
    assert integration.name == "integration-tak"
    assert integration.namespace is None
    assert integration.spec.version == __version__
    assert integration.spec.extra_roles == []
    assert integration.status is None
    deployments = [item for item in resources if item["kind"] == "Deployment"]
    assert len(deployments) == 2
    assert all(item["metadata"]["namespace"] == "integration-tak" for item in deployments)
    if overlay != "integration":
        package = yaml.safe_load((root / "zarf.yaml").read_text())
        assert package["metadata"]["version"] == __version__
        flavor = overlay.removeprefix("overlays/")
        component = next(item for item in package["components"] if item.get("only", {}).get("flavor") == flavor)
        manifest_images = {
            container["image"].replace("ZARF_CONST_", "ZARF_PKG_TMPL_")
            for deployment in deployments
            for container in deployment["spec"]["template"]["spec"]["containers"]
        }
        assert manifest_images == set(component["images"])
        assert not {"API_IMAGE", "OPERATOR_IMAGE"} & {item["name"] for item in package["variables"]}


@pytest.mark.parametrize(
    "overlay",
    [
        "integration",
        "overlays/local-dev",
        "overlays/production",
    ],
)
def test_deployment_security_context(overlay: str) -> None:
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        pytest.skip("kubectl is required to render deployment manifests")

    root = Path(__file__).resolve().parents[1]
    rendered = subprocess.check_output(
        [kubectl, "kustomize", str(root / "k8s" / overlay)],
        text=True,
        timeout=30,
    )

    resources = list(yaml.safe_load_all(rendered))
    deployments = [item for item in resources if item["kind"] == "Deployment"]

    assert len(deployments) == 2

    for deployment in deployments:
        pod_spec = deployment["spec"]["template"]["spec"]

        assert pod_spec["securityContext"]["runAsNonRoot"] is True
        assert pod_spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
        assert pod_spec["serviceAccountName"]

        for container in pod_spec["containers"]:
            security = container["securityContext"]

            assert security["allowPrivilegeEscalation"] is False
            assert security["readOnlyRootFilesystem"] is True
            assert security["capabilities"]["drop"] == ["ALL"]

            resources_config = container["resources"]
            assert resources_config["requests"]["cpu"]
            assert resources_config["requests"]["memory"]
            assert resources_config["limits"]["cpu"]
            assert resources_config["limits"]["memory"]
