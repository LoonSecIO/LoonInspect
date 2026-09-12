"""The CloudFormation templates under ops/aws, read the way CloudFormation would.

pods-ingress.template.yml (#397) is the shared per-region front door for hosted pods.
What can be asserted without an AWS account is the shape the pods naming ruling
requires — one wildcard certificate, one wildcard record, a 404 default that never
forwards — and the two facts every other pod stack leans on: the idle timeout floor
the AI endpoints need, and the cluster's name. The estate-literal sweep covers every
template in the directory, not only this one: an account id or a hosted zone id typed
into a template pins the repository to one account forever.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from app.ai.adapters import DEFAULT_TIMEOUT_SECONDS

REPO = Path(__file__).resolve().parents[2]
OPS_AWS = REPO / "ops" / "aws"
INGRESS = OPS_AWS / "pods-ingress.template.yml"

# A twelve-digit run is an AWS account id however it is nested; a Z-prefixed uppercase
# run is a Route 53 hosted zone id. Both belong in a deploy parameter, never in a file.
ESTATE_LITERALS = {
    "an AWS account id": re.compile(r"\d{12}"),
    "a Route 53 hosted zone id": re.compile(r"\bZ[0-9A-Z]{9,}\b"),
}


class CfnLoader(yaml.SafeLoader):
    """SafeLoader plus CloudFormation's short tags, as their long forms."""


def _short_tag(loader, tag_suffix, node):
    name = "Fn::" + tag_suffix if tag_suffix not in ("Ref", "Condition") else tag_suffix
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
        return {name: value.split(".", 1)} if tag_suffix == "GetAtt" else {name: value}
    if isinstance(node, yaml.SequenceNode):
        return {name: loader.construct_sequence(node, deep=True)}
    return {name: loader.construct_mapping(node, deep=True)}


CfnLoader.add_multi_constructor("!", _short_tag)


def load(path: Path) -> dict:
    return yaml.load(path.read_text(), Loader=CfnLoader)


@pytest.fixture(scope="module")
def ingress() -> dict:
    return load(INGRESS)


def _of_type(template: dict, type_name: str) -> dict[str, dict]:
    return {name: r for name, r in template["Resources"].items() if r["Type"] == type_name}


def test_certificate_is_the_wildcard_validated_by_dns_in_the_zone(ingress):
    (cert,) = _of_type(ingress, "AWS::CertificateManager::Certificate").values()
    wildcard = {"Fn::Sub": "*.${PodsZoneName}"}
    assert cert["Properties"]["DomainName"] == wildcard
    assert cert["Properties"]["ValidationMethod"] == "DNS"
    (option,) = cert["Properties"]["DomainValidationOptions"]
    assert option == {"DomainName": wildcard, "HostedZoneId": {"Ref": "HostedZoneId"}}
    assert "Default" not in ingress["Parameters"]["HostedZoneId"], "a zone id is never a default"


def test_https_listener_default_is_a_fixed_404_never_a_forward(ingress):
    listener = ingress["Resources"]["HttpsListener"]["Properties"]
    assert listener["Port"] == 443 and listener["Protocol"] == "HTTPS"
    assert listener["SslPolicy"] == "ELBSecurityPolicy-TLS13-1-2-2021-06"
    assert listener["Certificates"] == [{"CertificateArn": {"Ref": "Certificate"}}]
    (action,) = listener["DefaultActions"]
    assert action["Type"] == "fixed-response"
    assert "TargetGroupArn" not in action and "ForwardConfig" not in action
    body = action["FixedResponseConfig"]
    assert body["StatusCode"] == "404" and body["ContentType"] == "text/plain"
    assert body["MessageBody"] == "No pod answers at this name."


def test_http_listener_only_redirects(ingress):
    listener = ingress["Resources"]["HttpListener"]["Properties"]
    assert listener["Port"] == 80 and listener["Protocol"] == "HTTP"
    (action,) = listener["DefaultActions"]
    assert action["Type"] == "redirect"
    assert action["RedirectConfig"]["Protocol"] == "HTTPS"
    assert action["RedirectConfig"]["Port"] == "443"
    assert action["RedirectConfig"]["StatusCode"] == "HTTP_301"
    assert "TargetGroupArn" not in action and "ForwardConfig" not in action


def test_exactly_one_record_and_it_is_the_wildcard_alias(ingress):
    records = _of_type(ingress, "AWS::Route53::RecordSet")
    assert not _of_type(ingress, "AWS::Route53::RecordSetGroup")
    (record,) = records.values()
    props = record["Properties"]
    assert props["Name"] == {"Fn::Sub": "*.${PodsZoneName}"}
    assert props["Type"] == "A"
    assert props["HostedZoneId"] == {"Ref": "HostedZoneId"}
    assert props["AliasTarget"] == {
        "DNSName": {"Fn::GetAtt": ["LoadBalancer", "DNSName"]},
        "HostedZoneId": {"Fn::GetAtt": ["LoadBalancer", "CanonicalHostedZoneID"]},
        "EvaluateTargetHealth": False,
    }
    assert "ResourceRecords" not in props and "TTL" not in props


def test_idle_timeout_floor_outlasts_the_ai_endpoints(ingress):
    parameter = ingress["Parameters"]["IdleTimeoutSeconds"]
    assert parameter["Type"] == "Number"
    # Strictly above the AI endpoints' own wall clock, read rather than restated: at equality
    # a host that never answers reaches the operator as the balancer's 504, not the app's reply.
    assert parameter["MinValue"] > DEFAULT_TIMEOUT_SECONDS
    assert parameter["Default"] >= parameter["MinValue"]
    attributes = {a["Key"]: a["Value"] for a in ingress["Resources"]["LoadBalancer"]["Properties"]["LoadBalancerAttributes"]}
    assert attributes["idle_timeout.timeout_seconds"] == {"Ref": "IdleTimeoutSeconds"}
    assert attributes["routing.http.drop_invalid_header_fields.enabled"] == "true"


def test_cluster_is_named_pods(ingress):
    (cluster,) = _of_type(ingress, "AWS::ECS::Cluster").values()
    assert cluster["Properties"]["ClusterName"] == "pods"


def test_outputs_are_plain_and_named_for_the_pod_stacks(ingress):
    outputs = ingress["Outputs"]
    assert set(outputs) == {
        "VpcId",
        "HttpsListenerArn",
        "AlbSecurityGroupId",
        "ClusterName",
        "AlbDnsName",
        "AlbCanonicalHostedZoneId",
    }
    assert not any("Export" in o for o in outputs.values()), "outputs are parameters to the pod stacks, not Exports"
    assert len(ingress["Description"]) <= 1024


@pytest.mark.parametrize("path", sorted(OPS_AWS.glob("*.yml")), ids=lambda p: p.name)
def test_no_estate_literal_in_any_template(path: Path):
    text = path.read_text()
    for what, pattern in ESTATE_LITERALS.items():
        assert not pattern.search(text), f"{path.name} carries {what}: {pattern.search(text).group(0)}"
