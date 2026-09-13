"""The CloudFormation templates under ops/aws, read the way CloudFormation would.

pods-ingress.template.yml (#397) is the shared per-region front door for hosted pods.
What can be asserted without an AWS account is the shape the pods naming ruling
requires — one wildcard certificate, one wildcard record, a 404 default that never
forwards — and the two facts every other pod stack leans on: the idle timeout floor
the AI endpoints need, and the cluster's name. The estate-literal sweep covers every
template in the directory, not only this one: an account id or a hosted zone id typed
into a template pins the repository to one account forever.

pod-data.template.yml (#398), the per-pod stack that outlives every deploy, is pinned
where drift would lose or expose a pod's data: the database, the secrets, the security
groups that admit only the pod's own task, and what survives the stack's deletion.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from app.ai.adapters import DEFAULT_TIMEOUT_SECONDS

REPO = Path(__file__).resolve().parents[2]
OPS_AWS = REPO / "ops" / "aws"
INGRESS = OPS_AWS / "pods-ingress.template.yml"
POD_DATA = OPS_AWS / "pod-data.template.yml"

# The pods naming ruling (2026-08-28). ingress-<anything> is PodName's pattern's to refuse.
RESERVED_POD_NAMES = {
    *("login", "admin", "api", "sso", "billing", "www", "mail", "secure"),
    *("us", "eu", "emea", "apac", "ingress", "loon", "demo", "try", "dast", "staging"),
}

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


@pytest.fixture(scope="module")
def pod_data() -> dict:
    return load(POD_DATA)


def test_database_is_private_encrypted_protected_and_its_master_password_rds_managed(pod_data):
    (db,) = _of_type(pod_data, "AWS::RDS::DBInstance").values()
    props = db["Properties"]
    assert props["PubliclyAccessible"] is False
    assert props["StorageEncrypted"] is True
    assert props["DeletionProtection"] is True
    assert db["DeletionPolicy"] == "Snapshot" and db["UpdateReplacePolicy"] == "Snapshot"
    assert (props["Engine"], props["EngineVersion"]) == ("postgres", "17")
    assert props["VPCSecurityGroups"] == [{"Fn::GetAtt": ["DbSecurityGroup", "GroupId"]}]
    assert props["ManageMasterUserPassword"] is True and "MasterUserPassword" not in props
    assert not [p for p in pod_data["Parameters"] if re.search("password|secret", p, re.IGNORECASE)]
    assert pod_data["Outputs"]["MasterSecretArn"]["Value"] == {"Fn::GetAtt": ["Database", "MasterUserSecret.SecretArn"]}


def test_app_role_secret_is_generated_without_punctuation(pod_data):
    (secret,) = _of_type(pod_data, "AWS::SecretsManager::Secret").values()
    props = secret["Properties"]
    assert props["Name"] == {"Fn::Sub": "pods/${PodName}/db-app"}
    assert "SecretString" not in props
    generate = props["GenerateSecretString"]
    # URL-safe, so no '%' can ever reach Alembic's config parser (backend/migrations/env.py).
    assert generate["ExcludePunctuation"] is True
    assert json.loads(generate["SecretStringTemplate"]) == {"username": "looninspect_app"}
    assert generate["GenerateStringKey"] == "password" and generate["PasswordLength"] >= 32


def test_pod_name_is_at_most_28_characters_and_never_an_ingress_name(pod_data):
    parameter = pod_data["Parameters"]["PodName"]
    assert "Default" not in parameter, "every pod names itself"
    pattern = re.compile(parameter["AllowedPattern"])
    # pod-<name> is the compute stack's target group name, and ELBv2 caps those at 32.
    assert pattern.fullmatch("a" * 28) and not pattern.fullmatch("a" * 29)
    for name in ("dogtreats", "acme-2", "x", "ingress"):  # the bare word is the Rule's to refuse
        assert pattern.fullmatch(name), name
    for name in ("ingress-eu", "Dogtreats", "2pods", "pod-", "two--hyphens", ""):
        assert not pattern.fullmatch(name), name


def test_reserved_name_rule_lists_every_word_from_the_naming_ruling(pod_data):
    (assertion,) = pod_data["Rules"]["PodNameIsNotReserved"]["Assertions"]
    (contains,) = assertion["Assert"]["Fn::Not"]
    words, value = contains["Fn::Contains"]
    assert value == {"Ref": "PodName"}
    assert sorted(words) == sorted(RESERVED_POD_NAMES)
    for word in RESERVED_POD_NAMES:
        assert re.search(rf"\b{word}\b", assertion["AssertDescription"]), f"the refusal does not name {word}"


@pytest.mark.parametrize(
    ("group", "port", "source"),
    [
        ("TaskSecurityGroup", 8001, {"Ref": "AlbSecurityGroupId"}),
        ("DbSecurityGroup", 5432, {"Fn::GetAtt": ["TaskSecurityGroup", "GroupId"]}),
        ("EfsSecurityGroup", 2049, {"Fn::GetAtt": ["TaskSecurityGroup", "GroupId"]}),
    ],
)
def test_each_security_group_admits_one_port_from_one_group_never_a_cidr(pod_data, group, port, source):
    assert not _of_type(pod_data, "AWS::EC2::SecurityGroupIngress"), "every rule is inline, where this test reads it"
    (rule,) = pod_data["Resources"][group]["Properties"]["SecurityGroupIngress"]
    assert rule == {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "SourceSecurityGroupId": source}
    assert pod_data["Parameters"]["AlbSecurityGroupId"]["Type"] == "AWS::EC2::SecurityGroup::Id"


def test_file_system_is_encrypted_refuses_plain_mounts_and_outlives_the_stack(pod_data):
    fs = pod_data["Resources"]["FileSystem"]
    assert fs["DeletionPolicy"] == "RetainExceptOnCreate" and fs["UpdateReplacePolicy"] == "Retain"
    assert fs["Properties"]["Encrypted"] is True
    # One Deny, no Allow: any policy drops EFS's default allow-all, so a mount must be IAM-authorised.
    (statement,) = fs["Properties"]["FileSystemPolicy"]["Statement"]
    assert (statement["Effect"], statement["Action"]) == ("Deny", "*")
    assert statement["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    targets = [t["Properties"] for t in _of_type(pod_data, "AWS::EFS::MountTarget").values()]
    assert sorted(t["SubnetId"]["Fn::Select"][0] for t in targets) == [0, 1]
    assert all(t["SecurityGroups"] == [{"Fn::GetAtt": ["EfsSecurityGroup", "GroupId"]}] for t in targets)


def test_access_point_writes_as_the_images_own_user(pod_data):
    uid, gid = re.search(r"useradd --uid (\d+) --gid (\d+)", (REPO / "Dockerfile").read_text()).groups()
    assert (uid, gid) == ("10001", "10001")
    (access_point,) = _of_type(pod_data, "AWS::EFS::AccessPoint").values()
    props = access_point["Properties"]
    assert props["PosixUser"] == {"Uid": uid, "Gid": gid}
    assert props["RootDirectory"]["CreationInfo"] == {"OwnerUid": uid, "OwnerGid": gid, "Permissions": "0700"}


def test_log_group_keeps_30_days_by_default_and_outlives_the_stack(pod_data):
    group = pod_data["Resources"]["LogGroup"]
    assert group["DeletionPolicy"] == "RetainExceptOnCreate" and group["UpdateReplacePolicy"] == "Retain"
    assert group["Properties"]["RetentionInDays"] == {"Ref": "LogRetentionDays"}
    assert pod_data["Parameters"]["LogRetentionDays"]["Default"] == 30


def test_pod_data_outputs_are_plain_and_named_for_the_compute_stack(pod_data):
    outputs = pod_data["Outputs"]
    names = "DbEndpointAddress DbEndpointPort MasterSecretArn AppRoleSecretArn FileSystemId AccessPointId AccessPointArn"
    assert set(outputs) == {*names.split(), "TaskSecurityGroupId", "LogGroupName"}
    assert not any("Export" in o for o in outputs.values()), "outputs are parameters to the compute stack, not Exports"
    assert len(pod_data["Description"]) <= 1024


@pytest.mark.parametrize("path", sorted(OPS_AWS.glob("*.yml")), ids=lambda p: p.name)
def test_no_estate_literal_in_any_template(path: Path):
    text = path.read_text()
    for what, pattern in ESTATE_LITERALS.items():
        assert not pattern.search(text), f"{path.name} carries {what}: {pattern.search(text).group(0)}"
