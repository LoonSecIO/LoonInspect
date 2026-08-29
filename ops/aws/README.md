# Running a pod on AWS

The proof that the shipped containers run somewhere other than a laptop: one
Fargate task holding the app and its Postgres sidecar, reached by its public
IP, database ephemeral. This is deliberately not the product deployment — no
load balancer, no DNS name, no persistence — it exists to answer exactly one
question ("do our images boot, migrate, and serve on AWS?") for pennies.

Two stacks:

| Stack | Template | Cadence |
|---|---|---|
| `looninspect-images` | `images.template.yml` | once per account — ECR repos + the CI push role |
| `pod-<name>` | `pod.template.yml` | per pod, disposable — cluster, task definition, service |

Everything below assumes an admin-capable AWS CLI profile and a region
exported as `AWS_REGION`.

## 1. Registries and the push role (once)

Needs the ARN of the account's existing GitHub OIDC provider (the one the
LoonInspect_Support deploys use — do not create a second):

```bash
aws iam list-open-id-connect-providers
```

```bash
aws cloudformation deploy \
  --stack-name looninspect-images \
  --template-file ops/aws/images.template.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides GitHubOidcProviderArn=arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com
```

This org's tokens carry ID-stamped subs, so pass `OidcSubjectPatterns` both
forms (the Support repo's working role trusts both), main-only:

```bash
aws cloudformation deploy ... --parameter-overrides \
  "OidcSubjectPatterns=repo:LoonSecIO/LoonInspect:ref:refs/heads/main,repo:LoonSecIO@176315697/LoonInspect@1318452984:ref:refs/heads/main"
```

## 2. Publish images

Set two **repository variables** (not secrets) in GitHub:
`AWS_ECR_PUSH_ROLE_ARN` (the stack's `PushRoleArn` output) and `AWS_REGION`.
Then merge to main — the *Publish images* workflow pushes
`looninspect:<sha>` and `looninspect-db:<sha>`. The role trusts main only, so
a dispatch from a feature branch fails at the credentials step by design.

## 3. Pod secrets (per pod)

The task reads its configuration from SSM under `/pods/<name>/`. Generated
here rather than typed, and the app password is embedded into `DATABASE_URL`
in the same shell so the two can never disagree. `127.0.0.1` is correct: the
sidecar shares the task's network namespace.

```bash
POD=loon
DB_SUPER_PW=$(openssl rand -hex 24)
DB_APP_PW=$(openssl rand -hex 24)
ADMIN_PW=$(openssl rand -base64 18)
FERNET_KEY=$(python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())")

aws ssm put-parameter --type SecureString --name /pods/$POD/db-superuser-password --value "$DB_SUPER_PW"
aws ssm put-parameter --type SecureString --name /pods/$POD/db-app-password --value "$DB_APP_PW"
aws ssm put-parameter --type SecureString --name /pods/$POD/database-url \
  --value "postgresql+asyncpg://looninspect_app:${DB_APP_PW}@127.0.0.1:5432/looninspect"
aws ssm put-parameter --type SecureString --name /pods/$POD/encryption-key --value "$FERNET_KEY"
aws ssm put-parameter --type SecureString --name /pods/$POD/initial-admin-password --value "$ADMIN_PW"
echo "admin password: $ADMIN_PW"
```

Keep the admin password somewhere real (it is also recoverable from the
parameter later); everything else is never needed by a human.

## 4. The pod

```bash
POD=loon
SHA=<the git sha the publish workflow ran on>
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
VPC=$(aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)
SUBNETS=$(aws ec2 describe-subnets --filters Name=vpc-id,Values=$VPC \
  --query 'Subnets[?MapPublicIpOnLaunch==`true`].SubnetId' --output text | tr '\t' ',')
MY_IP=$(curl -s https://checkip.amazonaws.com)

aws cloudformation deploy \
  --stack-name pod-$POD \
  --template-file ops/aws/pod.template.yml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    PodName=$POD \
    AppImageUri=$ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/looninspect:$SHA \
    DbImageUri=$ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/looninspect-db:$SHA \
    VpcId=$VPC SubnetIds=$SUBNETS \
    AllowedIngressCidr=$MY_IP/32 \
    AdminEmail=you@loonsec.io
```

## 5. Verify

The public IP hangs off the task's network interface:

```bash
POD=loon
TASK=$(aws ecs list-tasks --cluster pods-$POD --service-name $POD --query 'taskArns[0]' --output text)
ENI=$(aws ecs describe-tasks --cluster pods-$POD --tasks $TASK \
  --query "tasks[0].attachments[0].details[?name=='networkInterfaceId'].value" --output text)
IP=$(aws ec2 describe-network-interfaces --network-interface-ids $ENI \
  --query 'NetworkInterfaces[0].Association.PublicIp' --output text)
curl -ks https://$IP:8001/api/health
```

Proven means: the health endpoint answers, `https://<ip>:8001` serves the SPA
past the self-signed warning, and the admin from step 3 can sign in. Logs, if
anything disagrees:

```bash
aws logs tail /pods/$POD --follow
```

A task replacement (deploy, crash, Fargate maintenance) starts an empty
database and re-provisions the same admin — disposability is the design here,
not a bug to file.

## 6. Teardown

```bash
POD=loon
aws cloudformation delete-stack --stack-name pod-$POD
aws ssm delete-parameters --names \
  /pods/$POD/db-superuser-password /pods/$POD/db-app-password \
  /pods/$POD/database-url /pods/$POD/encryption-key /pods/$POD/initial-admin-password
```

`looninspect-images` can stay: two ECR repositories holding a few images cost
cents per month, and the next pod needs them. The pod itself, left running,
is a 0.5 vCPU / 1 GB Fargate task — roughly $0.02/hour, about $18/month.

## What the product deployment adds later (deliberately absent here)

ALB + the `*.pods.loonsec.io` ACM certificate and DNS (the pod's real name),
a database that outlives the task (RDS, or a volume story), `/app/data`
persistence for the audit log, and deploy automation beyond image push. Each
is its own decision; none is needed to prove runnability.
