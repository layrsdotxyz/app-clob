# P0 direct-trading production runtime change set

Status: `PREPARED_NOT_CREATED_NOT_EXECUTED`

This bundle changes only the measured direct-runtime candidate and its governed
startup authorization. The candidate preserves signed session-to-action equality
while accepting any syntactically valid, nonzero customer-provided Base withdrawal
destination; Privy remains authentication-only and never selects that destination.  Every other live CloudFormation parameter uses
`UsePreviousValue=true`.  The preparation performed no AWS mutation.

## Bound artifacts

- Stack: `layrs-production-direct-execution-dormant`
- Template: `deployment/layrs-direct-execution-production.template.yaml`
- Parameter file: `evidence/P0_DIRECT_TRADING_PRODUCTION_RUNTIME_PARAMETERS_20260914.json`
- Signed grant: `evidence/WRITER_GRANT_P0_TRADING_SIGNED_20260914.json`
- AMI: `ami-0c6e26a5461b89937`
- EIF SHA-256: `eb111bb115f53cac3922bb7eea2c2c6cb4b584360791a07be0594eaeab433409`
- Source: `4d141632906a2a1b55fc53666574976da0c6bb8b`
- WriterGrant commitment: `f577563b8d72afae62d168bb21bb91a79ceaf6480ac5f41a5533a0faf3a15aad`
- PCR0: `f97216859fc4cf74f7d93cfc674012a3b605a7713e4c17b4a1a5b707e35e3fb5b9d701383220297d74b4d35e7afb66fb`
- PCR1: `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`
- PCR2: `80b8ec25bb71e6bf72bd688f910c39dd1ff132e6ddf63fed20cc9b61dfa416ee5a7e98b3679db320df324ab9cd3986cc`

The parameter file contains no secret value.  The signed grant is an
authorization artifact and CloudFormation still treats its parameter as
`NoEcho`.  Existing Secrets Manager references remain unchanged and are never
resolved by this procedure.

## Read-only preflight

Run from this worktree with shell tracing disabled:

```bash
set +x
export AWS_PROFILE=predifi-root
export AWS_REGION=us-east-1
export STACK_NAME=layrs-production-direct-execution-dormant
export PARAMETER_FILE=evidence/P0_DIRECT_TRADING_PRODUCTION_RUNTIME_PARAMETERS_20260914.json

jq -e 'length == 31' "$PARAMETER_FILE"
jq -e 'all(.[]; ((.UsePreviousValue == true and (has("ParameterValue") | not)) or (has("ParameterValue") and (has("UsePreviousValue") | not))))' "$PARAMETER_FILE"

aws cloudformation validate-template \
  --region "$AWS_REGION" \
  --template-body file://deployment/layrs-direct-execution-production.template.yaml

aws ec2 describe-images \
  --region "$AWS_REGION" \
  --image-ids ami-0c6e26a5461b89937 \
  --query 'Images[0].{State:State,SourceCommit:Tags[?Key==`SourceCommit`]|[0].Value,Eif:Tags[?Key==`EifSha256`]|[0].Value,PCR0:Tags[?Key==`PCR0`]|[0].Value,PCR1:Tags[?Key==`PCR1`]|[0].Value,PCR2:Tags[?Key==`PCR2`]|[0].Value,Encrypted:BlockDeviceMappings[0].Ebs.Encrypted}'

aws cloudformation describe-stacks \
  --region "$AWS_REGION" \
  --stack-name "$STACK_NAME" \
  --query 'Stacks[0].{Status:StackStatus,Parameters:Parameters[?ParameterKey!=`WriterGrantBase64` && ParameterKey!=`ApprovedRuntimeBindingBase64`]}'

test "$(jq -r .expiresAtUnix evidence/WRITER_GRANT_P0_TRADING_SIGNED_20260914.json)" -gt "$(( $(date -u +%s) + 1800 ))"
```

Before creating the change set, re-read the current runtime status and require:

- epoch state `84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590`;
- evidence manifest `70e579f630c759258728d91cb957fa84e200674aeebd3eae5997430a62203957`;
- current WriterGrant commitment `0e778174d3fb19c4d0de1c3e32dd982570e304d697f36f573672679111dd5bc1`;
- current key-release artifact `7935bf05e48dfce5d32f5ac9ea162906e52b2fd09127383386f7b5b380845b84`;
- current immutable head sequence `5` and artifact hash
  `b3ff84fef0cd61e8af04c024a37d922fadd73ddd71153209937596a550d1156e`;
- every legacy financial writer remains desired/running `0/0`.

Any mismatch stops the rollout and requires a refreshed, exact predecessor and
baseline.  It does not authorize rewriting production state.

## Exact change-set command

This creates a reviewable change set only.  It does not execute it:

```bash
aws cloudformation create-change-set \
  --region us-east-1 \
  --stack-name layrs-production-direct-execution-dormant \
  --change-set-name p0-direct-withdrawal-4d14163-20260914 \
  --change-set-type UPDATE \
  --description 'P0 exact measured direct-trading and arbitrary-destination withdrawal runtime' \
  --template-body file://deployment/layrs-direct-execution-production.template.yaml \
  --parameters file://evidence/P0_DIRECT_TRADING_PRODUCTION_RUNTIME_PARAMETERS_20260914.json \
  --capabilities CAPABILITY_IAM

aws cloudformation wait change-set-create-complete \
  --region us-east-1 \
  --stack-name layrs-production-direct-execution-dormant \
  --change-set-name p0-direct-withdrawal-4d14163-20260914

aws cloudformation describe-change-set \
  --region us-east-1 \
  --stack-name layrs-production-direct-execution-dormant \
  --change-set-name p0-direct-withdrawal-4d14163-20260914 \
  --query '{Status:Status,ExecutionStatus:ExecutionStatus,Changes:Changes[*].ResourceChange.{Action:Action,LogicalResourceId:LogicalResourceId,ResourceType:ResourceType,Replacement:Replacement,Details:Details}}'
```

Review must reject any change outside the runtime IAM condition, launch
template/ASG replacement, and their direct dependencies.  The execution command
is intentionally separate and was not run during preparation:

```bash
aws cloudformation execute-change-set \
  --region us-east-1 \
  --stack-name layrs-production-direct-execution-dormant \
  --change-set-name p0-direct-withdrawal-4d14163-20260914
```

## Read-only post-deployment verification

```bash
aws cloudformation wait stack-update-complete \
  --region us-east-1 \
  --stack-name layrs-production-direct-execution-dormant

ASG_NAME=$(aws cloudformation describe-stack-resources \
  --region us-east-1 \
  --stack-name layrs-production-direct-execution-dormant \
  --query 'StackResources[?ResourceType==`AWS::AutoScaling::AutoScalingGroup`].PhysicalResourceId | [0]' \
  --output text)

INSTANCE_ID=$(aws autoscaling describe-auto-scaling-groups \
  --region us-east-1 \
  --auto-scaling-group-names "$ASG_NAME" \
  --query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId | [0]' \
  --output text)

aws ec2 describe-instances \
  --region us-east-1 \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].{State:State.Name,ImageId:ImageId,WriterEnabled:Tags[?Key==`WriterEnabled`]|[0].Value,TransactionModel:Tags[?Key==`TransactionModel`]|[0].Value}'

TARGET_GROUP=$(aws cloudformation describe-stacks \
  --region us-east-1 \
  --stack-name layrs-production-direct-execution-dormant \
  --query 'Stacks[0].Outputs[?OutputKey==`ReadOnlyRuntimeTargetGroupArn`].OutputValue | [0]' \
  --output text)

aws elbv2 describe-target-health \
  --region us-east-1 \
  --target-group-arn "$TARGET_GROUP" \
  --query 'TargetHealthDescriptions[].{Instance:Target.Id,State:TargetHealth.State,Reason:TargetHealth.Reason}'
```

Use SSM to issue only bounded local `GET /v1/runtime/status` and nonce-bound
`GET /v1/attestation` requests.  The status must report the exact epoch hashes,
`writerGrantCommitment=f577563b8d72afae62d168bb21bb91a79ceaf6480ac5f41a5533a0faf3a15aad`,
`writerEnabled=true`, and `admissionEnabled=true`.  Pipe the attestation JSON to:

```bash
python3 scripts/verify-direct-nitro-attestation.py \
  --expected-nonce "$NONCE" \
  --expected-pcr0 f97216859fc4cf74f7d93cfc674012a3b605a7713e4c17b4a1a5b707e35e3fb5b9d701383220297d74b4d35e7afb66fb \
  --expected-pcr1 4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493 \
  --expected-pcr2 80b8ec25bb71e6bf72bd688f910c39dd1ff132e6ddf63fed20cc9b61dfa416ee5a7e98b3679db320df324ab9cd3986cc
```

The five existing governed market registrations were reverified against this source (`verified 5 governed direct-market registrations`) and remain recorded in `evidence/P0_DIRECT_MARKET_REGISTRATIONS_SIGNED_20260914.json`.

Before market registration, independently verify that the immutable head is
still sequence `5`, balances/projection reconcile, the old ASG instance is no
longer present, and there is exactly one target runtime.  A failed recovery,
attestation, grant check, target-health check, or lineage comparison remains
fail-closed; no BFF financial route may be enabled.
