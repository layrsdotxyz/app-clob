const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
const {execFileSync}=require('node:child_process');

const template=readFileSync(join(__dirname,'..','layrs-direct-execution-production.template.yaml'),'utf8');

test('v71 controls remain explicit and default to the v70 bridge',()=>{
  assert.match(template,/PersistenceFormat:\n    Type: String\n    Default: v70\n    AllowedValues: \[v70, v71-hot, v70-rollback-baseline\]/);
  assert.match(template,/V71ShadowRunId:\n    Type: String\n    Default: ''/);
  assert.match(template,/V71AutoPromote:\n    Type: String\n    Default: 'false'/);
  assert.match(template,/V70RollbackPrefix:\n    Type: String\n    Default: ''/);
});

test('parent receives only the selected persistence controls',()=>{
  assert.ok(template.includes('"LAYRS_DIRECT_PERSISTENCE_FORMAT": "${PersistenceFormat}"'));
  assert.ok(template.includes('if "${V71ShadowRunId}":'));
  assert.ok(template.includes('values["LAYRS_DIRECT_V71_SHADOW_RUN_ID"] = "${V71ShadowRunId}"'));
  assert.ok(template.includes('if "${V71AutoPromote}" == "true":'));
  assert.ok(template.includes('values["LAYRS_DIRECT_V71_AUTO_PROMOTE"] = "true"'));
  assert.ok(template.includes('if "${V70RollbackPrefix}":'));
  assert.ok(template.includes('values["LAYRS_DIRECT_V70_ROLLBACK_PREFIX"] = "${V70RollbackPrefix}"'));
  assert.ok(!template.includes('DURABLE_COMMAND'));
});

test('USDC subsidy cap comes from the hash-pinned Phase-1 configuration and is fixed at 50,000',()=>{
  assert.ok(template.includes('UsdcMaximumSubsidyAtomic: { Type: Number, Default: 50000, AllowedValues: [50000] }'));
  assert.ok(template.includes("!If [UsdcCustodyActive, !Ref UsdcPhase1ConfigurationSecretArn, !Ref 'AWS::NoValue']"));
  assert.ok(template.includes('phase1_raw = required(secret("${UsdcPhase1ConfigurationSecretArn}"), "configurationJson")'));
  assert.ok(template.includes('hashlib.sha256(phase1_raw.encode("utf-8")).hexdigest() != "${UsdcPhase1ConfigurationSha256}"'));
  assert.ok(template.includes('phase1_subsidy != "${UsdcMaximumSubsidyAtomic}"'));
  assert.ok(template.includes('"LAYRS_DIRECT_USDC_MAX_SUBSIDY_ATOMIC": phase1_subsidy'));
  assert.ok(!template.includes('"LAYRS_DIRECT_USDC_MAX_SUBSIDY_ATOMIC": "${UsdcMaximumSubsidyAtomic}"'));
});

test('candidate ASG health grace remains above measured restore plus margin',()=>{
  const match=template.match(/HealthCheckGracePeriod: ([0-9]+)/);
  assert.ok(match,'ASG health grace must be explicit');
  const seconds=Number(match[1]);
  assert.equal(seconds,3600);
  assert.ok(seconds>=25*60,'health grace must exceed the restore-based hard-abort floor');
});

test('hot grant renewal stages a restart-safe successor without replacing the writer',()=>{
  assert.match(template,/StagedWriterGrantBase64:\n    Type: String\n    Default: ''\n    NoEcho: true/);
  assert.ok(template.includes("StagedWriterGrantCommitment: { Type: String, Default: '' }"));
  assert.match(template,/kms:EncryptionContext:layrs-writer-grant:\n\s+- !Ref WriterGrantCommitment\n\s+- !Ref StagedWriterGrantCommitment/);
  assert.doesNotMatch(template,/AutoScalingRollingUpdate/,
    'grant-only launch-template staging must not recycle the live writer; releases refresh capacity explicitly');
  assert.ok(template.includes('"LAYRS_DIRECT_STAGED_WRITER_GRANT_JSON"'));
  assert.equal((template.match(/Type: AWS::EC2::LaunchTemplate/g)||[]).length,1);
  assert.equal((template.match(/Type: AWS::AutoScaling::AutoScalingGroup/g)||[]).length,1);
});

test('actual parent bootstrap remains valid Python',()=>{
  const match=template.match(/            \/usr\/bin\/python3 - <<'PY'\n([\s\S]*?)\n            PY/);
  assert.ok(match,'actual bootstrap must exist');
  const bootstrap=match[1].split('\n').map(line=>line.startsWith('            ')?line.slice(12):line).join('\n');
  execFileSync('python3',['-c','import sys; compile(sys.stdin.read(), "parent-bootstrap", "exec")'],{input:bootstrap,stdio:['pipe','pipe','pipe']});
});
