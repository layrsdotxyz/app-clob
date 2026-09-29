const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
const {execFileSync}=require('node:child_process');
const template=readFileSync(join(__dirname,'..','layrs-direct-execution-production.template.yaml'),'utf8');
const source=name=>readFileSync(join(__dirname,'..','..','enclave','direct-execution-v1','src',name),'utf8');

test('P1 parent settings are explicitly default-off and require the existing production writer',()=>{
  assert.match(template,/UsdcCustodyEnabled: \{ Type: String, Default: 'false'/);
  assert.match(template,/RuleCondition: !Equals \[!Ref UsdcCustodyEnabled, 'true'\]/);
  for(const field of ['UsdcRpcSecretArn','UsdcPhase1ConfigurationSecretArn','UsdcPhase1ConfigurationSha256','UsdcLedgerWalletAddress','UsdcAdministratorPublicKeyDerBase64']){
    assert.ok(template.includes(`!Not [!Equals [!Ref ${field}, '']]`));
  }
  assert.match(template,/!Equals \[!Ref ExecutionMode, production-enabled\]/);
  assert.ok(template.includes("!Not [!Equals [!Ref UsdcLedgerWalletAddress, '0x0000000000000000000000000000000000000000']]"));
});
test('every environment field required by enabled USDC proof adapters is wired',()=>{
  for(const name of ['usdc_custody.rs','usdc_bus_custody.rs','usdc_wallet_link.rs']){
    const required=[...source(name).matchAll(/(?:required|url|confirmations|positive|env::var)\("(LAYRS[A-Z0-9_]+)"\)/g)]
      .map(match=>match[1])
      .filter(variable=>variable!=='LAYRSV2_RELAY_BASE_URL');
    assert.ok(required.length>0);
    for(const variable of required)assert.ok(template.includes(`"${variable}"`),`${name}: missing ${variable}`);
  }
});
test('RPC secret is an exact conditional reference, never a wildcard or operator secret',()=>{
  assert.ok(template.includes("!If [UsdcCustodyActive, !Ref UsdcRpcSecretArn, !Ref 'AWS::NoValue']"));
  assert.ok(template.includes("!If [UsdcCustodyActive, !Ref UsdcPhase1ConfigurationSecretArn, !Ref 'AWS::NoValue']"));
  const usdc=template.slice(template.indexOf('if "${UsdcCustodyEnabled}" == "true":'),template.indexOf('            def quote(value):'));
  assert.ok(usdc.includes('usdc_rpc = secret("${UsdcRpcSecretArn}")'));
  assert.ok(!/PRIVATE_KEY|privateKey|administratorPrivate|workerPrivate/.test(usdc));
  assert.ok(usdc.includes('LAYRS_DIRECT_USDC_ADMIN_PUBLIC_KEY_DER_BASE64'));
});
test('P1 adds no resource or ingress and retains the existing ZEN bindings',()=>{
  assert.equal((template.match(/Type: AWS::EC2::LaunchTemplate/g)||[]).length,1);
  assert.equal((template.match(/Type: AWS::AutoScaling::AutoScalingGroup/g)||[]).length,1);
  assert.ok(template.includes('if "${ZenCustodyEnabled}" == "true":'));
  assert.ok(template.includes('"LAYRS_DIRECT_ZEN_CUSTODY_ENABLED": "true"'));
  assert.ok(!template.includes('FromPort: 8081'));
});
test('runtime health checks verify the enclave and replace an unhealthy host',()=>{
  assert.match(template,/HealthCheckType: ELB/);
  const match=template.match(/HealthCheckGracePeriod: ([0-9]+)/);
  assert.ok(match,'ASG health grace must be explicit');
  const seconds=Number(match[1]);
  assert.equal(seconds,3600);
  assert.ok(seconds>=25*60,'health grace must exceed the restore-based hard-abort floor');
  assert.match(template,/HealthCheckProtocol: HTTP/);
  assert.match(template,/HealthCheckPath: \/healthz/);
  assert.match(template,/Matcher: \{ HttpCode: '200-399' \}/);
});
test('USDC finality, principal subsidy and native fee bindings are independently explicit',()=>{
  assert.ok(template.includes('ArbitrumConfirmations: { Type: Number, Default: 1, AllowedValues: [1] }'));
  for(const [variable,parameter] of [['LAYRSV2_HORIZEN_CONFIRMATIONS','HorizenConfirmations'],
    ['LAYRS_DIRECT_USDC_MAX_BRIDGE_FEE_WEI','UsdcMaximumBridgeFeeWei']])
    assert.ok(template.includes(`"${variable}": "\${${parameter}}"`));
  assert.ok(template.includes('UsdcMaximumSubsidyAtomic: { Type: Number, Default: 50000, AllowedValues: [50000] }'));
  assert.ok(template.includes('phase1_raw = required(secret("${UsdcPhase1ConfigurationSecretArn}"), "configurationJson")'));
  assert.ok(template.includes('hashlib.sha256(phase1_raw.encode("utf-8")).hexdigest() != "${UsdcPhase1ConfigurationSha256}"'));
  assert.ok(template.includes('phase1_subsidy != "${UsdcMaximumSubsidyAtomic}"'));
  assert.ok(template.includes('"LAYRS_DIRECT_USDC_MAX_SUBSIDY_ATOMIC": phase1_subsidy'));
  assert.ok(!template.includes('"LAYRS_DIRECT_USDC_MAX_SUBSIDY_ATOMIC": "${UsdcMaximumSubsidyAtomic}"'));
});
test('actual parent bootstrap Python remains syntactically valid after the P1 environment addition',()=>{
  const match=template.match(/            \/usr\/bin\/python3 - <<'PY'\n([\s\S]*?)\n            PY/);
  assert.ok(match,'actual bootstrap must exist');
  const bootstrap=match[1].split('\n').map(line=>line.startsWith('            ')?line.slice(12):line).join('\n');
  execFileSync('python3',['-c','import sys; compile(sys.stdin.read(), "parent-bootstrap", "exec")'],{input:bootstrap,stdio:['pipe','pipe','pipe']});
});
