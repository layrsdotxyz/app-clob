const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');

const template=readFileSync(join(__dirname,'..','layrs-direct-execution-production.template.yaml'),'utf8');
const source=name=>readFileSync(join(__dirname,'..','..','enclave','direct-execution-v1','src',name),'utf8');

test('unified source proof is default-off and bound to the production writer',()=>{
  assert.match(template,/UnifiedDepositsEnabled: \{ Type: String, Default: 'false'/);
  assert.match(template,/RuleCondition: !Equals \[!Ref UnifiedDepositsEnabled, 'true'\]/);
  assert.ok(template.includes("!Equals [!Ref ExecutionMode, production-enabled]"));
  assert.ok(template.includes("!Not [!Equals [!Ref UnifiedRpcSecretArn, '']]"));
  assert.ok(template.includes("!Equals [!Ref ZenCustodyEnabled, 'true']"));
  assert.ok(template.includes("!If [UnifiedDepositsActive, !Ref UnifiedRpcSecretArn, !Ref 'AWS::NoValue']"));
});

test('all nine asset lanes and their canonical chain bindings reach the parent',()=>{
  for(const [chain,id,token,confirmations] of [
    ['ethereum','1','0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48','UnifiedEthereumConfirmations'],
    ['base','8453','0x833589fcd6edb6e08f4c7c32d4f71b54bda02913','UnifiedBaseConfirmations'],
    ['arbitrum','42161','0xaf88d065e77c8cc2239327c5edb3a432268e5831','UnifiedArbitrumConfirmations'],
    ['optimism','10','0x0b2c639c533813f4aa9d7837caf62653d097ff85','UnifiedOptimismConfirmations'],
    ['polygon','137','0x3c499c542cef5e3811e1192ce70d8cc03d5c3359','UnifiedPolygonConfirmations'],
    ['bnb','56','0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d','UnifiedBnbConfirmations'],
    ['horizen','26514','0xdf7108f8b10f9b9ec1aba01cca057268cbf86b6c','UnifiedHorizenConfirmations'],
  ]){
    assert.ok(template.includes(`"${chain}": ("${id}", "${token}", "\${${confirmations}}")`));
  }
  assert.ok(template.includes('"LAYRS_UNIFIED_BASE_ZEN_TOKEN_ADDRESS": "0xf43eb8de897fbc7f2502483b2bef7bb9ea179229"'));
  assert.ok(template.includes('"LAYRS_UNIFIED_HORIZEN_ZEN_TOKEN_ADDRESS": "0x57da2d504bf8b83ef304759d9f2648522d7a9280"'));
  assert.ok(template.includes('"LAYRS_UNIFIED_USDC_FINALITY_ENABLED": "true"'));
});

test('non-Horizen source proof uses optional second providers while Horizen remains wait-and-retry',()=>{
  assert.ok(template.includes('if chain != "horizen" and isinstance(fallback, str) and fallback:'));
  const custody=source('unified_deposit_custody.rs');
  assert.ok(custody.includes('rpc_urls: Vec<String>'));
  assert.ok(custody.includes('for rpc_url in &config.rpc_urls'));
  const parent=source('bin/parent.rs');
  assert.match(parent,/error\.starts_with\("unified deposit RPC"\).*StatusCode::SERVICE_UNAVAILABLE/s);
});

test('unified finality does not activate the historical Bus verifier',()=>{
  const usdc=source('usdc_custody.rs');
  assert.ok(usdc.includes('LAYRS_UNIFIED_USDC_FINALITY_ENABLED'));
  const bus=source('usdc_bus_custody.rs');
  assert.ok(!bus.includes('LAYRS_UNIFIED_USDC_FINALITY_ENABLED'));
});
