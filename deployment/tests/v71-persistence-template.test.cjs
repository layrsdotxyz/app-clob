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

test('actual parent bootstrap remains valid Python',()=>{
  const match=template.match(/            \/usr\/bin\/python3 - <<'PY'\n([\s\S]*?)\n            PY/);
  assert.ok(match,'actual bootstrap must exist');
  const bootstrap=match[1].split('\n').map(line=>line.startsWith('            ')?line.slice(12):line).join('\n');
  execFileSync('python3',['-c','import sys; compile(sys.stdin.read(), "parent-bootstrap", "exec")'],{input:bootstrap,stdio:['pipe','pipe','pipe']});
});
