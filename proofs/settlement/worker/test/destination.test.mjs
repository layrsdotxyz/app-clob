import assert from "node:assert/strict";
import test from "node:test";
import {
  expectedZkVerifyLeaf,
  requireDestinationAggregationReady,
} from "../destination.mjs";

test("destination leaf matches a finalized production zkVerify statement", () => {
  const journal = Buffer.from(
    "9b61f2e5b557ccb7d50440bf2797642dca0b62cb3c2d984d0b4fcfd477d9690b" +
      "8c4423efb7f28a9eda893d75b7dda416538b0539c66aa89ca85adbb2a8100ad3" +
      "0000000000000000000000000000000000000000000000000000000000006792" +
      "00000000000000000000000000000000000000000000000000000000000000f5" +
      "0000000000000000000000000000000000000000000000000000000016ef17e8" +
      "0000000000000000000000000000000000000000000000000000000016c3ff59" +
      "0000000000000000000000000000000000000000000000000000000000000002" +
      "6c100c8235357d37aaef6fae8518ff02cd4d13cfc092c6285cb2a0dbb99ecb96" +
      "b204ae561bbe77d511fda435c89d9ae9607dc30f82008aa359ce468c63929de9" +
      "2246a8976d93147211e58ebf84f72573c8a16a3206f42a892ecbc9dff359ae09" +
      "d36e4297e17c89fa0e754a315a3400f61f3cfbf56ca7b1555bc9c41084ee47d3" +
      "0000000000000000000000000000000000000000000000000000000000000000" +
      "0000000000000000000000000000000000000000000000000000000000000000" +
      "0000000000000000000000000000000000000000000000000000000000000000" +
      "db070fafedd4221a7c4a1b8aa13968f60847213cd15f6625889cb4a2bc9431d1",
    "hex",
  );
  assert.equal(journal.length, 480);
  assert.equal(
    expectedZkVerifyLeaf(
      journal,
      "0x563cc7ea1bdf5583d07234d48a198b41e348ac51bd4c8ae028652974284746dc",
    ),
    "0xbfd022de35998336a9c7e1ddcc195636463dc71be4aed010f9e483445b75e50f",
  );
});

test("destination readiness is fail-closed until the aggregation is imported", () => {
  assert.doesNotThrow(() => requireDestinationAggregationReady(true));
  assert.throws(
    () => requireDestinationAggregationReady(false),
    /ZKVERIFY_DESTINATION_AGGREGATION_PENDING/,
  );
});
