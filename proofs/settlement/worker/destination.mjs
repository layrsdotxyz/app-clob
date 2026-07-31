import { concat, keccak256 } from "ethers";
import { hex32 } from "./core.mjs";

export const HORIZEN_DOMAIN_ID = 3;
const PROVING_SYSTEM_ID =
  "0x676acbc40b7c7b5ba646aee26dd77984104e0674391ebd9f8e70b60d84ca6660";
const RISC_ZERO_V2_2_VERSION_HASH =
  "0xb3321f8b04ee9a754860a415c691f00756990e2054e5023f1a68c260a7042efe";

export function expectedZkVerifyLeaf(journal, imageId) {
  return keccak256(concat([
    PROVING_SYSTEM_ID,
    hex32(imageId, "registryImageId"),
    RISC_ZERO_V2_2_VERSION_HASH,
    keccak256(journal),
  ]));
}

export function requireDestinationAggregationReady(ready) {
  if (ready !== true) {
    throw new Error("ZKVERIFY_DESTINATION_AGGREGATION_PENDING");
  }
}
