-- SPDX-License-Identifier: MPL-2.0
-- Shadow Verifier for Cerro Torre eXtreme (X-) Variants
-- (Idris2 port of verification/ats/shadow_verifier.dats)
--
-- Uses Idris2 QTT linear types (multiplicity 1) so that the bundle, its hash
-- and each of its signatures are consumed exactly once, and every signature
-- passes through `verifySignature` (none skipped).
--
-- SECURITY: FAIL-CLOSED. This verifier is NOT implemented and MUST REJECT:
--   * `verifySignature` is a stub (the ATS `ext#` symbol had no body). It
--     consumes its inputs and ALWAYS returns a failing result. It is not an
--     Ed25519 check and not even LinearCrypto's symbolic model.
--   * An EMPTY signature chain is rejected explicitly (no vacuous truth).
--   * The chain fold is seeded with `False`, as in the ATS. Even if
--     `verifySignature` were replaced, nothing here can return True until the
--     seed is deliberately changed (the ATS comment's step (c)).
--   * Fail-closed holds by construction (stub returns failure, empty chain
--     rejected, False seed) and is checked on concrete bundles below. A
--     universal "rejects every bundle" proof was attempted but not kept: the
--     Idris2 0.7.0 unifier would not unfold the symbolic step under the
--     abstract-resource pattern matches. Do NOT weaken any of the three
--     guards without real signature verification.
--
-- Differences from the ATS:
--   * Signatures are OWNED by the loop and consumed by `verifySignature`
--     (the ATS borrowed them via `!List_vt` and so could not call the
--     consuming verifier at all: the ATS comment's steps (a) and (b)).
--   * `load_bundle(path)` is not modelled (no IO). A bundle is built from
--     in-memory data with `bundleLoad`. The ATS `main0` CLI is not ported.

module ShadowVerifier

import Data.Vect
import LinearCrypto

%default total

-- ============================================================================
-- Linear Types for Bundle Components (abstract)
-- ============================================================================

||| A bundle signature, consumed exactly once.
export
data Signature = MkSig (Vect 64 Bits8)

||| A verification result, consumed exactly once.
export
data VerifyResult = MkResult Bool

||| Linear list of signatures (ATS `List_vt(signature_vt)`).
public export
data SigList : Type where
  Nil  : SigList
  (::) : (1 _ : Signature) -> (1 _ : SigList) -> SigList

||| A bundle: its hash and its signatures (model).
export
data Bundle = MkBundle (Vect 32 Bits8) (List (Vect 64 Bits8))

||| Unrestricted description of a bundle (stands in for the file on disk).
public export
record BundleData where
  constructor MkBundleData
  bundleHash : Vect 32 Bits8
  bundleSigs : List (Vect 64 Bits8)

-- ============================================================================
-- Bundle Operations
-- ============================================================================

||| Model of `load_bundle`: from in-memory data, no IO.
public export
bundleLoad : (1 _ : Arena) -> BundleData -> Both Arena Bundle
bundleLoad h d = B h (MkBundle (bundleHash d) (bundleSigs d))

||| Extract the bundle hash (bundle handed back).
public export
bundleGetHash : (1 _ : Arena) -> (1 _ : Bundle) -> Both Arena (Both Bundle Bytes32)
bundleGetHash h (MkBundle hs ss) =
  let B h hash = bytes32Create h hs in B h (B (MkBundle hs ss) hash)

public export
toSigList : List (Vect 64 Bits8) -> SigList
toSigList [] = []
toSigList (s :: ss) = MkSig s :: toSigList ss

||| Extract the signatures (bundle handed back).
public export
bundleGetSignatures : (1 _ : Bundle) -> Both Bundle SigList
bundleGetSignatures (MkBundle hs ss) = B (MkBundle hs ss) (toSigList ss)

public export
bundleClose : (1 _ : Bundle) -> ()
bundleClose (MkBundle _ _) = ()

-- ============================================================================
-- Signature Verification (UNIMPLEMENTED -> FAIL-CLOSED)
-- ============================================================================

||| Consumes the signature and a hash copy. NOT IMPLEMENTED: always fails.
public export
verifySignature : (1 _ : Signature) -> (1 _ : Bytes32) -> VerifyResult
verifySignature (MkSig _) hash = let () = bytes32Free hash in MkResult False

||| Consumes the result.
public export
resultIsSuccess : (1 _ : VerifyResult) -> Bool
resultIsSuccess (MkResult b) = b

-- ============================================================================
-- Signature Chain Verification (Linear)
-- ============================================================================

-- Written as small pattern-matching functions so each step (copy hash,
-- verify, branch on the result) is a separate linear hand-off.
mutual
  ||| Every signature is consumed by `verifySignature` exactly once.
  public export
  chainLoop : (1 _ : SigList) -> (1 hash : Bytes32) -> Bool -> Res Bool (const Bytes32)
  chainLoop [] hash acc = acc # hash
  chainLoop (s :: rest) hash acc = chainWithCopy s rest (bytes32Copy hash) acc

  ||| Verify `s` against a fresh copy of the hash (the copy is consumed).
  public export
  chainWithCopy : (1 s : Signature) -> (1 rest : SigList)
               -> (1 _ : Both Bytes32 Bytes32) -> Bool -> Res Bool (const Bytes32)
  chainWithCopy s rest (B hash hashCopy) acc =
    chainDecide rest hash (resultIsSuccess (verifySignature s hashCopy)) acc

  ||| Matching on the Bool releases it from linearity.
  public export
  chainDecide : (1 rest : SigList) -> (1 hash : Bytes32) -> (1 ok : Bool) -> Bool
             -> Res Bool (const Bytes32)
  chainDecide rest hash True  acc = chainLoop rest hash acc
  chainDecide rest hash False _   = chainLoop rest hash False

||| Fail-closed chain check: empty chain rejects; seed is False.
public export
verifySignatureChain : (1 _ : SigList) -> (1 hash : Bytes32) -> Res Bool (const Bytes32)
verifySignatureChain [] hash = False # hash           -- empty chain REJECTS
verifySignatureChain (s :: rest) hash =
  chainLoop (s :: rest) hash False                    -- fail-closed seed

-- BAD CODE (does NOT typecheck): skipping a signature.
--   skipFirst : (1 _ : SigList) -> (1 hash : Bytes32) -> Res Bool (const Bytes32)
--   skipFirst (s :: rest) hash = chainLoop rest hash True
--   -- error: There are 0 uses of linear name s.

-- ============================================================================
-- Main Shadow Verification Entry Point
-- ============================================================================

||| Final cleanup: free the hash, close the bundle and the arena.
public export
shadowFinish : (1 _ : Arena) -> (1 _ : Bundle) -> (1 _ : Res Bool (const Bytes32)) -> Unr Bool
shadowFinish h bundle (r # hash) =
  let () = bytes32Free hash
      () = bundleClose bundle
      () = closeArena h
  in MkUnr r

public export
shadowWithSigs : (1 _ : Arena) -> (1 hash : Bytes32) -> (1 _ : Both Bundle SigList) -> Unr Bool
shadowWithSigs h hash (B bundle sigs) = shadowFinish h bundle (verifySignatureChain sigs hash)

public export
shadowWithHash : (1 _ : Both Arena (Both Bundle Bytes32)) -> Unr Bool
shadowWithHash (B h (B bundle hash)) = shadowWithSigs h hash (bundleGetSignatures bundle)

public export
shadowLoaded : (1 _ : Both Arena Bundle) -> Unr Bool
shadowLoaded (B h bundle) = shadowWithHash (bundleGetHash h bundle)

||| Shadow-verify a bundle. Always False while `verifySignature` is a stub.
public export
shadowVerifyBundle : BundleData -> Bool
shadowVerifyBundle d = runArena $ \1 h => shadowLoaded (bundleLoad h d)

-- ============================================================================
-- Checks / Proofs
-- ============================================================================

||| Concrete instance: a bundle whose signatures were stripped is rejected.
checkEmptyChainRejected : shadowVerifyBundle (MkBundleData (replicate 32 0) []) = False
checkEmptyChainRejected = Refl

||| Concrete instance: a bundle with signatures is still rejected (stub).
checkUnimplementedRejects :
  shadowVerifyBundle (MkBundleData (replicate 32 0) [replicate 64 1, replicate 64 2]) = False
checkUnimplementedRejects = Refl
