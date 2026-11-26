-- SPDX-License-Identifier: MPL-2.0
-- Linear Signature Chain Verification
-- (Idris2 port of verification/ats/signature_linear.dats)
--
-- Uses Idris2 QTT linear types (multiplicity 1) so that:
--   1. Every chain entry (public key + signature) is verified or freed;
--      none can be skipped (an unconsumed tail is a linearity error).
--   2. No signature can be verified twice without an explicit copy.
--   3. Threshold verification still consumes every entry.
--   4. The build -> sign -> countersign -> verify pipeline is enforced by an
--      indexed stage type, so out-of-order transitions do not typecheck
--      (the ATS version had runtime "should not happen" fall-through arms).
--
-- HONESTY NOTES:
--   * Signature checks go through LinearCrypto's symbolic MODEL. They are
--     NOT real Ed25519 verification; see LinearCrypto's header.
--   * Deliberate tightenings over the ATS:
--       - `chainVerifyAll` requires a non-empty chain (`Chain (S n)`); the ATS
--         loop seeded `true`, so an empty chain verified vacuously.
--       - `chainVerifyThreshold` requires 1 <= threshold <= n (the ATS allowed
--         threshold 0, which accepts anything).

module LinearSignature

import Data.Vect
import Data.Nat
import LinearCrypto

%default total

-- ============================================================================
-- Signature Chain Types
-- ============================================================================

||| A chain entry: public key + signature, both linear.
public export
data Entry : Type where
  MkEntry : (1 pk : Bytes32) -> (1 sig : Bytes64) -> Entry

||| Linear, length-indexed list of entries (ATS `list_vt(chain_entry, n)`).
public export
data Chain : Nat -> Type where
  Nil  : Chain 0
  (::) : (1 _ : Entry) -> (1 _ : Chain n) -> Chain (S n)

public export
chainEmpty : Chain 0
chainEmpty = []

||| Transfers ownership of pk and sig into the chain.
public export
chainCons : (1 pk : Bytes32) -> (1 sig : Bytes64) -> (1 rest : Chain n) -> Chain (S n)
chainCons pk sig rest = MkEntry pk sig :: rest

||| The "or freed" path: release every entry without verifying it.
public export
chainFree : (1 _ : Chain n) -> ()
chainFree [] = ()
chainFree (MkEntry pk sig :: rest) =
  let () = bytes32Free pk
      () = bytes64Free sig
  in chainFree rest

-- ============================================================================
-- Single-entry verification (shared by all-of and threshold)
-- ============================================================================

||| Verify one entry against msg: consumes pk and sig, borrows msg and arena.
public export
verifyEntry : (1 _ : Arena) -> (1 _ : Entry) -> (1 msg : Bytes32)
           -> Res Bool (const (Both Arena Bytes32))
verifyEntry h (MkEntry pk sig) msg =
  let B h ctx    = verifyCtxCreate h
      B ctx pk   = verifyCtxAddKey ctx pk
      ctx        = verifyCtxAddSignature ctx sig
      (r # msg)  = verifyCtxFinalize ctx msg
      ()         = bytes32Free pk
  in r # B h msg

-- ============================================================================
-- Chain Verification (Linear)
-- ============================================================================

public export
verifyAllLoop : (1 _ : Arena) -> (1 _ : Chain n) -> (1 msg : Bytes32) -> Bool
             -> Res Bool (const (Both Arena Bytes32))
verifyAllLoop h [] msg acc = acc # B h msg
verifyAllLoop h (e :: rest) msg acc =
  let (r # B h msg) = verifyEntry h e msg
  in verifyAllLoop h rest msg (acc && r)

||| Verify every signature of a NON-EMPTY chain; every entry is consumed even
||| after a failure (no short-circuit skip).
public export
chainVerifyAll : (1 _ : Arena) -> (1 _ : Chain (S n)) -> (1 msg : Bytes32)
              -> Res Bool (const (Both Arena Bytes32))
chainVerifyAll h chain msg = verifyAllLoop h chain msg True

-- ============================================================================
-- Threshold Verification
-- ============================================================================

public export
countValid : (1 _ : Arena) -> (1 _ : Chain n) -> (1 msg : Bytes32) -> Nat
          -> Res Nat (const (Both Arena Bytes32))
countValid h [] msg c = c # B h msg
countValid h (e :: rest) msg c =
  let (r # B h msg) = verifyEntry h e msg
  in countValid h rest msg (if r then S c else c)

||| At least `threshold` of the n signatures must verify; all n are consumed.
public export
chainVerifyThreshold : (1 _ : Arena) -> (threshold : Nat)
                    -> {auto 0 pos : LTE 1 threshold}
                    -> {auto 0 bound : LTE threshold n}
                    -> (1 _ : Chain n) -> (1 msg : Bytes32)
                    -> Res Bool (const (Both Arena Bytes32))
chainVerifyThreshold h threshold chain msg =
  let (k # rest) = countValid h chain msg 0
  in (k >= threshold) # rest

-- ============================================================================
-- Unordered two-signature verification
-- ============================================================================

public export
verifyTwoSigsUnordered : (1 _ : Arena)
                      -> (1 pk1 : Bytes32) -> (1 sig1 : Bytes64)
                      -> (1 pk2 : Bytes32) -> (1 sig2 : Bytes64)
                      -> (1 msg : Bytes32)
                      -> Res Bool (const (Both Arena Bytes32))
verifyTwoSigsUnordered h pk1 sig1 pk2 sig2 msg =
  let (r1 # B h msg) = verifyEntry h (MkEntry pk1 sig1) msg
      (r2 # B h msg) = verifyEntry h (MkEntry pk2 sig2) msg
  in (r1 && r2) # B h msg

-- ============================================================================
-- BAD CODE (does NOT typecheck)
-- ============================================================================
--
-- Skipping the rest of the chain:
--
-- skipSignature : (1 _ : Arena) -> (1 _ : Chain 2) -> (1 msg : Bytes32)
--              -> Res Bool (const (Both Arena Bytes32))
-- skipSignature h (MkEntry pk1 sig1 :: rest) msg =
--   let () = bytes32Free pk1
--       () = bytes64Free sig1
--   in True # B h msg       -- error: There are 0 uses of linear name rest.
--
-- Replaying one signature against two messages:
--
-- replayAttack : (1 _ : Arena) -> (1 pk : Bytes32) -> (1 sig : Bytes64)
--             -> (1 m1 : Bytes32) -> (1 m2 : Bytes32) -> ...
-- replayAttack h pk sig m1 m2 =
--   let B h c1 = verifyCtxCreate h
--       c1 = verifyCtxAddSignature c1 sig
--       ...
--       B h c2 = verifyCtxCreate h
--       c2 = verifyCtxAddSignature c2 sig   -- error: sig is not accessible
--       ...

-- ============================================================================
-- Multi-Step Pipeline (Build -> Sign -> Countersign -> Verify)
-- ============================================================================

public export
data Stage = SBuilt | SSigned | SCountersigned | SVerified

||| Pipeline state indexed by stage; transitions only exist in order.
public export
data Pipeline : Stage -> Type where
  Built         : Pipeline SBuilt
  Signed        : (1 _ : Chain 1) -> Pipeline SSigned
  Countersigned : (1 _ : Chain 2) -> Pipeline SCountersigned
  Verified      : Bool -> Pipeline SVerified

public export
pipelineSign : (1 _ : Pipeline SBuilt) -> (1 pk : Bytes32) -> (1 sig : Bytes64)
            -> Pipeline SSigned
pipelineSign Built pk sig = Signed (chainCons pk sig chainEmpty)

public export
pipelineCountersign : (1 _ : Pipeline SSigned) -> (1 pk : Bytes32) -> (1 sig : Bytes64)
                   -> Pipeline SCountersigned
pipelineCountersign (Signed chain) pk sig = Countersigned (chainCons pk sig chain)

public export
pipelineVerify : (1 _ : Arena) -> (1 _ : Pipeline SCountersigned) -> (1 msg : Bytes32)
              -> Both (Pipeline SVerified) (Both Arena Bytes32)
pipelineVerify h (Countersigned chain) msg =
  let (r # rest) = chainVerifyAll h chain msg
  in B (Verified r) rest

public export
completePipeline : (1 _ : Arena) -> (1 msg : Bytes32)
                -> (1 pk1 : Bytes32) -> (1 sig1 : Bytes64)
                -> (1 pk2 : Bytes32) -> (1 sig2 : Bytes64)
                -> Res Bool (const (Both Arena Bytes32))
completePipeline h msg pk1 sig1 pk2 sig2 =
  let s1 = pipelineSign Built pk1 sig1
      s2 = pipelineCountersign s1 pk2 sig2
      B (Verified r) rest = pipelineVerify h s2 msg
  in r # rest

-- BAD CODE (does NOT typecheck): verifying before countersigning.
--
-- earlyVerify h msg pk sig =
--   pipelineVerify h (pipelineSign Built pk sig) msg
--   -- error: Pipeline SSigned is not Pipeline SCountersigned

-- ============================================================================
-- Checks (evaluated by the type checker)
-- ============================================================================

sk1 : Vect 32 Bits8
sk1 = replicate 32 1

sk2 : Vect 32 Bits8
sk2 = replicate 32 2

msgM : Vect 32 Bits8
msgM = replicate 32 42

||| Linear-safe selection (an `if` would use both names in each branch
||| context and is rejected by the linearity checker).
pickSig : Bool -> (1 good : Bytes64) -> (1 bad : Bytes64) -> Both Bytes64 Bytes64
pickSig False good bad = B good bad
pickSig True  good bad = B bad good

||| Run the full pipeline with two signers. If `forgeSecond` the second
||| signature is replaced by garbage.
runPipeline : (forgeSecond : Bool) -> Bool
runPipeline forgeSecond = runArena $ \1 h =>
  let B h m             = bytes32Create h msgM
      B h k1            = secretKeyLoad h sk1
      B k1 pk1          = publicKeyOf k1
      B k1 (B m s1)     = modelSign k1 m
      ()                = secretKeyZeroize k1
      B h k2            = secretKeyLoad h sk2
      B k2 pk2          = publicKeyOf k2
      B k2 (B m s2)     = modelSign k2 m
      ()                = secretKeyZeroize k2
      B h bad           = bytes64Create h (replicate 64 0)
      B s2 bad          = pickSig forgeSecond s2 bad
      ()                = bytes64Free bad
      (r # B h m)       = completePipeline h m pk1 s1 pk2 s2
      ()                = bytes32Free m
      ()                = closeArena h
  in MkUnr r

checkPipelineAccepts : runPipeline False = True
checkPipelineAccepts = Refl

checkPipelineRejectsForgery : runPipeline True = False
checkPipelineRejectsForgery = Refl

||| Threshold 1-of-2 with the second signature forged.
threshold1of2Forged : Bool
threshold1of2Forged = runArena $ \1 h =>
  let B h m         = bytes32Create h msgM
      B h k1        = secretKeyLoad h sk1
      B k1 pk1      = publicKeyOf k1
      B k1 (B m s1) = modelSign k1 m
      ()            = secretKeyZeroize k1
      B h pk2       = bytes32Create h (replicate 32 0)
      B h s2        = bytes64Create h (replicate 64 0)
      chain         = chainCons pk1 s1 (chainCons pk2 s2 chainEmpty)
      (r # B h m)   = chainVerifyThreshold h 1 chain m
      ()            = bytes32Free m
      ()            = closeArena h
  in MkUnr r

checkThreshold1of2 : LinearSignature.threshold1of2Forged = True
checkThreshold1of2 = Refl
