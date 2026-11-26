-- SPDX-License-Identifier: MPL-2.0
-- Linear Cryptographic Operations (Idris2 port of verification/ats/crypto_linear.dats)
--
-- Uses Idris2 QTT linear types (multiplicity 1) to keep the properties the
-- ATS2 module expressed with `absvtype`:
--   1. Keys, hashes and signatures are consumed exactly once (no silent
--      duplication, no silent drop).
--   2. A secret key is zeroized exactly once (`secretKeyZeroize` is the only
--      eliminator for `SecretKey`).
--   3. A verification context is finalized exactly once
--      (`verifyCtxFinalize` is the only eliminator for `VerifyCtx`).
--   4. A signature is consumed when added to a context; verifying the same
--      signature data twice requires an explicit `bytes64Copy`.
--
-- HONESTY NOTES (read before relying on this module):
--   * The ATS externs (`= "ext#"`) had NO bodies anywhere in the repo. This
--     port therefore does NOT do cryptography. Every operation is a pure,
--     in-memory MODEL. `modelSign` / `verifyCtxFinalize` implement a
--     symbolic signature (sig = derivedPublicKey ++ message) that is trivially
--     forgeable. It exists only so the linear API has executable semantics
--     that can be tested. IT IS NOT Ed25519 AND MUST NOT BE USED AS SUCH.
--     Real SHA-256 / Ed25519 live in ffi/zig/src/crypto.zig (see CryptoFFI).
--   * `sha256` is not modelled: a digest enters the model through
--     `bytes32Create`, i.e. it is assumed to have been computed elsewhere.
--   * `secretKeyLoad` takes key material instead of a file path (no IO), and
--     "zeroize" in a pure model has no memory to overwrite: what is kept is the
--     linear discipline (zeroize is called exactly once on every key), not the
--     physical wiping of RAM.
--   * Idris2 linearity is a property of BINDERS, not of types. A plain
--     `create : Bytes32` could be bound with multiplicity omega and then copied
--     or dropped. To get the ATS "linear result" behaviour every resource is
--     created from a linear `Arena` token and the arena runner (`runArena`)
--     only lets an unrestricted `Unr a` escape. A linear resource cannot be put
--     into `Unr`, so every resource must be eliminated inside the arena.
--   * ATS `!T` (borrow) is modelled by threading: the function takes the
--     resource linearly and hands it back (`Both`, or `Res` for an
--     unrestricted result plus the returned resource).
--   * Functions are `public export` so the type checker can evaluate the
--     checks below and in importing modules; the resource TYPES are only
--     `export`, so their constructors stay private and cannot be forged.

module LinearCrypto

import Data.Vect

%default total

-- ============================================================================
-- Linear plumbing
-- ============================================================================

||| A pair whose two components are both linear.
public export
data Both : Type -> Type -> Type where
  B : (1 _ : a) -> (1 _ : b) -> Both a b

||| Unrestricted wrapper. Its field has multiplicity omega, so a linearly
||| bound resource can never be stored in it: this is what stops resources
||| escaping from `runArena`.
public export
data Unr : Type -> Type where
  MkUnr : a -> Unr a

||| Linear Maybe (the ATS `Option_vt`).
public export
data LMaybe : Type -> Type where
  LNothing : LMaybe a
  LJust    : (1 _ : a) -> LMaybe a

||| Allocation capability. Abstract: only `runArena` makes one.
export
data Arena = MkArena

||| Run a linear computation. The continuation must close the arena and may
||| only return unrestricted data, so every resource created inside must have
||| been consumed by one of its eliminators before returning.
public export
runArena : ((1 _ : Arena) -> Unr a) -> a
runArena k = case k MkArena of MkUnr x => x

public export
closeArena : (1 _ : Arena) -> ()
closeArena MkArena = ()

-- ============================================================================
-- Linear Types for Cryptographic Data (all abstract: constructors not exported)
-- ============================================================================

||| 32-byte hash or public key; must be freed exactly once.
export
data Bytes32 = MkB32 (Vect 32 Bits8)

||| 64-byte signature; must be freed or consumed by a context exactly once.
export
data Bytes64 = MkB64 (Vect 64 Bits8)

||| Secret key; must be zeroized exactly once.
export
data SecretKey = MkSK (Vect 32 Bits8)

||| Verification context; must be finalized exactly once.
||| Holds the added public keys and the (consumed) signatures.
export
data VerifyCtx = MkCtx (List (Vect 32 Bits8)) (List (Vect 64 Bits8))

-- ============================================================================
-- Bytes32 Operations
-- ============================================================================

||| Model of `bytes32_create` / the result of `sha256`: the digest bytes are
||| supplied by the caller (computed outside this model).
public export
bytes32Create : (1 _ : Arena) -> Vect 32 Bits8 -> Both Arena Bytes32
bytes32Create MkArena v = B MkArena (MkB32 v)

public export
bytes32Free : (1 _ : Bytes32) -> ()
bytes32Free (MkB32 _) = ()

||| Borrow the original, return it plus a new owned copy.
public export
bytes32Copy : (1 _ : Bytes32) -> Both Bytes32 Bytes32
bytes32Copy (MkB32 v) = B (MkB32 v) (MkB32 v)

||| Compare (borrows both).
public export
bytes32Eq : (1 _ : Bytes32) -> (1 _ : Bytes32) -> Res Bool (const (Both Bytes32 Bytes32))
bytes32Eq (MkB32 a) (MkB32 b) = (a == b) # B (MkB32 a) (MkB32 b)

-- ============================================================================
-- Bytes64 Operations
-- ============================================================================

public export
bytes64Create : (1 _ : Arena) -> Vect 64 Bits8 -> Both Arena Bytes64
bytes64Create MkArena v = B MkArena (MkB64 v)

public export
bytes64Free : (1 _ : Bytes64) -> ()
bytes64Free (MkB64 _) = ()

public export
bytes64Copy : (1 _ : Bytes64) -> Both Bytes64 Bytes64
bytes64Copy (MkB64 v) = B (MkB64 v) (MkB64 v)

-- ============================================================================
-- Secret Key Operations (must be zeroized)
-- ============================================================================

||| Model of `secret_key_load`: key material is passed in (no file IO).
public export
secretKeyLoad : (1 _ : Arena) -> Vect 32 Bits8 -> Both Arena SecretKey
secretKeyLoad MkArena v = B MkArena (MkSK v)

||| The ONLY eliminator for SecretKey. In the model there is no memory to
||| overwrite; the guarantee kept is that it is called exactly once per key.
public export
secretKeyZeroize : (1 _ : SecretKey) -> ()
secretKeyZeroize (MkSK _) = ()

||| MODEL public-key derivation (255 - b, i.e. bitwise complement). Not Ed25519.
public export
modelPublic : Vect 32 Bits8 -> Vect 32 Bits8
modelPublic v = map (\b => 255 - b) v

||| Derive the model public key (borrows the secret key).
public export
publicKeyOf : (1 _ : SecretKey) -> Both SecretKey Bytes32
publicKeyOf (MkSK s) = B (MkSK s) (MkB32 (modelPublic s))

||| MODEL signing (port of `ed25519_sign`): borrows key and message, returns a
||| new linear signature. sig = modelPublic(sk) ++ msg. NOT Ed25519.
public export
modelSign : (1 _ : SecretKey) -> (1 _ : Bytes32)
         -> Both SecretKey (Both Bytes32 Bytes64)
modelSign (MkSK s) (MkB32 m) = B (MkSK s) (B (MkB32 m) (MkB64 (modelPublic s ++ m)))

-- ============================================================================
-- Verification Context
-- ============================================================================

public export
verifyCtxCreate : (1 _ : Arena) -> Both Arena VerifyCtx
verifyCtxCreate MkArena = B MkArena (MkCtx [] [])

||| Add a public key (borrows the key).
public export
verifyCtxAddKey : (1 _ : VerifyCtx) -> (1 _ : Bytes32) -> Both VerifyCtx Bytes32
verifyCtxAddKey (MkCtx ks ss) (MkB32 k) = B (MkCtx (k :: ks) ss) (MkB32 k)

||| Add a signature (CONSUMES it: it can only be checked through this context).
public export
verifyCtxAddSignature : (1 _ : VerifyCtx) -> (1 _ : Bytes64) -> VerifyCtx
verifyCtxAddSignature (MkCtx ks ss) (MkB64 s) = MkCtx ks (s :: ss)

||| Model acceptance of one signature: some added key k with sig == k ++ msg.
public export
modelAccepts : List (Vect 32 Bits8) -> Vect 32 Bits8 -> Vect 64 Bits8 -> Bool
modelAccepts ks m s = any (\k => (k ++ m) == s) ks

||| Finalize (CONSUMES the context, borrows the message).
||| Fail-closed: a context with no signatures rejects; every signature must be
||| accepted by some added key.
public export
verifyCtxFinalize : (1 _ : VerifyCtx) -> (1 _ : Bytes32) -> Res Bool (const Bytes32)
verifyCtxFinalize (MkCtx ks ss) (MkB32 m) =
  (not (null ss) && all (modelAccepts ks m) ss) # MkB32 m

-- ============================================================================
-- Linear Verification Pattern
-- ============================================================================

||| Port of `verify_bundle_2sigs`: msg, pk1, pk2 borrowed; sig1, sig2 consumed.
public export
verifyBundle2Sigs : (1 _ : Arena)
                 -> (1 msg : Bytes32) -> (1 pk1 : Bytes32) -> (1 sig1 : Bytes64)
                 -> (1 pk2 : Bytes32) -> (1 sig2 : Bytes64)
                 -> Res Bool (const (Both Arena (Both Bytes32 (Both Bytes32 Bytes32))))
verifyBundle2Sigs h msg pk1 sig1 pk2 sig2 =
  let B h ctx    = verifyCtxCreate h
      B ctx pk1  = verifyCtxAddKey ctx pk1
      B ctx pk2  = verifyCtxAddKey ctx pk2
      ctx        = verifyCtxAddSignature ctx sig1
      ctx        = verifyCtxAddSignature ctx sig2
      (r # msg)  = verifyCtxFinalize ctx msg
  in r # B h (B msg (B pk1 pk2))

-- Proof that signatures are not leaked. BAD CODE (does NOT typecheck):
--
-- leakSignature : (1 _ : Arena) -> Both Arena ()
-- leakSignature h =
--   let B h sig = bytes64Create h (replicate 64 0)
--   in B h ()            -- error: There are 0 uses of linear name sig.

-- ============================================================================
-- Secret Keys Are Zeroized
-- ============================================================================

||| Port of `sign_with_ephemeral_key`: the key is loaded, used, and MUST be
||| zeroized before returning (omitting the zeroize is a linearity error).
public export
signWithEphemeralKey : (1 _ : Arena) -> (material : Vect 32 Bits8) -> (1 msg : Bytes32)
                    -> Both Arena (Both Bytes32 Bytes64)
signWithEphemeralKey h material msg =
  let B h key          = secretKeyLoad h material
      B key (B msg sig) = modelSign key msg
      ()               = secretKeyZeroize key
  in B h (B msg sig)

-- BAD CODE (does NOT typecheck): key never zeroized.
--
-- signNoZeroize : (1 _ : Arena) -> Vect 32 Bits8 -> (1 msg : Bytes32)
--              -> Both Arena (Both Bytes32 Bytes64)
-- signNoZeroize h material msg =
--   let B h key = secretKeyLoad h material
--       B key (B msg sig) = modelSign key msg
--   in B h (B msg sig)   -- error: There are 0 uses of linear name key.

-- ============================================================================
-- Non-Malleability / Single Use of Signatures
-- ============================================================================

-- BAD CODE (does NOT typecheck): same signature verified twice.
--
-- doubleVerify : (1 _ : Arena) -> (1 sig : Bytes64) -> (1 msg : Bytes32)
--             -> Res Bool (const (Both Arena Bytes32))
-- doubleVerify h sig msg =
--   let B h ctx1 = verifyCtxCreate h
--       ctx1 = verifyCtxAddSignature ctx1 sig
--       (r1 # msg) = verifyCtxFinalize ctx1 msg
--       B h ctx2 = verifyCtxCreate h
--       ctx2 = verifyCtxAddSignature ctx2 sig   -- error: sig not accessible
--       (r2 # msg) = verifyCtxFinalize ctx2 msg
--   in (r1 && r2) # B h msg

||| Port of `double_verify_explicit`: reuse needs an explicit copy.
||| (A borrowed public key is added here; the ATS version added none, which
||| under the fail-closed model would always reject.)
public export
doubleVerifyExplicit : (1 _ : Arena) -> (1 pk : Bytes32) -> (1 sig : Bytes64)
                    -> (1 msg : Bytes32)
                    -> Res Bool (const (Both Arena (Both Bytes32 Bytes32)))
doubleVerifyExplicit h pk sig msg =
  let B sig sigCopy = bytes64Copy sig
      B h ctx1      = verifyCtxCreate h
      B ctx1 pk     = verifyCtxAddKey ctx1 pk
      ctx1          = verifyCtxAddSignature ctx1 sig
      (r1 # msg)    = verifyCtxFinalize ctx1 msg
      B h ctx2      = verifyCtxCreate h
      B ctx2 pk     = verifyCtxAddKey ctx2 pk
      ctx2          = verifyCtxAddSignature ctx2 sigCopy
      (r2 # msg)    = verifyCtxFinalize ctx2 msg
  in (r1 && r2) # B h (B pk msg)

||| Port of `verify_no_replay`: the signature is consumed by the first check,
||| so the second result can only be `False` without a second signature.
public export
verifyNoReplay : (1 _ : Arena) -> (1 pk : Bytes32) -> (1 msg1 : Bytes32)
              -> (1 msg2 : Bytes32) -> (1 sig : Bytes64)
              -> Res (Bool, Bool) (const (Both Arena (Both Bytes32 (Both Bytes32 Bytes32))))
verifyNoReplay h pk msg1 msg2 sig =
  let B h ctx    = verifyCtxCreate h
      B ctx pk   = verifyCtxAddKey ctx pk
      ctx        = verifyCtxAddSignature ctx sig
      (r1 # msg1) = verifyCtxFinalize ctx msg1
  in (r1, False) # B h (B pk (B msg1 msg2))

-- ============================================================================
-- Checks (evaluated by the type checker)
-- ============================================================================

zeros32 : Vect 32 Bits8
zeros32 = replicate 32 0

msgA : Vect 32 Bits8
msgA = replicate 32 7

msgB : Vect 32 Bits8
msgB = replicate 32 9

||| Sign msgA with a fresh ephemeral key, then verify against the derived key
||| and the given message. Everything is consumed inside the arena.
signThenVerify : Vect 32 Bits8 -> Bool
signThenVerify m = runArena $ \1 h =>
  let B h msgS          = bytes32Create h msgA
      B h (B msgS sig)  = signWithEphemeralKey h zeros32 msgS
      B h pk            = bytes32Create h (modelPublic zeros32)
      B h msgV          = bytes32Create h m
      B h ctx           = verifyCtxCreate h
      B ctx pk          = verifyCtxAddKey ctx pk
      ctx               = verifyCtxAddSignature ctx sig
      (r # msgV)        = verifyCtxFinalize ctx msgV
      ()                = bytes32Free msgS
      ()                = bytes32Free msgV
      ()                = bytes32Free pk
      ()                = closeArena h
  in MkUnr r

checkSignVerifyOk : signThenVerify LinearCrypto.msgA = True
checkSignVerifyOk = Refl

checkWrongMessageRejected : signThenVerify LinearCrypto.msgB = False
checkWrongMessageRejected = Refl

||| A context finalized with no signatures rejects.
emptyCtx : Bool
emptyCtx = runArena $ \1 h =>
  let B h ctx  = verifyCtxCreate h
      B h msg  = bytes32Create h msgA
      (r # msg) = verifyCtxFinalize ctx msg
      ()       = bytes32Free msg
      ()       = closeArena h
  in MkUnr r

checkEmptyCtxRejected : LinearCrypto.emptyCtx = False
checkEmptyCtxRejected = Refl
