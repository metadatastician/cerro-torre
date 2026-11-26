-- SPDX-License-Identifier: MPL-2.0
--
-- Argon2Checks: shadow model for Argon2id parameter validation.
--
-- Ported from tools/ats-shadow/argon2-checks.dats (ATS2).
-- Non-authoritative: for CI shadow verification only. It checks that
-- keystore policy parameters satisfy constraints. It does not implement
-- Argon2id (that is the SPARK core's job).
--
-- Checks:
--   * salt_bytes in [16, 32]
--   * hash_bytes in [32, 64]
--   * parallelism in [1, 8]
--   * memory_kib in [65536, 1048576]
--   * time_cost in [2, 10]
--   * profile name is valid
--   * an upgrade only increases parameters
module Argon2Checks

%default total

-- Bounds from spec/keystore-policy.json
public export saltBytesMin, saltBytesMax, hashBytesMin, hashBytesMax : Integer
saltBytesMin = 16
saltBytesMax = 32
hashBytesMin = 32
hashBytesMax = 64

public export parallelismMin, parallelismMax, memoryKibMin, memoryKibMax : Integer
parallelismMin = 1
parallelismMax = 8
memoryKibMin = 65536
memoryKibMax = 1048576

public export timeCostMin, timeCostMax : Integer
timeCostMin = 2
timeCostMax = 10

public export
record Argon2Params where
  constructor MkParams
  saltBytes   : Integer
  hashBytes   : Integer
  parallelism : Integer
  memoryKib   : Integer
  timeCost    : Integer

||| Ok, or the error message the ATS code returned.
public export
Validation : Type
Validation = Either String ()

public export
range : String -> Integer -> Integer -> Integer -> Validation
range name lo hi v =
  if v < lo then Left (name ++ " below minimum (" ++ show lo ++ ")")
  else if v > hi then Left (name ++ " above maximum (" ++ show hi ++ ")")
  else Right ()

public export
validateSaltBytes : Integer -> Validation
validateSaltBytes = range "salt_bytes" saltBytesMin saltBytesMax

public export
validateHashBytes : Integer -> Validation
validateHashBytes = range "hash_bytes" hashBytesMin hashBytesMax

public export
validateParallelism : Integer -> Validation
validateParallelism = range "parallelism" parallelismMin parallelismMax

public export
validateMemoryKib : Integer -> Validation
validateMemoryKib = range "memory_kib" memoryKibMin memoryKibMax

public export
validateTimeCost : Integer -> Validation
validateTimeCost = range "time_cost" timeCostMin timeCostMax

||| Full validation. Reports the first failing field, in the same order
||| as the ATS code (salt, hash, parallelism, memory, time).
public export
validateParams : Argon2Params -> Validation
validateParams p = do
  validateSaltBytes p.saltBytes
  validateHashBytes p.hashBytes
  validateParallelism p.parallelism
  validateMemoryKib p.memoryKib
  validateTimeCost p.timeCost

||| allow_increase_only: no field may go down. As in the ATS code this
||| does not re-check the bounds; call `validateParams` on the new value too.
public export
validateUpgrade : (old, new : Argon2Params) -> Validation
validateUpgrade old new =
  if new.saltBytes < old.saltBytes then Left "upgrade cannot decrease salt_bytes"
  else if new.hashBytes < old.hashBytes then Left "upgrade cannot decrease hash_bytes"
  else if new.parallelism < old.parallelism then Left "upgrade cannot decrease parallelism"
  else if new.memoryKib < old.memoryKib then Left "upgrade cannot decrease memory_kib"
  else if new.timeCost < old.timeCost then Left "upgrade cannot decrease time_cost"
  else Right ()

public export
data ProfileName = Interactive | Moderate | High | Unknown String

public export
parseProfile : String -> ProfileName
parseProfile "interactive" = Interactive
parseProfile "moderate" = Moderate
parseProfile "high" = High
parseProfile s = Unknown s

public export
validateProfileName : String -> Validation
validateProfileName s =
  case parseProfile s of
    Unknown n => Left ("unknown profile: " ++ n)
    _ => Right ()

||| Profile defaults. `Unknown` maps to all zeros, as in the ATS code,
||| so that it fails `validateParams`.
public export
profileDefaults : ProfileName -> Argon2Params
profileDefaults Interactive = MkParams 16 32 1 131072 3
profileDefaults Moderate    = MkParams 16 32 2 262144 4
profileDefaults High        = MkParams 16 32 4 524288 5
profileDefaults (Unknown _) = MkParams 0 0 0 0 0

-- Invariant: Argon2id output MUST NOT be used for artifact hashing.
--
-- The ATS code declared two abstract types and left them unused. Here
-- they are real: constructors are NOT exported, and there is no
-- conversion between them. Code outside this module cannot build one
-- from the other, so mixing them is a type error. Review and the CI
-- grep check still guard against importing Argon2 into artifact modules.

||| A digest of an artifact (not derived from Argon2).
export
data ArtifactDigest : Type where
  MkArtifactDigest : String -> ArtifactDigest

||| An Argon2id password verifier.
export
data PasswordVerifier : Type where
  MkPasswordVerifier : String -> PasswordVerifier

export
artifactDigestFromHex : String -> ArtifactDigest
artifactDigestFromHex = MkArtifactDigest

export
passwordVerifierFromEncoded : String -> PasswordVerifier
passwordVerifierFromEncoded = MkPasswordVerifier

export
artifactDigestHex : ArtifactDigest -> String
artifactDigestHex (MkArtifactDigest s) = s
