-- SPDX-License-Identifier: MPL-2.0
-- Linear Importer Safety (Idris2 port of verification/ats/importer_linear.dats)
--
-- Uses Idris2 QTT linear types (multiplicity 1) so that during (modelled)
-- tar extraction:
--   1. A `SafePath` can only be obtained from `validatePath`: the type is
--      abstract (constructor not exported) and `validatePath` is a real,
--      total, pure function that rejects absolute paths and ".." components.
--   2. File and directory handles are closed exactly once.
--   3. Extraction contexts are finalized exactly once.
--   4. Symlink link AND target paths must both pass `validatePath`.
--   5. An OCI layout extraction needs all three components (manifest,
--      blobs directory, layout file), enforced by an indexed type.
--   6. Tar-bomb limits (max_files, max_bytes, max_depth) are ENFORCED by
--      `extractCtxAddEntry` / `extractCtxFinalize`. In the ATS the
--      `extract_limits` record was declared but never consulted.
--
-- HONESTY NOTES:
--   * The ATS externs (`= "ext#"`) had no bodies. File/dir handles and the
--     extraction context here are a pure in-memory MODEL: nothing touches a
--     real filesystem, and writes are only counted. A runtime extractor must
--     still route every path through `validatePath` and every entry through
--     `extractCtxAddEntry` for these guarantees to mean anything.
--   * Joining a SafePath under the extraction root is not modelled; the
--     guarantee is about the relative path only (no absolute path, no "..").
--     Empty and "." components are dropped; NUL bytes are rejected. Other
--     platform-specific forms (e.g. Windows drive letters, backslashes) are
--     not handled.
--   * Symlink targets are validated with the same rule as entry paths (no
--     "..", not absolute), which is stricter than needed but keeps every
--     target inside the root.
--   * Byte counts are `Nat` (unbounded), so the limit arithmetic cannot
--     overflow.

module LinearImporter

import Data.List
import Data.List1
import Data.Maybe
import Data.String
import LinearCrypto

%default total

-- ============================================================================
-- Path Validation (pure, total, real)
-- ============================================================================

||| Split on '/', dropping empty and "." components.
public export
pathComponents : String -> List String
pathComponents s = filter keep (forget (split (== '/') s))
  where
    keep : String -> Bool
    keep c = c /= "" && c /= "."

||| The validation rule. Returns the normalised components if safe.
||| Rejects: absolute paths, any ".." component, NUL bytes, and paths that
||| normalise to nothing (e.g. "", ".", "./").
public export
checkPath : String -> Maybe (List String)
checkPath s =
  if isPrefixOf "/" s || isInfixOf "\0" s
     then Nothing
     else let cs = pathComponents s in
          if null cs || any (== "..") cs then Nothing else Just cs

public export
isSafePath : String -> Bool
isSafePath s = isJust (checkPath s)

-- ============================================================================
-- Linear resource types (abstract)
-- ============================================================================

||| A validated path. Constructor NOT exported: only `validatePath` makes one.
export
data SafePath = MkSafePath (List String)

||| A file handle that must be closed exactly once (model: path + bytes written).
export
data FileHandle = MkFile (List String) Nat

||| A directory handle that must be closed exactly once.
export
data DirHandle = MkDir (List String)

||| Port of `validate_path`: the ONLY producer of SafePath.
public export
validatePath : (1 _ : Arena) -> String -> Both Arena (LMaybe SafePath)
validatePath h s = case checkPath s of
  Nothing => B h LNothing
  Just cs => B h (LJust (MkSafePath cs))

public export
safePathFree : (1 _ : SafePath) -> ()
safePathFree (MkSafePath _) = ()

||| Borrow a safe path and render it.
public export
safePathToString : (1 _ : SafePath) -> Res String (const SafePath)
safePathToString (MkSafePath cs) = joinBy "/" cs # MkSafePath cs

||| Depth (number of components) of a safe path, borrowing it.
public export
safePathDepth : (1 _ : SafePath) -> Res Nat (const SafePath)
safePathDepth (MkSafePath cs) = length cs # MkSafePath cs

-- ============================================================================
-- File / Directory Operations (model)
-- ============================================================================

||| Open a file for writing; borrows the path.
public export
fileOpen : (1 _ : SafePath) -> Both SafePath FileHandle
fileOpen (MkSafePath cs) = B (MkSafePath cs) (MkFile cs 0)

||| Write bytes (model: only the length is recorded).
public export
fileWrite : (1 _ : FileHandle) -> List Bits8 -> FileHandle
fileWrite (MkFile p n) bs = MkFile p (n + length bs)

||| Close (consumes the handle).
public export
fileClose : (1 _ : FileHandle) -> ()
fileClose (MkFile _ _) = ()

public export
dirOpen : (1 _ : SafePath) -> Both SafePath DirHandle
dirOpen (MkSafePath cs) = B (MkSafePath cs) (MkDir cs)

public export
dirClose : (1 _ : DirHandle) -> ()
dirClose (MkDir _) = ()

-- ============================================================================
-- Single-entry extraction
-- ============================================================================

||| Port of `extract_entry_safe`: validate, open, write, close, free.
public export
extractEntrySafe : (1 _ : Arena) -> (root : String) -> (entryPath : String)
                -> List Bits8 -> Res Bool (const Arena)
extractEntrySafe h _ entryPath bytes =
  let B h mp = validatePath h entryPath in
  case mp of
    LNothing => False # h
    LJust p  =>
      let B p fh = fileOpen p
          fh     = fileWrite fh bytes
          ()     = fileClose fh
          ()     = safePathFree p
      in True # h

||| Port of `extract_and_close`: path borrowed, handle closed before return.
public export
extractAndClose : (1 _ : SafePath) -> List Bits8 -> SafePath
extractAndClose p bytes =
  let B p fh = fileOpen p
      fh     = fileWrite fh bytes
      ()     = fileClose fh
  in p

||| Port of `extract_with_error_handling` (identical shape: the handle is
||| closed on every path because nothing else can eliminate it).
public export
extractWithErrorHandling : (1 _ : Arena) -> (root : String) -> (entryPath : String)
                        -> List Bits8 -> Res Bool (const Arena)
extractWithErrorHandling = extractEntrySafe

-- BAD CODE (does NOT typecheck):
--
-- Forging a SafePath without validation:
--   extractUnsafe : String -> SafePath
--   extractUnsafe s = MkSafePath [s]   -- error: Name LinearImporter.MkSafePath is private.
--
-- Leaking a file handle:
--   leakFileHandle : (1 _ : SafePath) -> SafePath
--   leakFileHandle p = let B p fh = fileOpen p in p
--                      -- error: There are 0 uses of linear name fh.
--
-- Closing a file handle twice:
--   closeTwice : (1 _ : FileHandle) -> ()
--   closeTwice fh = let () = fileClose fh in fileClose fh
--                      -- error: fh is not accessible in this context.

-- ============================================================================
-- Tar Bomb Prevention (ENFORCED)
-- ============================================================================

public export
record ExtractLimits where
  constructor MkLimits
  maxFiles : Nat
  maxBytes : Nat
  maxDepth : Nat

||| The limits stated in the ATS comments: 1 million files, 10 GiB, depth 100.
public export
defaultLimits : ExtractLimits
defaultLimits = MkLimits 1000000 10737418240 100

||| Pure limit check (files so far, bytes so far, depth of the new entry).
public export
withinLimits : ExtractLimits -> (files : Nat) -> (bytes : Nat) -> (depth : Nat) -> Bool
withinLimits l f b d = f <= maxFiles l && b <= maxBytes l && d <= maxDepth l

||| Extraction context: root, limits, files, bytes, and a sticky ok flag.
export
data ExtractCtx = MkCtx String ExtractLimits Nat Nat Bool

public export
extractCtxCreate : (1 _ : Arena) -> (root : String) -> ExtractLimits -> Both Arena ExtractCtx
extractCtxCreate h root l = B h (MkCtx root l 0 0 True)

||| Add an entry of `size` bytes: consumes the safe path, updates counters and
||| poisons the context (sticky) as soon as any limit is exceeded.
public export
extractCtxAddEntry : (1 _ : ExtractCtx) -> (1 _ : SafePath) -> (size : Nat) -> ExtractCtx
extractCtxAddEntry (MkCtx r l f b ok) (MkSafePath cs) size =
  let f' = S f
      b' = b + size
  in MkCtx r l f' b' (ok && withinLimits l f' b' (length cs))

||| Mark the context failed (e.g. an entry path failed validation).
public export
extractCtxFail : (1 _ : ExtractCtx) -> ExtractCtx
extractCtxFail (MkCtx r l f b _) = MkCtx r l f b False

||| Borrow: is the context still within budget? Lets a loop stop early.
public export
extractCtxOk : (1 _ : ExtractCtx) -> Res Bool (const ExtractCtx)
extractCtxOk (MkCtx r l f b ok) = ok # MkCtx r l f b ok

||| Finalize (consumes the context). True only if no limit was exceeded and
||| no entry was rejected.
public export
extractCtxFinalize : (1 _ : ExtractCtx) -> Bool
extractCtxFinalize (MkCtx _ _ _ _ ok) = ok

||| Feed entries into the context. Stops as soon as the context is poisoned;
||| an entry whose path fails validation poisons it (fail-closed).
addAll : (1 _ : Arena) -> (1 _ : ExtractCtx) -> List (String, Nat) -> Both Arena ExtractCtx
addAll h ctx [] = B h ctx
addAll h ctx ((p, n) :: rest) =
  let (ok # ctx) = extractCtxOk ctx in
  case ok of
    False => B h ctx
    True  =>
      let B h mp = validatePath h p in
      case mp of
        LNothing => B h (extractCtxFail ctx)
        LJust sp => addAll h (extractCtxAddEntry ctx sp n) rest

||| Port of `extract_with_limits`, now with the limits actually enforced.
||| Entries are (path, size in bytes).
public export
extractWithLimits : (1 _ : Arena) -> (root : String) -> ExtractLimits
                 -> List (String, Nat) -> Res Bool (const Arena)
extractWithLimits h root limits entries =
  let B h ctx = extractCtxCreate h root limits
      B h ctx = addAll h ctx entries
  in -- Matching on the (linearly obtained) Bool releases it as unrestricted.
     case extractCtxFinalize ctx of
       True  => True # h
       False => False # h

-- ============================================================================
-- Symlink Attack Prevention
-- ============================================================================

||| Model of `symlink_create`: both paths borrowed, both already validated.
public export
symlinkCreate : (1 target : SafePath) -> (1 link : SafePath)
             -> Res Bool (const (Both SafePath SafePath))
symlinkCreate t l = True # B t l

||| Port of `extract_symlink_safe`: link AND target must validate.
public export
extractSymlinkSafe : (1 _ : Arena) -> (root : String) -> (linkPath : String)
                  -> (targetPath : String) -> Res Bool (const Arena)
extractSymlinkSafe h _ linkPath targetPath =
  let B h ml = validatePath h linkPath in
  case ml of
    LNothing => False # h
    LJust safeLink =>
      let B h mt = validatePath h targetPath in
      case mt of
        LNothing => let () = safePathFree safeLink in False # h
        LJust safeTarget =>
          let (ok # B safeTarget safeLink) = symlinkCreate safeTarget safeLink
              () = safePathFree safeTarget
              () = safePathFree safeLink
          in ok # h

-- ============================================================================
-- OCI Layout Enforcement
-- ============================================================================

public export
data OciKind = KManifest | KBlobs | KLayout

||| Indexed by kind, so each slot of `extractOciImage` accepts exactly one
||| constructor and all three must be supplied.
public export
data OciComponent : OciKind -> Type where
  ManifestJSON : (1 _ : SafePath)  -> OciComponent KManifest
  BlobsDir     : (1 _ : DirHandle) -> OciComponent KBlobs
  OCILayout    : (1 _ : SafePath)  -> OciComponent KLayout

||| Port of `extract_oci_image`: consumes all three components.
public export
extractOciImage : (1 _ : OciComponent KManifest) -> (1 _ : OciComponent KBlobs)
               -> (1 _ : OciComponent KLayout) -> Bool
extractOciImage (ManifestJSON m) (BlobsDir d) (OCILayout l) =
  let () = safePathFree m
      () = dirClose d
      () = safePathFree l
  in True

-- BAD CODE (does NOT typecheck): missing / misplaced component.
--   extractOciImage (ManifestJSON m) (OCILayout l) (OCILayout l2)
--   -- error: OciComponent KLayout is not OciComponent KBlobs

-- ============================================================================
-- Checks (evaluated by the type checker)
-- ============================================================================

checkRejectsDotDot : isSafePath "../x" = False
checkRejectsDotDot = Refl

checkRejectsInnerDotDot : isSafePath "a/../../etc/passwd" = False
checkRejectsInnerDotDot = Refl

checkRejectsAbsolute : isSafePath "/etc/passwd" = False
checkRejectsAbsolute = Refl

checkRejectsEmpty : isSafePath "" = False
checkRejectsEmpty = Refl

checkAcceptsRelative : checkPath "a/b" = Just ["a", "b"]
checkAcceptsRelative = Refl

checkNormalises : checkPath "./a//b/" = Just ["a", "b"]
checkNormalises = Refl

checkDotDotSubstringOk : isSafePath "a..b/c" = True
checkDotDotSubstringOk = Refl

||| Run a single-entry extraction through the linear API.
runEntry : String -> Bool
runEntry p = runArena $ \1 h =>
  let (ok # h) = extractEntrySafe h "/root" p [1, 2, 3]
      ()     = closeArena h
  in MkUnr ok

checkExtractRejectsTraversal : runEntry "../../etc/passwd" = False
checkExtractRejectsTraversal = Refl

checkExtractAccepts : runEntry "a/b" = True
checkExtractAccepts = Refl

runSymlink : String -> String -> Bool
runSymlink l t = runArena $ \1 h =>
  let (ok # h) = extractSymlinkSafe h "/root" l t
      ()     = closeArena h
  in MkUnr ok

checkSymlinkBadTarget : runSymlink "a/link" "/etc/shadow" = False
checkSymlinkBadTarget = Refl

checkSymlinkOk : runSymlink "a/link" "b/target" = True
checkSymlinkOk = Refl

runLimits : ExtractLimits -> List (String, Nat) -> Bool
runLimits l es = runArena $ \1 h =>
  let (ok # h) = extractWithLimits h "/root" l es
      ()     = closeArena h
  in MkUnr ok

small : ExtractLimits
small = MkLimits 2 100 2

checkLimitsOk : runLimits LinearImporter.small [("a", 10), ("b/c", 20)] = True
checkLimitsOk = Refl

checkTooManyFiles : runLimits LinearImporter.small [("a", 1), ("b", 1), ("c", 1)] = False
checkTooManyFiles = Refl

checkTooManyBytes : runLimits LinearImporter.small [("a", 60), ("b", 60)] = False
checkTooManyBytes = Refl

checkTooDeep : runLimits LinearImporter.small [("a/b/c", 1)] = False
checkTooDeep = Refl

checkBadPathPoisons : runLimits LinearImporter.small [("a", 1), ("../x", 1)] = False
checkBadPathPoisons = Refl
