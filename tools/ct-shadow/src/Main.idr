-- SPDX-License-Identifier: MPL-2.0
--
-- ct-shadow: non-authoritative shadow verifier for canonical CTP bytes.
--
-- Ported from tools/ats-shadow/main.dats (ATS2). For CI only.
--
-- Default checks: no CR, no TAB, exactly one final LF, no trailing space,
-- best-effort key ordering. See CanonChecks.
--
-- Options:
--   --summary FILE --check-digest     compare sha256 to the summary (needs sha256sum)
--   --canon-cmd CMD --check-idempotence   run an external canonicalizer, compare bytes
--   --self-test                       run built-in checks and exit
--
-- Differences from the ATS version: the file path given to `sha256sum` and to
-- the canonicalizer is single-quoted for the shell. `--canon-cmd` itself is
-- still a shell command by design, so only pass trusted values.
module Main

import System
import System.File
import Data.List
import Data.String

import Argon2Checks
import CanonChecks

%default covering

die : String -> IO a
die msg = do
  _ <- fPutStrLn stderr ("ct-shadow: FAIL: " ++ msg)
  exitWith (ExitFailure 1)

readAll : String -> IO String
readAll path = do
  Right s <- readFile path
    | Left err => die ("cannot read " ++ path ++ ": " ++ show err)
  pure s

shellQuote : String -> String
shellQuote s = "'" ++ concatMap esc (unpack s) ++ "'"
  where
    esc : Char -> String
    esc '\'' = "'\\''"
    esc c = singleton c

readPipe : File -> IO String
readPipe h = go ""
  where
    go : String -> IO String
    go acc = do
      eof <- fEOF h
      if eof then pure acc else do
        Right l <- fGetLine h
          | Left _ => pure acc
        go (acc ++ l)

runCapture : String -> IO String
runCapture cmd = do
  Right h <- popen cmd Read
    | Left err => die ("cannot run command: " ++ show err)
  out <- readPipe h
  status <- pclose h
  when (status /= 0) $
    die ("command failed (status " ++ show status ++ "): " ++ cmd)
  pure out

record Options where
  constructor MkOptions
  path : String
  summary : String
  checkDigest : Bool
  checkIdem : Bool
  canonCmd : String
  selfTest : Bool

parseArgs : Options -> List String -> IO Options
parseArgs o [] = pure o
parseArgs o ("--summary" :: f :: rest) = parseArgs ({ summary := f } o) rest
parseArgs o ["--summary"] = die "--summary requires a file"
parseArgs o ("--check-digest" :: rest) = parseArgs ({ checkDigest := True } o) rest
parseArgs o ("--check-idempotence" :: rest) = parseArgs ({ checkIdem := True } o) rest
parseArgs o ("--canon-cmd" :: c :: rest) = parseArgs ({ canonCmd := c } o) rest
parseArgs o ["--canon-cmd"] = die "--canon-cmd requires a command"
parseArgs o ("--self-test" :: rest) = parseArgs ({ selfTest := True } o) rest
parseArgs o (a :: rest) =
  if isPrefixOf "-" a then die ("unknown option: " ++ a)
  else parseArgs ({ path := a } o) rest

usage : String
usage = "usage: ct-shadow [--summary file.json --check-digest] [--canon-cmd \"ct canonicalize\" --check-idempotence] canonical.ctp"

-- ---------------------------------------------------------------------------
-- Self test (runtime). Covers the cases the type checker cannot reduce, and
-- the exact error text.

data Result = Pass | Fail String

check : String -> Bool -> Result
check name b = if b then Pass else Fail name

failsWith : String -> Either String () -> Bool
failsWith msg (Left m) = m == msg
failsWith _ _ = False

passes : Either String () -> Bool
passes (Right ()) = True
passes _ = False

selfChecks : List Result
selfChecks =
  [ check "canon: simple ok" (passes (checkCanonical "a: 1\nb: 2\n"))
  , check "canon: CR" (failsWith "CR detected: canonical bytes must be LF-only" (checkCanonical "a: 1\r\n"))
  , check "canon: TAB" (failsWith "TAB detected: canonical bytes must not contain TAB" (checkCanonical "a:\t1\n"))
  , check "canon: no final LF" (failsWith "file must end with exactly one LF (and not two)" (checkCanonical "a: 1"))
  , check "canon: two final LF" (failsWith "file must end with exactly one LF (and not two)" (checkCanonical "a: 1\n\n"))
  , check "canon: empty" (failsWith "file must end with exactly one LF (and not two)" (checkCanonical ""))
  , check "canon: trailing space" (failsWith "trailing whitespace before LF" (checkCanonical "a: 1 \n"))
  , check "canon: key order" (failsWith "key ordering violated at indent=0: b > a" (checkCanonical "b: 1\na: 2\n"))
  , check "canon: nested ok" (passes (checkCanonical "b:\n  a: 1\n  c: 2\nd: 3\n"))
  , check "canon: nested bad" (failsWith "key ordering violated at indent=2: c > a" (checkCanonical "b:\n  c: 1\n  a: 2\n"))
  , check "canon: non-key lines ignored" (passes (checkCanonical "z\na: 1\n"))
  , check "json: field" (extractJsonStringField "{\"digest_algorithm\": \"sha256\"}" "digest_algorithm" == Just "sha256")
  , check "json: missing" (extractJsonStringField "{\"x\": \"y\"}" "digest_value" == Nothing)
  , check "argon2: salt low msg" (failsWith "salt_bytes below minimum (16)" (validateSaltBytes 15))
  , check "argon2: memory high msg" (failsWith "memory_kib above maximum (1048576)" (validateMemoryKib 1048577))
  , check "argon2: unknown profile msg" (failsWith "unknown profile: turbo" (validateProfileName "turbo"))
  , check "argon2: upgrade msg" (failsWith "upgrade cannot decrease parallelism"
        (validateUpgrade (profileDefaults High) (profileDefaults Interactive)))
  , check "argon2: defaults valid"
      (all (passes . validateParams . profileDefaults) [Interactive, Moderate, High])
  ]

failName : Result -> Maybe String
failName Pass = Nothing
failName (Fail n) = Just n

runSelfTest : IO ()
runSelfTest = do
  let fails = mapMaybe failName selfChecks
  case fails of
    [] => putStrLn ("ct-shadow: OK: self-test passed (" ++ show (length selfChecks) ++ " checks)")
    _ => do
      traverse_ (\n => putStrLn ("ct-shadow: FAIL: self-test: " ++ n)) fails
      exitWith (ExitFailure 1)

-- ---------------------------------------------------------------------------

main : IO ()
main = do
  args <- getArgs
  o <- parseArgs (MkOptions "" "" False False "" False) (drop 1 args)
  when o.selfTest $ do
    runSelfTest
    exitSuccess
  when (o.path == "") $ die usage
  content <- readAll o.path
  case checkCanonical content of
    Left msg => die msg
    Right () => pure ()
  when o.checkDigest $ do
    when (o.summary == "") $ die "--check-digest requires --summary <file.json>"
    js <- readAll o.summary
    -- Documented field: manifest.canonical_bytes_sha256 (SHA-256 implied).
    expectedDigest <- case extractJsonStringField js "canonical_bytes_sha256" of
      Just d => pure (Just d)
      Nothing => case extractJsonStringField js "digest_algorithm" of
        Nothing => pure Nothing
        Just alg => do
          when (alg /= "sha256") $
            die ("unsupported digest_algorithm (expected sha256): " ++ alg)
          pure (extractJsonStringField js "digest_value")
    case expectedDigest of
      Nothing => die "summary.json missing manifest.canonical_bytes_sha256"
      Just expected => do
        out <- runCapture ("sha256sum " ++ shellQuote o.path ++ " 2>/dev/null")
        let got = firstWord out
        when (got /= expected) $
          die ("digest mismatch: expected=" ++ expected ++ " got=" ++ got)
  when o.checkIdem $ do
    when (o.canonCmd == "") $ die "--check-idempotence requires --canon-cmd \"<command>\""
    out <- runCapture (o.canonCmd ++ " " ++ shellQuote o.path ++ " 2>/dev/null")
    when (out /= content) $ die "idempotence failed: external canonicalizer output differs"
  putStrLn "ct-shadow: OK: all requested checks passed"
