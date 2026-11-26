-- SPDX-License-Identifier: MPL-2.0
--
-- CanonChecks: pure checks over canonical CTP bytes.
--
-- Ported from tools/ats-shadow/main.dats (ATS2). Non-authoritative: for CI
-- only. The SPARK core is the source of truth.
--
-- Default checks:
--   * no CR
--   * no TAB
--   * ends with exactly one LF
--   * no trailing space before LF
--   * best-effort key ordering for lines matching `^( *)key:`
-- Helper for the optional digest check: a small JSON string-field reader.
--
-- Each check returns `Left message` on failure. Main does the IO and exits.
module CanonChecks

import Data.List
import Data.String

%default total

||| True if the character occurs in the string.
public export
hasChar : Char -> String -> Bool
hasChar c s = elem c (unpack s)

||| Ends with an LF that is not preceded by another LF. An empty string fails.
public export
endsWithSingleLf : String -> Bool
endsWithSingleLf s =
  case reverse (unpack s) of
    '\n' :: '\n' :: _ => False
    '\n' :: _ => True
    _ => False

||| A space directly before an LF is an error. As in the ATS code, only
||| the space character counts here (TAB is rejected by its own check).
public export
noTrailingWs : List Char -> Char -> Bool
noTrailingWs [] _ = True
noTrailingWs ('\n' :: cs) prev = if prev == ' ' then False else noTrailingWs cs '\n'
noTrailingWs (c :: cs) _ = noTrailingWs cs c

public export
isKeyChar : Char -> Bool
isKeyChar ch =
  (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
  (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' || ch == '/'

||| If the line looks like `<spaces>key:`, give (indent, key).
public export
parseKeyColon : List Char -> Maybe (Nat, String)
parseKeyColon line =
  let (sp, rest) = span (== ' ') line
      (key, after) = span isKeyChar rest
  in case (key, after) of
       ([], _) => Nothing
       (_, ':' :: _) => Just (length sp, pack key)
       _ => Nothing

||| Last key seen at each indent, innermost first.
Frames : Type
Frames = List (Nat, String)

-- Drop frames deeper than `ind`.
popTo : Nat -> Frames -> Frames
popTo ind [] = []
popTo ind ((i, k) :: rest) = if i > ind then popTo ind rest else (i, k) :: rest

-- Replace or push the frame for `ind`.
setLast : Nat -> String -> Frames -> Frames
setLast ind key [] = [(ind, key)]
setLast ind key ((i, k) :: rest) =
  if i == ind then (ind, key) :: rest
  else if i < ind then (ind, key) :: (i, k) :: rest
  else setLast ind key rest

getLast : Nat -> Frames -> Maybe String
getLast ind [] = Nothing
getLast ind ((i, k) :: rest) = if i == ind then Just k else getLast ind rest

||| Keys at the same indent must not go down (byte order, like strcmp).
||| Returns the first violation as (indent, previous, current).
public export
keyOrderViolation : String -> Maybe (Nat, String, String)
keyOrderViolation s = go (lines s) []
  where
    go : List String -> Frames -> Maybe (Nat, String, String)
    go [] _ = Nothing
    go (l :: ls) st =
      case parseKeyColon (unpack l) of
        Nothing => go ls st
        Just (ind, key) =>
          let st1 = popTo ind st in
          case getLast ind st1 of
            Nothing => go ls (setLast ind key st1)
            Just prev =>
              if prev <= key then go ls (setLast ind key st1)
              else Just (ind, prev, key)

||| First position of `needle` in `hay`, returning the text from there on.
public export
findFrom : List Char -> List Char -> Maybe (List Char)
findFrom needle [] = if isNil needle then Just [] else Nothing
findFrom needle hay@(_ :: rest) =
  if isPrefixOf needle hay then Just hay else findFrom needle rest

dropUntil : Char -> List Char -> Maybe (List Char)
dropUntil c [] = Nothing
dropUntil c (x :: xs) = if x == c then Just (x :: xs) else dropUntil c xs

||| Minimal JSON string-field reader: finds `"field"`, then the next `:`,
||| then the next quoted string. Intentionally dumb but stable for CI.
public export
extractJsonStringField : String -> String -> Maybe String
extractJsonStringField js field = do
  p <- findFrom (unpack ("\"" ++ field ++ "\"")) (unpack js)
  p2 <- dropUntil ':' p
  p3 <- dropUntil '"' p2
  case p3 of
    [] => Nothing
    (_ :: body) => do
      _ <- dropUntil '"' body
      Just (pack (takeWhile (/= '"') body))

||| The text of `sha256sum` output up to the first space.
public export
firstWord : String -> String
firstWord s = pack (takeWhile (/= ' ') (unpack s))

||| Run the default checks, in the ATS order. `Right ()` means all pass.
public export
checkCanonical : String -> Either String ()
checkCanonical content = do
  when (hasChar '\r' content) $ Left "CR detected: canonical bytes must be LF-only"
  when (hasChar '\t' content) $ Left "TAB detected: canonical bytes must not contain TAB"
  unless (endsWithSingleLf content) $ Left "file must end with exactly one LF (and not two)"
  unless (noTrailingWs (unpack content) '\n') $ Left "trailing whitespace before LF"
  case keyOrderViolation content of
    Nothing => Right ()
    Just (ind, prev, key) =>
      Left ("key ordering violated at indent=" ++ show ind ++ ": " ++ prev ++ " > " ++ key)
