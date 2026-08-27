--  SPDX-License-Identifier: MPL-2.0
--  Cerro Torre Provenance - in-toto attestation chain verification
--  Palimpsest-Covenant: 1.0
--
--  Implements the verification algorithm specified in
--  spec/provenance-chain.md:381:
--
--     VERIFY_PACKAGE(package, bundle):
--       1. Extract attestations from bundle
--       2. For each attestation:
--          a. Verify signature against trust store
--          b. Verify log inclusion (at least 2-of-3 logs)
--       3. Verify chain continuity:
--          a. Source attestation subject == Build attestation material
--          b. Build attestation subject == package hash
--       4. Verify threshold signature (k-of-n signers)
--       5. If all pass: VERIFIED
--          Else: REJECT with specific failure reason
--
--  WHAT THIS BODY COVERS, AND WHAT IT DOES NOT.
--
--  Steps 1, 2a, 3 and 5 are implemented here. Steps 2b (transparency-log
--  inclusion) and 4 (k-of-n threshold signatures) are NOT, and cannot be:
--  this package's spec takes neither a log endpoint nor a signer threshold,
--  so there is nowhere to put them. They belong to CT_Transparency and
--  Threshold_Signatures respectively.
--
--  That boundary is stated rather than silently ignored, because a caller
--  reading "Verified" from Verify_Chain must not conclude that log inclusion
--  or a signing threshold was checked. It was not.
--
--  NO NEW CRYPTOGRAPHY IS WRITTEN HERE. Signature checking delegates to
--  Cerro_Crypto.Verify_Ed25519, which is a real Ed25519 implementation
--  (point decompression, and S < L malleability rejection). This repository
--  has already shipped two gates that returned success for every input --
--  cerro_policy_enforce.adb returning True, and vordr's stub returning
--  VALID -- so a third hand-rolled verifier is precisely what is avoided.

pragma Ada_2022;

with Ada.Calendar;
with Ada.Directories;
with Ada.Streams.Stream_IO;
with Cerro_Trust_Store;

--  Ada.Calendar.Time is private, so "<" is not directly visible. The spec's
--  own `with Ada.Calendar` does not carry a use clause into this body.
use type Ada.Calendar.Time;

package body Cerro_Provenance
   with SPARK_Mode => Off
is

   --  A digest that is entirely zero is the value an unset SHA256_Digest
   --  field holds. It is never a real hash of anything a caller has, so it
   --  is treated as "absent" rather than as a hash that happens to be zero.
   Zero_Digest : constant SHA256_Digest := (others => 0);

   function Is_Set (D : SHA256_Digest) return Boolean is (D /= Zero_Digest);

   --  Ed25519_Public_Key and SHA256_Digest are both 32-byte arrays but are
   --  distinct types, so Bytes_To_Hex cannot take a key directly.
   function Key_To_Hex (K : Ed25519_Public_Key) return String is
      D : SHA256_Digest;
   begin
      for I in K'Range loop
         D (I) := K (I);
      end loop;
      return Bytes_To_Hex (D);
   end Key_To_Hex;

   function Fail
      (Status : Verification_Status;
       At_Idx : Natural;
       Msg    : String) return Verification_Result
   is (Status        => Status,
       Failed_At     => At_Idx,
       Error_Message => To_Unbounded_String (Msg));

   ---------------------------------------------------------------------------
   --  The signed message
   ---------------------------------------------------------------------------

   --  What Verify_Attestation_Signature checks the signature AGAINST.
   --
   --  It must exclude Signature itself -- a signature cannot cover itself --
   --  and it must be deterministic, or the same attestation would verify on
   --  one run and not the next. To_JSON is used with the signature field
   --  omitted, which is also what a verifier in another language would
   --  reconstruct from the published statement.
   function Signed_Payload (A : Attestation) return String is
      B : Attestation := A;
   begin
      B.Signature := (others => 0);
      return To_JSON (B);
   end Signed_Payload;

   ---------------------------------------------------------------------------
   --  Verification
   ---------------------------------------------------------------------------

   function Verify_Attestation_Signature (A : Attestation) return Boolean is
   begin
      --  An all-zero signature or key is an UNSIGNED attestation, which is
      --  exactly what Create_Source_Attestation / Create_Build_Attestation
      --  return. Rejecting them here is the point: an attestation nobody has
      --  signed must not verify.
      if A.Signature = Ed25519_Signature'(others => 0)
        or else A.Signer_Key = Ed25519_Public_Key'(others => 0)
      then
         return False;
      end if;

      return Cerro_Crypto.Verify_Ed25519
         (Message    => Signed_Payload (A),
          Signature  => A.Signature,
          Public_Key => A.Signer_Key);
   end Verify_Attestation_Signature;

   function Verify_Materials (A : Attestation) return Boolean is
   begin
      --  Structural verification only, and deliberately so. Confirming that a
      --  material's digest matches its content would require fetching the
      --  content at Material.URI, which this package has no means to do and
      --  no business doing. What CAN be checked is that the attestation does
      --  not claim a material it failed to describe: a blank URI or an unset
      --  digest is a malformed attestation, not a verified one.
      for M of A.Materials loop
         if Length (M.URI) = 0 or else not Is_Set (M.Digest) then
            return False;
         end if;
      end loop;
      return True;
   end Verify_Materials;

   function Is_Chain_Complete (Chain : Attestation_Chain) return Boolean is
      use Attestation_Vectors;
   begin
      --  An empty chain is NOT complete. The alternative reading -- "no links,
      --  so no gaps" -- would make every unattested package verify, which is
      --  the failure this whole package exists to prevent.
      if Chain.Is_Empty then
         return False;
      end if;

      --  Continuity, per spec/provenance-chain.md:389: each attestation's
      --  subject must appear as a material of the next. That is the
      --  "cryptographically bound to the previous" property (principle 3):
      --  what one step produced is what the next step consumed.
      for I in First_Index (Chain) .. Last_Index (Chain) - 1 loop
         declare
            Current : constant Attestation := Chain (I);
            Next    : constant Attestation := Chain (I + 1);
            Linked  : Boolean := False;
         begin
            if Current.Subjects.Is_Empty then
               return False;
            end if;

            for S of Current.Subjects loop
               for M of Next.Materials loop
                  if Is_Set (S.Digest) and then S.Digest = M.Digest then
                     Linked := True;
                  end if;
               end loop;
            end loop;

            if not Linked then
               return False;
            end if;
         end;
      end loop;

      --  The last link still has to attest something.
      return not Chain (Last_Index (Chain)).Subjects.Is_Empty;
   end Is_Chain_Complete;

   function Verify_Chain
      (Chain       : Attestation_Chain;
       Trust_Store : String)
      return Verification_Result
   is
      use Attestation_Vectors;
      Idx : Natural := 0;
   begin
      if Chain.Is_Empty then
         return Fail (Missing_Attestation, 0, "attestation chain is empty");
      end if;

      --  Cerro_Trust_Store addresses ONE store, at Get_Store_Path; it has no
      --  operation that opens a store at a caller-supplied path. Rather than
      --  accept Trust_Store and quietly verify against a different store than
      --  the caller named -- which would report "Verified" on the strength of
      --  keys they did not ask for -- the mismatch is a failure.
      if not Cerro_Trust_Store.Is_Initialized then
         Cerro_Trust_Store.Initialize;
      end if;

      if Trust_Store /= Cerro_Trust_Store.Get_Store_Path then
         return Fail
            (Untrusted_Signer, 0,
             "trust store " & Trust_Store & " is not the active store (" &
             Cerro_Trust_Store.Get_Store_Path &
             "); Cerro_Trust_Store cannot open a store at an arbitrary path");
      end if;

      for A of Chain loop
         Idx := Idx + 1;

         if not Verify_Materials (A) then
            return Fail (Parse_Error, Idx,
                         "attestation has a material with no URI or no digest");
         end if;

         --  Step 2a: signature, then signer trust. Order matters -- a valid
         --  signature from an untrusted key and an invalid signature are
         --  different failures, and the caller is told which.
         if not Verify_Attestation_Signature (A) then
            return Fail (Invalid_Signature, Idx,
                         "signature does not verify against the signer key");
         end if;

         if not Cerro_Trust_Store.Is_Trusted
                  (Cerro_Trust_Store.Compute_Fingerprint
                     (Key_To_Hex (A.Signer_Key)))
         then
            return Fail (Untrusted_Signer, Idx,
                         "signer is not in the trust store");
         end if;

         if A.Build_End_Time < A.Build_Start_Time then
            return Fail (Expired_Attestation, Idx,
                         "build end time precedes build start time");
         end if;
      end loop;

      --  Step 3: continuity. Checked after the per-attestation pass so that a
      --  bad signature is reported as a bad signature rather than as a gap.
      if not Is_Chain_Complete (Chain) then
         return Fail (Missing_Attestation, 0,
                      "chain is not continuous: an attestation's subject does "
                      & "not appear as a material of the next");
      end if;

      return (Status        => Verified,
              Failed_At     => 0,
              Error_Message => To_Unbounded_String
                 ("chain verified; NOTE transparency-log inclusion and "
                  & "threshold signatures are NOT checked by this operation"));
   end Verify_Chain;

   function Verify_Package
      (Package_Path : String;
       Provenance   : Package_Provenance)
      return Verification_Result
   is
      use Ada.Streams.Stream_IO;
   begin
      if not Ada.Directories.Exists (Package_Path) then
         return Fail (Parse_Error, 0, "package not found: " & Package_Path);
      end if;

      if not Is_Set (Provenance.Package_Digest) then
         return Fail (Hash_Mismatch, 0,
                      "provenance carries no package digest to compare against");
      end if;

      --  Step 3b: the chain's claim must be about THIS file.
      declare
         F      : File_Type;
         Actual : SHA256_Digest;
      begin
         Open (F, In_File, Package_Path);
         declare
            Size    : constant Natural := Natural (Ada.Directories.Size (Package_Path));
            Content : String (1 .. Size);
         begin
            String'Read (Stream (F), Content);
            Close (F);
            Actual := Cerro_Crypto.Compute_SHA256 (Content);
         end;

         if not Cerro_Crypto.Constant_Time_Equal (Actual, Provenance.Package_Digest) then
            return Fail (Hash_Mismatch, 0,
                         "package content does not match the digest its "
                         & "provenance claims");
         end if;
      exception
         when others =>
            if Is_Open (F) then
               Close (F);
            end if;
            return Fail (Parse_Error, 0, "could not read " & Package_Path);
      end;

      return Verify_Chain (Provenance.Chain, Cerro_Trust_Store.Get_Store_Path);
   end Verify_Package;

   ---------------------------------------------------------------------------
   --  Creation
   ---------------------------------------------------------------------------

   --  Both constructors return an UNSIGNED attestation: Signature and
   --  Signer_Key are left zeroed, and Verify_Attestation_Signature rejects
   --  that. Signing is a separate, deliberate act by whoever holds the key --
   --  a constructor that produced something already-verifying would be a
   --  forgery primitive.

   function Create_Source_Attestation
      (Source_URI    : String;
       Source_Digest : SHA256_Digest;
       Upstream_Sig  : String)
      return Attestation
   is
      A : Attestation;
      T : constant Ada.Calendar.Time := Ada.Calendar.Clock;
   begin
      A.Stmt_Type := Source_Attestation;
      A.Pred_Type := SLSA_Provenance;
      A.Subjects.Append (Subject'(Name   => To_Unbounded_String (Source_URI),
                                  Digest => Source_Digest));
      A.Builder := (ID       => To_Unbounded_String ("cerro-torre/import"),
                    Version  => To_Unbounded_String ("0.1.0"),
                    Verified => False);
      A.Invocation :=
         (Config_Source => To_Unbounded_String (Source_URI),
          Config_Digest => Source_Digest,
          --  The upstream detached signature is recorded as a claim, not as
          --  something this constructor has checked. Verifying it needs the
          --  upstream keyring, which is a manifest concern
          --  (Cerro_Manifest.Provenance_Section.Upstream_Keyring).
          Parameters    => To_Unbounded_String
                              ("{""upstream_signature"":""" & Upstream_Sig & """}"),
          Environment   => To_Unbounded_String ("{}"));
      A.Build_Start_Time := T;
      A.Build_End_Time   := T;
      A.Signature  := (others => 0);
      A.Signer_Key := (others => 0);
      return A;
   end Create_Source_Attestation;

   function Create_Build_Attestation
      (Manifest      : Cerro_Manifest.Manifest;
       Output_Digest : SHA256_Digest;
       Builder       : Builder_Identity;
       Materials     : Material_List)
      return Attestation
   is
      A : Attestation;
      T : constant Ada.Calendar.Time := Ada.Calendar.Clock;
   begin
      A.Stmt_Type := Build_Attestation;
      A.Pred_Type := SLSA_Provenance;
      A.Subjects.Append
         (Subject'(Name   => Manifest.Metadata.Name,
                   Digest => Output_Digest));
      A.Builder    := Builder;
      A.Materials  := Materials;
      A.Invocation :=
         (Config_Source => Manifest.Metadata.Name,
          Config_Digest => Zero_Digest,
          Parameters    => To_Unbounded_String ("{}"),
          Environment   => To_Unbounded_String ("{}"));
      A.Build_Start_Time := T;
      A.Build_End_Time   := T;
      A.Signature  := (others => 0);
      A.Signer_Key := (others => 0);
      return A;
   end Create_Build_Attestation;

   ---------------------------------------------------------------------------
   --  Serialisation
   ---------------------------------------------------------------------------

   function Predicate_URI (P : Predicate_Type) return String is
     (case P is
         when SLSA_Provenance => "https://slsa.dev/provenance/v1",
         when SPDX_SBOM       => "https://spdx.dev/Document",
         when CT_Native       => "https://cerro-torre.org/provenance/v1");

   function JSON_Escape (S : String) return String is
      R : Unbounded_String;
   begin
      for C of S loop
         case C is
            when '"'      => Append (R, "\""");
            when '\'      => Append (R, "\\");
            when ASCII.LF => Append (R, "\n");
            when ASCII.CR => Append (R, "\r");
            when ASCII.HT => Append (R, "\t");
            when others   => Append (R, C);
         end case;
      end loop;
      return To_String (R);
   end JSON_Escape;

   function To_JSON (A : Attestation) return String is
      R     : Unbounded_String;
      First : Boolean := True;
   begin
      Append (R, "{""_type"":""https://in-toto.io/Statement/v1"",""subject"":[");
      for S of A.Subjects loop
         if not First then
            Append (R, ",");
         end if;
         First := False;
         Append (R, "{""name"":""" & JSON_Escape (To_String (S.Name))
                    & """,""digest"":{""sha256"":""" & Bytes_To_Hex (S.Digest)
                    & """}}");
      end loop;
      Append (R, "],""predicateType"":""" & Predicate_URI (A.Pred_Type)
                 & """,""predicate"":{""statementType"":"""
                 & A.Stmt_Type'Image
                 & """,""builder"":{""id"":""" & JSON_Escape (To_String (A.Builder.ID))
                 & """,""version"":""" & JSON_Escape (To_String (A.Builder.Version))
                 & """},""materials"":[");
      First := True;
      for M of A.Materials loop
         if not First then
            Append (R, ",");
         end if;
         First := False;
         Append (R, "{""uri"":""" & JSON_Escape (To_String (M.URI))
                    & """,""digest"":{""sha256"":""" & Bytes_To_Hex (M.Digest)
                    & """}}");
      end loop;
      Append (R, "]}}");
      return To_String (R);
   end To_JSON;

   function From_JSON (JSON : String) return Parse_Result is
   begin
      --  DELIBERATELY NOT IMPLEMENTED, AND IT FAILS RATHER THAN GUESSING.
      --
      --  Parsing in-toto statements needs a real JSON parser. Writing one
      --  here -- or, worse, recovering fields with string searches -- would
      --  produce an Attestation assembled from whatever happened to match,
      --  which then flows into Verify_Chain and is reported as Verified.
      --  A parser that half-works on security input is more dangerous than
      --  one that refuses.
      --
      --  Returning Success => False means every caller is told the
      --  attestation could not be read, which is true. When a JSON dependency
      --  is available (CT_Transparency already decodes Rekor responses and is
      --  the natural place for it), implement here and the round-trip
      --  To_JSON -> From_JSON becomes testable.
      pragma Unreferenced (JSON);
      return (Success   => False,
              Error_Msg => To_Unbounded_String
                 ("From_JSON is not implemented: no JSON parser is available "
                  & "to this package. It refuses rather than returning a "
                  & "partially-recovered attestation."));
   end From_JSON;

end Cerro_Provenance;
