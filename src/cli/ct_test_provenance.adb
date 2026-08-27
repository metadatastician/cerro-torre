--  SPDX-License-Identifier: MPL-2.0
--  ct_test_provenance - Cerro_Provenance verification tests
--
--  These are mostly DENIAL tests. Every operation in Cerro_Provenance returns
--  Boolean or Verification_Result, so the failure mode that matters is one
--  that PERMITS: a chain check returning True for an empty chain, or a
--  signature check returning True for an unsigned attestation, would be a
--  fake gate of exactly the kind this repository has already shipped twice
--  (cerro_policy_enforce.adb returning True; vordr's stub returning VALID).
--
--  So each test below constructs something that MUST be rejected and asserts
--  that it is. Test 5 is the control: a well-formed chain that must be
--  ACCEPTED. Without it the whole suite could pass by denying everything,
--  which is the mirror-image fake gate.

with Ada.Command_Line;
with Ada.Text_IO;
with Ada.Calendar;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Cerro_Crypto;
with Cerro_Provenance;

procedure CT_Test_Provenance is
   use Ada.Text_IO;
   use Cerro_Crypto;
   use Cerro_Provenance;
   use type Cerro_Provenance.Verification_Status;

   --  Verification_Result is declared in BOTH Cerro_Crypto (an enum,
   --  cerro_crypto.ads:109) and Cerro_Provenance (a record,
   --  cerro_provenance.ads:129). Using both packages -- the normal case for
   --  anything doing provenance -- makes the bare name ambiguous, so it is
   --  named explicitly here rather than relying on which use clause wins.
   subtype Prov_Result is Cerro_Provenance.Verification_Result;

   Failures : Natural := 0;

   procedure Check (Name : String; Condition : Boolean) is
   begin
      if Condition then
         Put_Line ("  PASS  " & Name);
      else
         Put_Line ("  FAIL  " & Name);
         Failures := Failures + 1;
      end if;
   end Check;

   function Digest_Of (Seed : String) return SHA256_Digest is
     (Compute_SHA256 (Seed));

   --  A minimally well-formed attestation whose subject is Subject_Digest and
   --  which consumes Material_Digest, so chains can be built by hand.
   function Make
      (Subject_Digest  : SHA256_Digest;
       Material_Digest : SHA256_Digest;
       With_Material   : Boolean := True) return Attestation
   is
      A : Attestation;
      T : constant Ada.Calendar.Time := Ada.Calendar.Clock;
   begin
      A.Stmt_Type := Build_Attestation;
      A.Pred_Type := SLSA_Provenance;
      A.Subjects.Append (Subject'(Name   => To_Unbounded_String ("pkg"),
                                  Digest => Subject_Digest));
      if With_Material then
         A.Materials.Append (Material'(URI    => To_Unbounded_String ("src://x"),
                                       Digest => Material_Digest));
      end if;
      A.Builder := (ID       => To_Unbounded_String ("test"),
                    Version  => To_Unbounded_String ("0"),
                    Verified => False);
      A.Invocation := (Config_Source => To_Unbounded_String ("m"),
                       Config_Digest => Subject_Digest,
                       Parameters    => To_Unbounded_String ("{}"),
                       Environment   => To_Unbounded_String ("{}"));
      A.Build_Start_Time := T;
      A.Build_End_Time   := T;
      A.Signature  := (others => 0);
      A.Signer_Key := (others => 0);
      return A;
   end Make;

   D_Source : constant SHA256_Digest := Digest_Of ("upstream tarball");
   D_Build  : constant SHA256_Digest := Digest_Of ("built artefact");
   D_Other  : constant SHA256_Digest := Digest_Of ("unrelated");

begin
   Put_Line ("Cerro_Provenance verification tests");
   Put_Line ("");

   ---------------------------------------------------------------------------
   Put_Line ("Signature verification must DENY");
   ---------------------------------------------------------------------------

   --  This is the one that matters most. Create_* returns an UNSIGNED
   --  attestation; if that verified, the constructors would be a forgery
   --  primitive -- anyone could manufacture provenance without a key.
   declare
      A : constant Attestation :=
         Create_Source_Attestation ("https://example.org/x.tar.gz", D_Source, "");
   begin
      Check ("a freshly created source attestation is UNSIGNED and does not verify",
             not Verify_Attestation_Signature (A));
   end;

   declare
      A : Attestation := Make (D_Build, D_Source);
   begin
      A.Signature (1) := 42;  --  signature set, key still absent
      Check ("an attestation with a signature but no signer key does not verify",
             not Verify_Attestation_Signature (A));

      A.Signer_Key (1) := 7;  --  both present, but not a real signature
      Check ("a fabricated signature does not verify against a real Ed25519 check",
             not Verify_Attestation_Signature (A));
   end;

   ---------------------------------------------------------------------------
   Put_Line ("");
   Put_Line ("Chain completeness must DENY");
   ---------------------------------------------------------------------------

   declare
      Empty : Attestation_Chain;
   begin
      --  "No links, so no gaps" would make every unattested package verify.
      Check ("an EMPTY chain is not complete",
             not Is_Chain_Complete (Empty));
   end;

   declare
      C : Attestation_Chain;
   begin
      --  Source produces D_Source; build consumes D_Other. Nothing links them.
      C.Append (Make (D_Source, D_Other));
      C.Append (Make (D_Build,  D_Other));
      Check ("a chain whose link does not match is not complete",
             not Is_Chain_Complete (C));
   end;

   declare
      C : Attestation_Chain;
   begin
      C.Append (Make (D_Source, D_Other));
      C.Append (Make (D_Build,  D_Source, With_Material => False));
      Check ("a chain whose next step consumes NOTHING is not complete",
             not Is_Chain_Complete (C));
   end;

   ---------------------------------------------------------------------------
   Put_Line ("");
   Put_Line ("THE CONTROL -- a well-formed chain must be ACCEPTED");
   ---------------------------------------------------------------------------

   declare
      C : Attestation_Chain;
   begin
      --  Step 1 produces D_Source; step 2 consumes exactly that, and produces
      --  D_Build. This is the continuity rule of spec/provenance-chain.md:389.
      C.Append (Make (D_Source, D_Other));
      C.Append (Make (D_Build,  D_Source));
      Check ("a correctly linked chain IS complete " &
             "(without this the suite could pass by denying everything)",
             Is_Chain_Complete (C));
   end;

   ---------------------------------------------------------------------------
   Put_Line ("");
   Put_Line ("Material validation must DENY");
   ---------------------------------------------------------------------------

   declare
      A : Attestation := Make (D_Build, D_Source);
   begin
      Check ("well-formed materials pass (control)", Verify_Materials (A));

      A.Materials.Clear;
      A.Materials.Append (Material'(URI    => To_Unbounded_String (""),
                                    Digest => D_Source));
      Check ("a material with no URI is rejected", not Verify_Materials (A));

      A.Materials.Clear;
      A.Materials.Append (Material'(URI    => To_Unbounded_String ("src://x"),
                                    Digest => (others => 0)));
      Check ("a material with an unset digest is rejected",
             not Verify_Materials (A));
   end;

   ---------------------------------------------------------------------------
   Put_Line ("");
   Put_Line ("Verify_Chain reports a NAMED reason");
   ---------------------------------------------------------------------------

   declare
      Empty : Attestation_Chain;
      R     : constant Prov_Result := Verify_Chain (Empty, "/nonexistent");
   begin
      Check ("an empty chain gives Missing_Attestation, not Verified",
             R.Status = Missing_Attestation);
      Check ("...and it is not reported as Verified",
             R.Status /= Verified);
   end;

   declare
      C : Attestation_Chain;
      R : Prov_Result;
   begin
      C.Append (Make (D_Source, D_Other));
      R := Verify_Chain (C, "/definitely/not/the/active/store");
      --  Cerro_Trust_Store can only address one store. Accepting a path it
      --  cannot honour and verifying against a DIFFERENT store would report
      --  success on the strength of keys the caller never named.
      Check ("a trust-store path that cannot be honoured is refused, not ignored",
             R.Status = Untrusted_Signer);
      Check ("...and the reason names the mismatch",
             Length (R.Error_Message) > 0);
   end;

   ---------------------------------------------------------------------------
   Put_Line ("");
   Put_Line ("Serialisation");
   ---------------------------------------------------------------------------

   declare
      A : constant Attestation := Make (D_Build, D_Source);
      J : constant String := To_JSON (A);
   begin
      Check ("To_JSON emits an in-toto Statement",
             J'Length > 0);
      Check ("...carrying the subject digest as hex",
             (for some I in J'Range =>
                I + Bytes_To_Hex (D_Build)'Length - 1 <= J'Last
                and then J (I .. I + Bytes_To_Hex (D_Build)'Length - 1)
                         = Bytes_To_Hex (D_Build)));
   end;

   declare
      P : constant Parse_Result := From_JSON ("{""_type"":""x""}");
   begin
      --  From_JSON is deliberately unimplemented. It must REFUSE rather than
      --  return a partially-recovered attestation that then flows into
      --  Verify_Chain and is reported as Verified.
      Check ("From_JSON refuses rather than guessing", not P.Success);
   end;

   ---------------------------------------------------------------------------
   Put_Line ("");
   if Failures = 0 then
      Put_Line ("All provenance tests passed.");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
   else
      Put_Line (Failures'Image & " provenance test(s) FAILED.");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end CT_Test_Provenance;
