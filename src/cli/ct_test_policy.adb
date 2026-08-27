--  SPDX-License-Identifier: MPL-2.0
--  ct_test_policy - Cerro.Policy enforcement must FAIL CLOSED
--
--  Enforce_Policy returns Pass or Fail, so the dangerous defect is one that
--  PASSES. Every requirement type it understands is currently backed by a
--  stub, and the question each test asks is the same: does the stub DENY?
--
--  Three of the five already did (Min_Signatures, SBOM_Required,
--  Attestation_Required all deny on their stub values). Two did not:
--
--    Registry_Allowlist  compared a hardcoded "docker.io" against a policy
--                        that Load_Policy never parses, through an
--                        Allows_Registry that read an empty allowlist as
--                        "allow all" -- three stubs compounding into a permit
--    Build_Attestation   was `null`, so requiring an attestation was
--                        satisfied by doing nothing
--
--  The last test is the control: a policy with no enabled requirements must
--  still PASS, or this suite would be satisfied by an Enforce_Policy that
--  refused everything, which is the mirror-image fake gate.

with Ada.Command_Line;
with Ada.Text_IO;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Cerro.Policy.A2ML;
with Cerro.Policy.Enforce;

procedure CT_Test_Policy is
   use Ada.Text_IO;
   use Cerro.Policy.A2ML;
   use Cerro.Policy.Enforce;
   use type Cerro.Policy.Enforce.Verification_Result;

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

   --  A policy carrying exactly one enabled requirement of the given kind.
   function Policy_Requiring (Kind : Policy_Requirement_Type) return Policy_Handle is
      P : Policy;
      R : Policy_Requirement;
      H : Policy_Handle;
   begin
      P.ID      := ID_Strings.To_Bounded_String ("test-policy");
      P.Version := ID_Strings.To_Bounded_String ("1.0");
      R.Req_Type := Kind;
      R.Enabled  := True;
      R.Min_Sigs := 1;
      P.Requirements.Append (R);
      H.Pol   := P;
      H.Valid := True;
      return H;
   end Policy_Requiring;

   function Empty_Policy return Policy_Handle is
      P : Policy;
      H : Policy_Handle;
   begin
      P.ID      := ID_Strings.To_Bounded_String ("empty-policy");
      P.Version := ID_Strings.To_Bounded_String ("1.0");
      H.Pol   := P;
      H.Valid := True;
      return H;
   end Empty_Policy;

   --  Enforce_Policy has Pre => Is_Valid (Bundle) and Is_Valid (Pol), and
   --  Is_Valid is just the Valid flag — so a default-initialised handle
   --  violates the precondition rather than exercising the body. Both handles
   --  are marked valid here so the tests reach the enforcement logic they are
   --  actually about.
   Bundle : constant Bundle_Handle :=
      (Path  => Path_Strings.To_Bounded_String ("/tmp/test-bundle.ctp"),
       Valid => True);

begin
   Put_Line ("Cerro.Policy enforcement — fail-closed tests");
   Put_Line ("");

   ---------------------------------------------------------------------------
   Put_Line ("Every stubbed requirement must DENY");
   ---------------------------------------------------------------------------

   declare
      D : constant Verification_Details :=
         Enforce_Policy (Bundle, Policy_Requiring (Registry_Allowlist));
   begin
      --  The one that used to pass. Three stubs compounded into a permit:
      --  a hardcoded registry, an unparsed policy, and an empty allowlist
      --  read as "allow all".
      Check ("Registry_Allowlist denies while it cannot be evaluated",
             D.Result = Fail);
      Check ("...and says why, rather than failing mutely",
             Short_Strings.Length (D.Reason) > 0);
      Check ("...and does not claim the registry was allowed",
             not D.Registry_Allowed);
   end;

   declare
      D : constant Verification_Details :=
         Enforce_Policy (Bundle, Policy_Requiring (Build_Attestation));
   begin
      --  This arm was `null` — requiring an attestation was satisfied by
      --  doing nothing at all.
      Check ("Build_Attestation denies while SLSA verification is unimplemented",
             D.Result = Fail);
      Check ("...and says why", Short_Strings.Length (D.Reason) > 0);
   end;

   declare
      D : constant Verification_Details :=
         Enforce_Policy (Bundle, Policy_Requiring (Min_Signatures));
   begin
      Check ("Min_Signatures denies (found 0, required 1)", D.Result = Fail);
   end;

   declare
      D : constant Verification_Details :=
         Enforce_Policy (Bundle, Policy_Requiring (SBOM_Required));
   begin
      Check ("SBOM_Required denies while no SBOM is read", D.Result = Fail);
   end;

   declare
      D : constant Verification_Details :=
         Enforce_Policy (Bundle, Policy_Requiring (Attestation_Required));
   begin
      Check ("Attestation_Required denies while Rekor is unverified",
             D.Result = Fail);
   end;

   ---------------------------------------------------------------------------
   Put_Line ("");
   Put_Line ("An unreadable allowlist must not read as permission");
   ---------------------------------------------------------------------------

   declare
      P : Policy;
   begin
      --  Empty means "unconfigured OR unloadable OR broken" — and Load_Policy
      --  never parses the file, so EVERY policy it returns has an empty
      --  allowlist. Treating that as allow-all made the policy engine a no-op.
      Check ("an empty allowlist denies rather than permitting everything",
             not Allows_Registry (P, "docker.io"));
      Check ("...for any registry, not just one",
             not Allows_Registry (P, "ghcr.io"));
   end;

   declare
      P : Policy;
   begin
      --  The control for that rule: an allowlist with an entry still permits
      --  the entry it names, so the deny above is discrimination and not a
      --  blanket refusal.
      P.Allowed_Registries.Append
         (Short_Strings.To_Bounded_String ("ghcr.io"));
      Check ("a populated allowlist still ADMITS the registry it names",
             Allows_Registry (P, "ghcr.io"));
      Check ("...and still denies one it does not",
             not Allows_Registry (P, "evil.example"));
   end;

   ---------------------------------------------------------------------------
   Put_Line ("");
   Put_Line ("THE CONTROL — enforcement must not deny everything");
   ---------------------------------------------------------------------------

   declare
      D : constant Verification_Details := Enforce_Policy (Bundle, Empty_Policy);
   begin
      --  Without this, every test above could be satisfied by an
      --  Enforce_Policy that refused unconditionally — the mirror-image fake
      --  gate. A policy that requires nothing has nothing to fail.
      Check ("a policy with no enabled requirements PASSES " &
             "(else the suite passes by denying everything)",
             D.Result = Pass);
   end;

   ---------------------------------------------------------------------------
   Put_Line ("");
   if Failures = 0 then
      Put_Line ("All policy tests passed.");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
   else
      Put_Line (Failures'Image & " policy test(s) FAILED.");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end CT_Test_Policy;
