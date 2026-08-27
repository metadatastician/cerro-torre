-- SPDX-License-Identifier: MPL-2.0
-- Cerro Torre Policy Enforcement Engine - Implementation

pragma Ada_2022;

with Ada.Text_IO;
with Ada.Calendar;
with Ada.Calendar.Formatting;

package body Cerro.Policy.Enforce with
   SPARK_Mode => Off
is

   --  All THREE bounded-string instantiations must be use-d. A2ML declares
   --  ID_Strings/Short_Strings/Path_Strings as separate instantiations of
   --  Generic_Bounded_Length, which makes them three unrelated private types
   --  with three separate To_String operations. ID_Strings was missing, so
   --  To_String (Pol.Pol.ID) at :201 had no candidate that matched.
   --  cerro-policy-a2ml.adb use-s all three; this body did not.
   use ID_Strings;
   use Short_Strings;
   use Path_Strings;

   ----------------------
   -- Enforce_Policy  --
   ----------------------

   function Enforce_Policy
     (Bundle : Bundle_Handle;
      Pol    : Policy_Handle) return Verification_Details
   is
      Details : Verification_Details;
   begin
      Details.Result := Pass;  -- Optimistic start
      Details.Reason := To_Bounded_String ("Policy enforcement in progress");

      -- Initialize counts
      Details.Signatures_Found := 0;
      Details.Signatures_Required := 0;
      Details.SBOM_Present := False;
      Details.Rekor_Verified := False;
      Details.Registry_Allowed := True;

      -- Check each requirement
      for Req of Pol.Pol.Requirements loop
         if Req.Enabled then
            case Req.Req_Type is
               when Min_Signatures =>
                  Details.Signatures_Required := Req.Min_Sigs;
                  -- TODO: Count actual signatures in bundle
                  Details.Signatures_Found := 0;  -- Stub

                  if Details.Signatures_Found < Details.Signatures_Required then
                     Details.Result := Fail;
                     Details.Reason := To_Bounded_String
                       ("Insufficient signatures: found" &
                        Details.Signatures_Found'Image &
                        ", required" &
                        Details.Signatures_Required'Image);
                     return Details;
                  end if;

               when SBOM_Required =>
                  -- TODO: Check bundle for SBOM
                  Details.SBOM_Present := False;  -- Stub

                  if not Details.SBOM_Present then
                     Details.Result := Fail;
                     Details.Reason := To_Bounded_String
                       ("SBOM required but not found");
                     return Details;
                  end if;

               when Attestation_Required =>
                  -- TODO: Verify Rekor entry
                  Details.Rekor_Verified := False;  -- Stub

                  if not Details.Rekor_Verified then
                     Details.Result := Fail;
                     Details.Reason := To_Bounded_String
                       ("Rekor attestation required but not verified");
                     return Details;
                  end if;

               when Registry_Allowlist =>
                  --  FAIL-CLOSED. This requirement cannot be evaluated yet,
                  --  and until it can it must DENY rather than pass.
                  --
                  --  Three stubs used to compound into a permit:
                  --
                  --    1. the bundle's registry was never extracted -- the
                  --       check ran against a hardcoded "docker.io";
                  --    2. Cerro.Policy.A2ML.Load_Policy never parses the
                  --       policy file (its own body says "TODO: Actually
                  --       parse the A2ML file"), so Allowed_Registries is
                  --       always empty; and
                  --    3. Allows_Registry treats an empty allowlist as
                  --       "allow all".
                  --
                  --  So this arm asked whether a registry the bundle does not
                  --  use is permitted by a policy that was never read, and the
                  --  answer was always yes. The sibling arms -- Min_Signatures,
                  --  SBOM_Required, Attestation_Required -- already deny on
                  --  their stub values; this one and Build_Attestation were the
                  --  only two that did not.
                  --
                  --  TODO: extract the registry from the bundle, and parse the
                  --  policy, then restore a real allowlist check.
                  Details.Registry_Allowed := False;
                  Details.Result := Fail;
                  Details.Reason := To_Bounded_String
                    ("Registry allowlist cannot be evaluated: bundle registry "
                     & "not extracted and policy file not parsed");
                  return Details;

               when Build_Attestation =>
                  --  FAIL-CLOSED, same reasoning. This was `null`, so a policy
                  --  requiring a build attestation was satisfied by doing
                  --  nothing at all -- a gate that could not fail.
                  --
                  --  TODO: verify SLSA provenance through
                  --  Cerro_Provenance.Verify_Chain once bundles carry a chain.
                  Details.Result := Fail;
                  Details.Reason := To_Bounded_String
                    ("Build attestation required, but SLSA provenance "
                     & "verification is not implemented");
                  return Details;
            end case;
         end if;
      end loop;

      -- All checks passed
      Details.Result := Pass;
      Details.Reason := To_Bounded_String ("All policy requirements satisfied");

      return Details;
   end Enforce_Policy;

   ------------------------
   -- Check_Signatures  --
   ------------------------

   function Check_Signatures
     (Bundle : Bundle_Handle;
      Pol    : Policy_Handle;
      Store  : Trust_Store) return Verification_Details
   is
      Details : Verification_Details;
   begin
      -- MVP stub
      Details.Result := Inconclusive;
      Details.Reason := To_Bounded_String ("Signature verification not implemented");
      Details.Signatures_Found := 0;
      Details.Signatures_Required := 0;

      -- TODO: Extract signatures from bundle
      -- TODO: Verify each signature against trust store
      -- TODO: Count valid signatures

      return Details;
   end Check_Signatures;

   ------------------
   -- Check_SBOM  --
   ------------------

   function Check_SBOM
     (Bundle : Bundle_Handle;
      Pol    : Policy_Handle) return Verification_Details
   is
      Details : Verification_Details;
   begin
      -- MVP stub
      Details.Result := Inconclusive;
      Details.Reason := To_Bounded_String ("SBOM verification not implemented");
      Details.SBOM_Present := False;

      -- TODO: Extract SBOM from bundle
      -- TODO: Validate SBOM format
      -- TODO: Check for CVEs

      return Details;
   end Check_SBOM;

   ----------------------
   -- Check_Registry  --
   ----------------------

   function Check_Registry
     (Bundle : Bundle_Handle;
      Pol    : Policy_Handle) return Verification_Details
   is
      Details : Verification_Details;
   begin
      -- MVP stub
      Details.Result := Inconclusive;
      Details.Reason := To_Bounded_String ("Registry verification not implemented");
      Details.Registry_Allowed := True;

      -- TODO: Extract registry from bundle metadata
      -- TODO: Check against policy allowlist/blocklist

      return Details;
   end Check_Registry;

   ----------------------------------
   -- Log_Enforcement_Decision    --
   ----------------------------------

   procedure Log_Enforcement_Decision
     (Bundle  : Bundle_Handle;
      Pol     : Policy_Handle;
      Details : Verification_Details)
   is
      use Ada.Text_IO;
      use Ada.Calendar;
      use Ada.Calendar.Formatting;

      Log_Path : constant String := To_String (Pol.Pol.Audit_Log_Path);
      Log_File : File_Type;
   begin
      -- Create or append to log file
      begin
         Open (Log_File, Append_File, Log_Path);
      exception
         when Name_Error =>
            Create (Log_File, Out_File, Log_Path);
      end;

      -- Write log entry
      Put_Line (Log_File, "---");
      Put_Line (Log_File, "Timestamp: " & Image (Clock));
      Put_Line (Log_File, "Policy: " & To_String (Pol.Pol.ID) &
                          " v" & To_String (Pol.Pol.Version));
      Put_Line (Log_File, "Bundle: " & To_String (Bundle.Path));
      Put_Line (Log_File, "Result: " & Details.Result'Image);
      Put_Line (Log_File, "Reason: " & To_String (Details.Reason));
      Put_Line (Log_File, "Signatures: " & Details.Signatures_Found'Image &
                          " / " & Details.Signatures_Required'Image);
      Put_Line (Log_File, "SBOM Present: " & Details.SBOM_Present'Image);
      Put_Line (Log_File, "Rekor Verified: " & Details.Rekor_Verified'Image);
      Put_Line (Log_File, "Registry Allowed: " & Details.Registry_Allowed'Image);

      Close (Log_File);
   end Log_Enforcement_Decision;

   --------------------------
   -- Verify_Trust_Store  --
   --------------------------

   function Verify_Trust_Store (Store : Trust_Store) return Boolean is
      pragma Unreferenced (Store);
   begin
      --  FAIL-CLOSED. Nothing below is implemented, so this cannot attest to
      --  anything; returning True would tell every caller the trust store had
      --  been verified when no verification exists. In a supply-chain tool
      --  that is the most dangerous possible default.
      --
      --  Returning False makes callers deny. That is correct: a verifier that
      --  cannot verify must not approve.
      --
      --  TODO: Implement Rekor verification
      --  TODO: Verify key fingerprints match public keys
      return False;
   end Verify_Trust_Store;

   ----------------------
   -- Verify_Policy   --
   ----------------------

   function Verify_Policy (Pol : A2ML.Policy) return Boolean is
      pragma Unreferenced (Pol);
   begin
      --  FAIL-CLOSED, for the same reason as Verify_Trust_Store above: the
      --  signature and Rekor checks do not exist, so True would be a claim
      --  this function has no basis to make.
      --
      --  TODO: Verify policy signature
      --  TODO: Verify Rekor entry
      return False;
   end Verify_Policy;

end Cerro.Policy.Enforce;
