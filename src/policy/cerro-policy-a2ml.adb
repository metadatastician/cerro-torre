-- SPDX-License-Identifier: MPL-2.0
-- Cerro Torre A2ML Policy Integration - Implementation

pragma Ada_2022;

with Ada.Directories;
with Ada.Text_IO;
with GNAT.OS_Lib;

package body Cerro.Policy.A2ML with
   SPARK_Mode => Off  -- Using external process calls, not SPARK-compatible
is

   use ID_Strings;
   use Short_Strings;
   use Path_Strings;

   -----------------------
   -- Load_Trust_Store --
   -----------------------

   function Load_Trust_Store (Path : String) return Trust_Store is
      Store : Trust_Store;
   begin
      -- Check file exists
      if not Ada.Directories.Exists (Path) then
         raise Parse_Error with "Trust store file not found: " & Path;
      end if;

      -- For MVP: Call a2ml CLI to validate
      -- TODO: Parse A2ML directly in Ada or via JSON AST
      declare
         Command : constant String := "a2ml validate " & Path;
         Success : Boolean;
         Return_Code : Integer;
      begin
         GNAT.OS_Lib.Spawn
           (Program_Name => "/bin/sh",
            Args         => (new String'("-c"), new String'(Command)),
            Success      => Success);

         if not Success then
            Ada.Text_IO.Put_Line ("Warning: a2ml not available, skipping validation");
         end if;
      end;

      -- For MVP: Return stub trust store
      -- TODO: Actually parse the A2ML file
      Store.ID := To_Bounded_String ("stub-trust-store");
      Store.Version := To_Bounded_String ("1.0");
      Store.Verified := False;  -- Not actually verified yet

      -- Add example key
      declare
         Example_Key : Signing_Key;
      begin
         Example_Key.ID := To_Bounded_String ("release-key-2026");
         Example_Key.Algorithm := Ed25519;
         Example_Key.Public_Key := To_Bounded_String ("ssh-ed25519 STUB");
         Example_Key.Fingerprint := To_Bounded_String ("SHA256:stub");
         Example_Key.Purpose := To_Bounded_String ("Stub key for MVP");
         Example_Key.Owner := To_Bounded_String ("Platform Team");
         Example_Key.Revoked := False;
         Example_Key.Revocation_Reason := To_Bounded_String ("");

         Store.Keys.Append (Example_Key);
      end;

      return Store;
   end Load_Trust_Store;

   -------------------
   -- Load_Policy  --
   -------------------

   function Load_Policy (Path : String) return Policy is
      Pol : Policy;
   begin
      -- Check file exists
      if not Ada.Directories.Exists (Path) then
         raise Parse_Error with "Policy file not found: " & Path;
      end if;

      --  Validate with the a2ml CLI. FAIL-CLOSED: this used to print
      --  "Warning: a2ml not available, skipping validation" and carry on, so
      --  a missing validator silently downgraded to no validation at all.
      --  A policy that could not be validated is not a validated policy.
      declare
         Command : constant String := "a2ml validate " & Path;
         Success : Boolean;
      begin
         GNAT.OS_Lib.Spawn
           (Program_Name => "/bin/sh",
            Args         => (new String'("-c"), new String'(Command)),
            Success      => Success);

         if not Success then
            raise Parse_Error with
              "policy validation failed for " & Path &
              " (a2ml unavailable, or the file is invalid). Refusing to load " &
              "an unvalidated policy.";
         end if;
      end;

      --  ⚠ THE FILE IS STILL NOT PARSED. Everything below fabricates a policy
      --  rather than reading Path, and the caller cannot tell the difference
      --  from the return type alone.
      --
      --  Verified is left False and Cerro.Policy.Enforce's Registry_Allowlist
      --  arm now DENIES outright, so this can no longer be laundered into a
      --  permit — but a fabricated policy is still a lie, and the ID says so
      --  explicitly so it shows up in the audit log rather than reading as a
      --  real policy named after the file.
      --
      --  TODO: actually parse the A2ML file. Until then, treat any Policy
      --  returned by this function as UNVERIFIED regardless of its contents.
      Pol.ID := To_Bounded_String ("UNPARSED-STUB-POLICY");
      Pol.Version := To_Bounded_String ("1.0");
      Pol.Description := To_Bounded_String ("Stub policy for MVP");
      Pol.Verified := False;

      -- Add basic requirements
      declare
         Req : Policy_Requirement;
      begin
         Req.Req_Type := Min_Signatures;
         Req.Enabled := True;
         Req.Min_Sigs := 1;
         Pol.Requirements.Append (Req);

         Req.Req_Type := SBOM_Required;
         Req.Enabled := False;
         Req.SBOM_Format := To_Bounded_String ("spdx");
         Pol.Requirements.Append (Req);
      end;

      Pol.Audit_Log_Path := To_Bounded_String ("/var/log/ct/policy.log");

      return Pol;
   end Load_Policy;

   ----------------
   -- Find_Key  --
   ----------------

   function Find_Key (Store : Trust_Store; Key_ID : String) return Signing_Key is
      use type ID_String;
      Target_ID : constant ID_String := To_Bounded_String (Key_ID);
   begin
      for Key of Store.Keys loop
         if Key.ID = Target_ID then
            return Key;
         end if;
      end loop;

      raise Key_Not_Found with "Key not found: " & Key_ID;
   end Find_Key;

   --------------------
   -- Is_Key_Valid  --
   --------------------

   function Is_Key_Valid (Key : Signing_Key) return Boolean is
   begin
      return not Key.Revoked;
      -- TODO: Also check expiry date
   end Is_Key_Valid;

   -----------------------
   -- Allows_Registry  --
   -----------------------

   function Allows_Registry (Pol : Policy; Registry_URL : String) return Boolean is
      use type Short_String;
      URL : constant Short_String := To_Bounded_String (Registry_URL);
   begin
      -- If blocklist has entries, check against it
      if not Pol.Blocked_Registries.Is_Empty then
         for Blocked of Pol.Blocked_Registries loop
            if Blocked = URL then
               return False;  -- Registry is blocked
            end if;
         end loop;
      end if;

      --  An empty allowlist DENIES. This used to return True — "allow all
      --  except blocked" — which is a defensible policy only when the
      --  emptiness is deliberate. It is not distinguishable from the two ways
      --  a list ends up empty by accident:
      --
      --    * Load_Policy does not parse the file, so every Policy it returns
      --      has an empty allowlist regardless of what the file says; and
      --    * a malformed or truncated policy would produce the same shape.
      --
      --  So "empty" meant "unconfigured OR unloadable OR broken", and all
      --  three read as permit-everything. An allowlist that cannot be read is
      --  not an allowlist that permits.
      --
      --  If allow-all is genuinely wanted, it should be stated in the policy
      --  as an explicit wildcard entry, so the intent is in the file rather
      --  than inferred from an absence.
      if Pol.Allowed_Registries.Is_Empty then
         return False;
      end if;

      -- Check allowlist
      for Allowed of Pol.Allowed_Registries loop
         if Allowed = URL then
            return True;  -- Registry is allowed
         end if;
      end loop;

      return False;  -- Not in allowlist
   end Allows_Registry;

   --------------------------
   -- Verify_Trust_Store  --
   --------------------------

   function Verify_Trust_Store (Store : Trust_Store) return Boolean is
      pragma Unreferenced (Store);
   begin
      --  FAIL-CLOSED. None of the checks below exist, so True would assert a
      --  verification that never happened. The contract in the spec is
      --  Post => (if Result then Store.Verified) -- returning False satisfies
      --  it vacuously and is the only honest answer an unimplemented verifier
      --  can give.
      --
      --  TODO: Verify Rekor attestation
      --  TODO: Verify key fingerprints
      --  TODO: Check key expiry dates
      return False;
   end Verify_Trust_Store;

   ----------------------
   -- Verify_Policy   --
   ----------------------

   function Verify_Policy (Pol : Policy) return Boolean is
      pragma Unreferenced (Pol);
   begin
      --  FAIL-CLOSED, as Verify_Trust_Store above.
      --  Post => (if Result then Pol.Verified) holds vacuously on False.
      --
      --  TODO: Verify policy signature
      --  TODO: Verify Rekor entry for policy
      return False;
   end Verify_Policy;

end Cerro.Policy.A2ML;
