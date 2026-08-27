--  SPDX-License-Identifier: MPL-2.0
--  ct_test_trust_store - a fingerprint must be DERIVED, never ASSERTED
--
--  Cerro_Trust_Store.Get_Key had two branches that disagreed about where a
--  fingerprint comes from. With no .meta sidecar it derived one from the key
--  material; with a sidecar it took the sidecar's word for it. Set_Trust
--  writes a sidecar, so every key that has ever been trusted has one -- the
--  branch that believed the file was the branch taken for exactly the keys
--  callers ask about.
--
--  The test that matters is therefore not "Get_Key recomputes the
--  fingerprint" -- that asserts the implementation back to itself. It is
--  whether an attacker who can write the trust-store directory can make THEIR
--  key answer to SOMEONE ELSE'S fingerprint, which is the property the store
--  exists to provide.
--
--  Two controls, because a store that refuses everything would satisfy every
--  attack test here: a genuine key at trust=full must still be trusted, and a
--  key whose sidecar recognises nothing must still be READABLE (merely
--  untrusted) rather than erroring.

with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Text_IO;
with Cerro_Trust_Store;

procedure CT_Test_Trust_Store is
   use Ada.Text_IO;
   use Cerro_Trust_Store;
   use type Cerro_Trust_Store.Store_Result;
   use type Cerro_Trust_Store.Trust_Level;

   Failures : Natural := 0;

   Store_Root : constant String := "/tmp/ct-test-trust-store";

   --  Two distinct, well-formed Ed25519-shaped public keys (64 hex chars).
   Victim_Hex : constant String :=
     "1111111111111111111111111111111111111111111111111111111111111111";
   Attacker_Hex : constant String :=
     "2222222222222222222222222222222222222222222222222222222222222222";

   procedure Check (Name : String; Condition : Boolean) is
   begin
      if Condition then
         Put_Line ("  PASS  " & Name);
      else
         Put_Line ("  FAIL  " & Name);
         Failures := Failures + 1;
      end if;
   end Check;

   procedure Write_File (Path : String; Content : String) is
      F : File_Type;
   begin
      Create (F, Out_File, Path);
      Put_Line (F, Content);
      Close (F);
   end Write_File;

   function Store_Dir return String is (Get_Store_Path);

begin
   --  Point the store at a scratch directory BEFORE anything caches the path.
   Ada.Environment_Variables.Set ("XDG_CONFIG_HOME", Store_Root);
   if Ada.Directories.Exists (Store_Root) then
      Ada.Directories.Delete_Tree (Store_Root);
   end if;

   Put_Line ("Cerro_Trust_Store — a fingerprint is derived, not asserted");
   Put_Line ("");

   Initialize;
   Check ("the scratch store initialises", Is_Initialized);

   ---------------------------------------------------------------------------
   Put_Line ("");
   Put_Line ("SETUP — one genuine, trusted key");
   ---------------------------------------------------------------------------

   Check ("victim key imports", Import_Key_Hex (Victim_Hex, "victim") = OK);
   Check ("victim key can be trusted", Set_Trust ("victim", Full) = OK);

   declare
      Victim : Key_Info;
      R      : constant Store_Result := Get_Key ("victim", Victim);
   begin
      Check ("victim key reads back", R = OK);

      declare
         Victim_FP : constant String := Victim.Fingerprint (1 .. Victim.Finger_Len);
      begin
         ---------------------------------------------------------------------
         Put_Line ("");
         Put_Line ("CONTROL — a genuine trusted key is still trusted");
         --  Without this the whole suite would be satisfied by a store that
         --  denied unconditionally, which is the mirror-image fake gate.
         ---------------------------------------------------------------------

         Check ("a genuine key at trust=full IS trusted", Is_Trusted (Victim_FP));
         Check ("...and reports its real trust level",
                Get_Trust_Level (Victim_FP) = Full);

         ---------------------------------------------------------------------
         Put_Line ("");
         Put_Line ("THE ATTACK — a sidecar claiming someone else's fingerprint");
         ---------------------------------------------------------------------

         --  attacker.pub holds the ATTACKER's key; attacker.meta claims the
         --  VICTIM's fingerprint and the highest trust level. Nothing here
         --  requires any privilege beyond writing the store directory.
         Write_File (Store_Dir & "/attacker.pub", Attacker_Hex);
         Write_File (Store_Dir & "/attacker.meta",
                     "key_id=attacker" & ASCII.LF &
                     "fingerprint=" & Victim_FP & ASCII.LF &
                     "trust=ultimate" & ASCII.LF &
                     "created=2026-01-01");

         declare
            Bad : Key_Info;
            BR  : constant Store_Result := Get_Key ("attacker", Bad);
         begin
            Check ("a sidecar whose fingerprint contradicts its key is REJECTED",
                   BR = Invalid_Format);
            Check ("...rather than being read as a valid key", BR /= OK);
         end;

         declare
            Found : Key_Info;
            FR    : constant Store_Result :=
                       Get_Key_By_Fingerprint (Victim_FP, Found);
         begin
            --  The sharp assertion: looking up the victim's fingerprint must
            --  still yield the VICTIM's key material, never the attacker's.
            Check ("the victim's fingerprint still resolves", FR = OK);
            Check ("...to the VICTIM's key material, not the attacker's",
                   Found.Public_Key (1 .. Found.Pubkey_Len) = Victim_Hex);
            Check ("...and NOT to the attacker's key",
                   Found.Public_Key (1 .. Found.Pubkey_Len) /= Attacker_Hex);
         end;

         ---------------------------------------------------------------------
         Put_Line ("");
         Put_Line ("THE CLAIM ALONE IS WORTHLESS");
         ---------------------------------------------------------------------

         --  Remove the genuine key. The attacker's claim to its fingerprint is
         --  now the only one in the store. It must buy nothing.
         Ada.Directories.Delete_File (Store_Dir & "/victim.pub");
         Ada.Directories.Delete_File (Store_Dir & "/victim.meta");

         Check ("with the real key gone, its fingerprint is NOT trusted",
                not Is_Trusted (Victim_FP));

         declare
            Impostor : Key_Info;
         begin
            Check ("...and does not resolve to the impostor",
                   Get_Key_By_Fingerprint (Victim_FP, Impostor) /= OK);
         end;
      end;
   end;

   ---------------------------------------------------------------------------
   Put_Line ("");
   Put_Line ("CONTROL — an uninformative sidecar is not an error");
   ---------------------------------------------------------------------------

   declare
      Orphan : Key_Info;
      R      : Store_Result;
   begin
      --  Read_Meta_File now reports failure when it recognises no key=value
      --  line, so an empty sidecar reads as ABSENT. Get_Key must still return
      --  the key -- untrusted -- rather than refusing it.
      Write_File (Store_Dir & "/orphan.pub", Attacker_Hex);
      Write_File (Store_Dir & "/orphan.meta", "");

      R := Get_Key ("orphan", Orphan);
      Check ("a key with an EMPTY sidecar is still readable", R = OK);
      Check ("...and is Untrusted, not trusted by default",
             Orphan.Trust = Untrusted);
      Check ("...with a fingerprint derived from its own key",
             Orphan.Fingerprint (1 .. Orphan.Finger_Len)
               = Compute_Fingerprint (Attacker_Hex));
   end;

   ---------------------------------------------------------------------------
   Put_Line ("");
   if Ada.Directories.Exists (Store_Root) then
      Ada.Directories.Delete_Tree (Store_Root);
   end if;

   if Failures = 0 then
      Put_Line ("All trust-store tests passed.");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
   else
      Put_Line (Failures'Image & " trust-store test(s) FAILED.");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end CT_Test_Trust_Store;
