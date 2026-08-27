--  SPDX-License-Identifier: MPL-2.0
--  Cerro_CLI - Keygen using Rust cerro-sign binary
--  Replacement for shell script keygen

with Ada.Text_IO;
with Ada.Directories;
with Ada.Environment_Variables;
--  Run_Keygen declares Unbounded_String locals (:22, :23) and calls
--  To_Unbounded_String/To_String; the unit had never with-ed this.
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with GNAT.OS_Lib;
with Cerro_Trust_Store;
with Cerro_Crypto_OpenSSL;

package body Cerro_CLI_Keygen_Rust is

   package TIO renames Ada.Text_IO;
   package Dir renames Ada.Directories;

   procedure Run_Keygen is
      use Cerro_Crypto_OpenSSL;
      use Cerro_Trust_Store;

      Key_Id      : Unbounded_String := To_Unbounded_String ("ct-key-default");
      Output_Dir  : Unbounded_String;
      Private_Key : Ed25519_Private_Key;
      Public_Key  : Ed25519_Public_Key;
      Success     : Boolean;
   begin
      --  Parse arguments (simplified for demonstration)
      --  In production, integrate with existing argument parsing

      --  Set up output directory
      declare
         Home_Dir : constant String := Ada.Environment_Variables.Value ("HOME");
         Keys_Dir : constant String := Home_Dir & "/.config/cerro-torre/keys/";
      begin
         if not Dir.Exists (Keys_Dir) then
            Dir.Create_Path (Keys_Dir);
         end if;
         Output_Dir := To_Unbounded_String (Keys_Dir);
      end;

      --  Call Rust cerro-sign binary for keygen
      declare
         use GNAT.OS_Lib;
         Cerro_Sign  : constant String := "cerro-sign";  --  Assume in PATH or bin/
         Priv_Path   : constant String := To_String (Output_Dir) & To_String (Key_Id) & ".priv";
         Pub_Path    : constant String := To_String (Output_Dir) & To_String (Key_Id) & ".pub";
         Args        : Argument_List :=
            (new String'("keygen"),
             new String'("--priv-key"),
             new String'(Priv_Path),
             new String'("--pub-key"),
             new String'(Pub_Path));
         Exit_Status : Integer;
      begin
         --  Execute cerro-sign keygen. See cerro_pack_rust_signing.adb for
         --  why the four-argument Spawn call this replaced never existed.
         Exit_Status := Spawn (Cerro_Sign, Args);

         --  Free arguments
         for I in Args'Range loop
            Free (Args (I));
         end loop;

         if Exit_Status /= 0 then
            TIO.Put_Line ("✗ Keygen failed (cerro-sign exit code: " &
                         Integer'Image (Exit_Status) & ")");
            return;
         end if;

         --  Read generated public key for trust store import
         declare
            Pub_File : TIO.File_Type;
            Pub_Hex  : String (1 .. 64);
            Last     : Natural;
         begin
            TIO.Open (Pub_File, TIO.In_File, Pub_Path);
            TIO.Get_Line (Pub_File, Pub_Hex, Last);
            TIO.Close (Pub_File);

            --  Convert hex to binary
            Hex_To_Public_Key (Pub_Hex (1 .. Last), Public_Key, Success);
            if not Success then
               TIO.Put_Line ("✗ Invalid public key format");
               return;
            end if;
         end;
      end;

      --  Import to trust store.
      --
      --  This block was written against a Cerro_Trust_Store that does not
      --  exist and never has. It named a type Store_Status (the real one is
      --  Store_Result), called Public_Key_To_String (no such subprogram
      --  anywhere in the tree), and passed Import_Key six named parameters --
      --  Key_Id_Val, Public_Key, Fingerprint, Trust_Level, Key_Type_Val,
      --  Suite -- none of which it has. Ed25519 and CT_SIG_01 were undefined
      --  too: the only Ed25519 in the tree is a Key_Algorithm literal
      --  belonging to a different subsystem (cerro-policy-a2ml.ads:36).
      --
      --  Rewritten against the real API (cerro_trust_store.ads:47, 51):
      --    function Import_Key (Path : String; Key_Id : String := "")
      --    function Set_Trust  (Key_Id : String; Level : Trust_Level)
      --
      --  Two consequences worth stating rather than hiding:
      --
      --  * Import_Key reads the key from a FILE, so the public key is
      --    imported from Pub_Path. The Public_Key binary decoded above is now
      --    used only to validate that what cerro-sign wrote is well-formed
      --    before the store is asked to read it -- which is still worth
      --    doing, and is why that step is kept.
      --
      --  * The old code PRINTED "Trust level set to 'ultimate'" while merely
      --    passing Trust_Level to a call that could not accept it. Setting
      --    the trust level is a separate operation, so it is now a separate
      --    call, and the message is printed only if that call succeeds.
      declare
         Pub_Path : constant String :=
            To_String (Output_Dir) & To_String (Key_Id) & ".pub";
         Imported  : Store_Result;
         Trusted   : Store_Result;
      begin
         Imported := Import_Key (Path => Pub_Path, Key_Id => To_String (Key_Id));

         if Imported /= OK then
            TIO.Put_Line ("✗ Failed to import public key: " & Imported'Image);
            return;
         end if;

         Trusted := Set_Trust (To_String (Key_Id), Ultimate);

         TIO.Put_Line ("✓ Private key saved: " &
                     To_String (Output_Dir) & To_String (Key_Id) & ".priv");
         TIO.Put_Line ("✓ Public key imported to trust store");

         if Trusted = OK then
            TIO.Put_Line ("✓ Trust level set to 'ultimate'");
         else
            TIO.Put_Line ("✗ Key imported, but trust level NOT set: " &
                        Trusted'Image);
         end if;
      end;
   end Run_Keygen;

end Cerro_CLI_Keygen_Rust;
