--  SPDX-License-Identifier: MPL-2.0
--  Cerro_Pack - Signing using Rust cerro-sign binary
--  Replacement for shell script signing

with Ada.Text_IO;
with Ada.Directories;
with GNAT.OS_Lib;
with Ada.Strings.Fixed;
with Cerro_Crypto_OpenSSL;

package body Cerro_Pack_Rust_Signing is

   package TIO renames Ada.Text_IO;
   package Dir renames Ada.Directories;

   ---------------------------------------------------------------------------
   --  Sign_Manifest_Hash - Sign a manifest hash using Rust cerro-sign
   ---------------------------------------------------------------------------

   function Sign_Manifest_Hash
      (Manifest_Hash : String;
       Private_Key_Path : String;
       Key_Id : String) return Sign_Result
   is
      use GNAT.OS_Lib;

      Temp_Msg    : constant String := "/tmp/ct-msg-" &
                                      Ada.Strings.Fixed.Trim (Key_Id, Ada.Strings.Both) & ".txt";
      Temp_Sig    : constant String := "/tmp/ct-sig-" &
                                      Ada.Strings.Fixed.Trim (Key_Id, Ada.Strings.Both) & ".hex";
      Cerro_Sign  : constant String := "cerro-sign";  --  Assume in PATH or bin/
      Args        : Argument_List :=
         (new String'("sign"),
          new String'("--key"),
          new String'(Private_Key_Path),
          new String'("--message"),
          new String'(Manifest_Hash),
          new String'("--output"),
          new String'(Temp_Sig));
      Exit_Status : Integer;
      Sig_File    : TIO.File_Type;
      Sig_Hex     : String (1 .. 128);
      Sig_Last    : Natural;
      Success     : Boolean;
   begin
      --  Execute cerro-sign.
      --
      --  This was written as Spawn (Cerro_Sign, Args, Exit_Status, True), a
      --  procedure that does not exist in GNAT.OS_Lib. The nearest overload
      --  (s-os_lib.ads:915) takes an Output_File_Descriptor and a SEPARATE
      --  out Return_Code, so Exit_Status was being matched against a
      --  File_Descriptor. The function at :905 is what was meant: it returns
      --  the operating system's status directly.
      --
      --  The dropped True was Err_To_Out. The function form does not redirect,
      --  so cerro-sign's stderr now reaches this process's stderr instead of
      --  being folded into stdout -- which is what a CLI wants anyway.
      Exit_Status := Spawn (Cerro_Sign, Args);

      --  Free arguments
      for I in Args'Range loop
         Free (Args (I));
      end loop;

      if Exit_Status /= 0 then
         return (Success => False,
                 Signature => (others => 0));
      end if;

      --  Read signature
      if not Dir.Exists (Temp_Sig) then
         return (Success => False,
                 Signature => (others => 0));
      end if;

      TIO.Open (Sig_File, TIO.In_File, Temp_Sig);
      TIO.Get_Line (Sig_File, Sig_Hex, Sig_Last);
      TIO.Close (Sig_File);

      --  Clean up temp file
      Dir.Delete_File (Temp_Sig);

      --  Convert hex to binary signature
      declare
         Signature : Cerro_Crypto.Ed25519_Signature;
      begin
         --  Qualified: with-ing Cerro_Crypto_OpenSSL makes the unit visible
         --  but not its contents; there is no use clause for it here.
         Cerro_Crypto_OpenSSL.Hex_To_Signature
            (Sig_Hex (1 .. Sig_Last), Signature, Success);

         if not Success then
            return (Success => False,
                    Signature => (others => 0));
         end if;

         return (Success => True,
                 Signature => Signature);
      end;
   end Sign_Manifest_Hash;

end Cerro_Pack_Rust_Signing;
