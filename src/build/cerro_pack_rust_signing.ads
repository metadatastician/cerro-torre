--  SPDX-License-Identifier: MPL-2.0
--  Cerro_Pack - Signing using the Rust cerro-sign binary
--
--  This spec did not exist. An Ada library-level package body is legal only
--  with a matching spec, so cerro_pack_rust_signing.adb had never compiled --
--  gprbuild stopped at "file cerro_pack_rust_signing.ads not found" before
--  reaching any other diagnostic in the file.
--
--  Sign_Result is reconstructed from the body's four return aggregates
--  (cerro_pack_rust_signing.adb:54, :60, :78, :82), each of the form
--  (Success => <Boolean>, Signature => <Ed25519_Signature>). No prior
--  declaration of this type exists anywhere in the repository's history,
--  so this is authorship, not restoration.

with Cerro_Crypto;

package Cerro_Pack_Rust_Signing is

   --  Outcome of an out-of-process signing call.
   --
   --  Signature is meaningful ONLY when Success is True. On every failure
   --  path the body returns (others => 0) rather than leaving the array
   --  uninitialised, so a caller that ignores Success reads zeroes rather
   --  than stack residue -- but it is still reading a signature that was
   --  never produced. Check Success.
   type Sign_Result is record
      Success   : Boolean;
      Signature : Cerro_Crypto.Ed25519_Signature;
   end record;

   --  Sign Manifest_Hash by invoking the external `cerro-sign` binary with
   --  the Ed25519 private key at Private_Key_Path.
   --
   --  Returns Success => False, rather than raising, when: the binary is not
   --  on PATH, it exits non-zero, it writes no signature file, or the hex it
   --  writes does not decode. Key_Id names the temporary files and so must
   --  not contain path separators.
   function Sign_Manifest_Hash
      (Manifest_Hash    : String;
       Private_Key_Path : String;
       Key_Id           : String) return Sign_Result
   with Pre => Manifest_Hash'Length > 0
               and then Private_Key_Path'Length > 0
               and then Key_Id'Length > 0;

end Cerro_Pack_Rust_Signing;
