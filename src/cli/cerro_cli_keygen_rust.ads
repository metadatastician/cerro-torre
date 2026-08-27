--  SPDX-License-Identifier: MPL-2.0
--  Cerro_CLI - Keygen using the Rust cerro-sign binary
--
--  This spec did not exist. An Ada library-level package body is legal only
--  with a matching spec, so cerro_cli_keygen_rust.adb had never compiled --
--  gprbuild stopped at "file cerro_cli_keygen_rust.ads not found" before
--  reaching any other diagnostic in the file.

package Cerro_CLI_Keygen_Rust is

   --  Generate an Ed25519 keypair by invoking the external `cerro-sign`
   --  binary, then register the public key in the trust store under its
   --  SHA-256 fingerprint.
   --
   --  Reports failures on standard output and returns normally; it does not
   --  raise, and it does not set an exit status. A caller that needs to know
   --  whether keygen succeeded must inspect the trust store.
   procedure Run_Keygen;

end Cerro_CLI_Keygen_Rust;
