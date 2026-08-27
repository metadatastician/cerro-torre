--  SPDX-License-Identifier: MPL-2.0
--  Cerro Torre - policy subsystem namespace
--
--  Declares no entities; exists so that Cerro.Policy.A2ML and
--  Cerro.Policy.Enforce have a parent to be children of. See cerro.ads.

pragma Ada_2022;

package Cerro.Policy with
   Pure,
   SPARK_Mode => On
is
end Cerro.Policy;
