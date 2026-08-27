--  SPDX-License-Identifier: MPL-2.0
--  Cerro Torre - root namespace package
--
--  This package declares no entities. It exists because Ada requires the
--  parent of a child unit to be a real compilation unit: Cerro.Policy.A2ML
--  and Cerro.Policy.Enforce cannot be compiled unless Cerro and Cerro.Policy
--  exist. Both children were written without either parent ever being
--  created, so neither had ever compiled.
--
--  Pure, so that children remain free to be Pure or Preelaborate.

pragma Ada_2022;

package Cerro with
   Pure,
   SPARK_Mode => On
is
end Cerro;
