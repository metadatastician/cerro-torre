-- SPDX-License-Identifier: MPL-2.0
--
-- Compile-time checks for CanonChecks. If this module typechecks, they hold.
module CanonTests

-- Key-ordering and full-file cases need `lines`, which the type checker does
-- not reduce. They run at runtime: `ct-shadow --self-test` (also covers the JSON field reader).

import CanonChecks

%default total

ok : Either String () -> Bool
ok (Right ()) = True
ok (Left _) = False

withCr : ok (checkCanonical "a: 1\r\n") = False
withCr = Refl

withTab : ok (checkCanonical "a:\t1\n") = False
withTab = Refl

noFinalLf : ok (checkCanonical "a: 1") = False
noFinalLf = Refl

twoFinalLf : ok (checkCanonical "a: 1\n\n") = False
twoFinalLf = Refl

emptyFile : ok (checkCanonical "") = False
emptyFile = Refl

trailingSpace : ok (checkCanonical "a: 1 \n") = False
trailingSpace = Refl

