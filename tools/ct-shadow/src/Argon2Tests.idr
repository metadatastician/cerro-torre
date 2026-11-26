-- SPDX-License-Identifier: MPL-2.0
--
-- Compile-time checks for Argon2Checks. If this module typechecks, they hold.
-- They check pass/fail only. Error text is built with `show`, which the type
-- checker does not reduce, so message wording is not covered here.
module Argon2Tests

import Argon2Checks

%default total

ok : Validation -> Bool
ok (Right ()) = True
ok (Left _) = False

-- The three profile defaults are valid.
interactiveOk : ok (validateParams (profileDefaults Interactive)) = True
interactiveOk = Refl

moderateOk : ok (validateParams (profileDefaults Moderate)) = True
moderateOk = Refl

highOk : ok (validateParams (profileDefaults High)) = True
highOk = Refl

-- Unknown profile fails by name, and its zero defaults fail validation.
unknownRejected : ok (validateProfileName "turbo") = False
unknownRejected = Refl

knownAccepted : ok (validateProfileName "moderate") = True
knownAccepted = Refl

unknownDefaultsRejected : ok (validateParams (profileDefaults (Unknown "x"))) = False
unknownDefaultsRejected = Refl

-- Bounds, both edges of every field.
saltEdges : (ok (validateSaltBytes 15), ok (validateSaltBytes 33), ok (validateSaltBytes 16), ok (validateSaltBytes 32))
          = (False, False, True, True)
saltEdges = Refl

hashEdges : (ok (validateHashBytes 31), ok (validateHashBytes 65), ok (validateHashBytes 32), ok (validateHashBytes 64))
          = (False, False, True, True)
hashEdges = Refl

parEdges : (ok (validateParallelism 0), ok (validateParallelism 9), ok (validateParallelism 1), ok (validateParallelism 8))
         = (False, False, True, True)
parEdges = Refl

memEdges : (ok (validateMemoryKib 65535), ok (validateMemoryKib 1048577), ok (validateMemoryKib 65536), ok (validateMemoryKib 1048576))
         = (False, False, True, True)
memEdges = Refl

timeEdges : (ok (validateTimeCost 1), ok (validateTimeCost 11), ok (validateTimeCost 2), ok (validateTimeCost 10))
          = (False, False, True, True)
timeEdges = Refl

-- Upgrades only increase.
upgradeUp : ok (validateUpgrade (profileDefaults Interactive) (profileDefaults High)) = True
upgradeUp = Refl

upgradeSame : ok (validateUpgrade (profileDefaults High) (profileDefaults High)) = True
upgradeSame = Refl

upgradeDown : ok (validateUpgrade (profileDefaults High) (profileDefaults Interactive)) = False
upgradeDown = Refl

-- One field going down is enough to reject.
upgradeTimeDown : ok (validateUpgrade (MkParams 16 32 1 131072 5) (MkParams 16 32 1 131072 4)) = False
upgradeTimeDown = Refl
