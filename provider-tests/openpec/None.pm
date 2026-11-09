# An antivirus for OpenPEC that finds nothing, for the provider tests, which send no virus.
# OpenPEC's scan contract: undef for a clean message, an array reference for a virus, a string for an error.
package Opec::AV::None;

use strict;

sub new { return bless {}, shift }

sub scan { return undef }

sub ping { return 1 }

1;
