##
##  OSSP uuid - Universally Unique Identifier
##  Copyright (c) 2004-2005 Ralf S. Engelschall <rse@engelschall.com>
##  Copyright (c) 2004-2005 The OSSP Project <http://www.ossp.org/>
##  Copyright (c) 2004 Piotr Roszatycki <dexter@debian.org>
##
##  This file is part of OSSP uuid, a library for the generation
##  of UUIDs which can found at http://www.ossp.org/pkg/lib/uuid/
##
##  Permission to use, copy, modify, and distribute this software for
##  any purpose with or without fee is hereby granted, provided that
##  the above copyright notice and this permission notice appear in all
##  copies.
##
##  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
##  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
##  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
##  IN NO EVENT SHALL THE AUTHORS AND COPYRIGHT HOLDERS AND THEIR
##  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
##  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
##  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
##  USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
##  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
##  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
##  OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
##  SUCH DAMAGE.
##
##  uuid_compat.pm: Data::UUID Backward Compatibility Perl API
##

package Data::UUID;

use 5.006;
use warnings;
use strict;

use OSSP::uuid;
use MIME::Base64;

require Exporter;

our @ISA     = qw(Exporter);
our @EXPORT  = qw(NameSpace_DNS NameSpace_OID NameSpace_URL NameSpace_X500);

our $VERSION = do { my @v = ('1.3.0' =~ m/\d+/g); sprintf("%d.".("%02d"x$#v), @v); };

sub new {
    my $class = shift;
    my $self = bless {}, $class;
    return $self;
}

sub create {
    my ($self) = @_;
    my $uuid = new OSSP::uuid;
    $uuid->make("v4");
    return $uuid->export("bin");
}

sub create_from_name {
    my ($self, $nsid, $name) = @_;
    my $uuid = new OSSP::uuid;
    my $nsiduuid = new OSSP::uuid;
    $nsiduuid->import("bin", $nsiduuid);
    $uuid = new OSSP::uuid;
    $uuid->make("v3", $nsiduuid, $name);
    return $uuid->export("bin");
}

sub to_string {
    my ($self, $bin) = @_;
    my $uuid = new OSSP::uuid;
    $uuid->import("bin", $bin);
    return $uuid->export("str");
}

sub to_hexstring {
    my ($self, $bin) = @_;
    my $uuid = new OSSP::uuid;
    $uuid->import("bin", $bin);
    $_ = $uuid->export("str");
    s/-//g;
    s/^/0x/;
    return $_;
}

sub to_b64string {
    my ($self, $bin) = @_;
    return MIME::Base64::encode_base64($bin);
}

sub from_string {
    my ($self, $str) = @_;
    my $uuid = new OSSP::uuid;
    if ($str =~ /^0x(........)(....)(....)(....)(............)$/) {
        $str = "$1-$2-$3-$4-$5";
    }
    $uuid->import("str", $str);
    return $uuid->export("bin");
}

sub from_hexstring {
    my ($self, $str) = @_;
    my $uuid = new OSSP::uuid;
    if ($str =~ /^0x(........)(....)(....)(....)(............)$/) {
        $str = "$1-$2-$3-$4-$5";
    }
    $uuid->import("str", $str);
    return $uuid->export("bin");
}

sub from_b64string {
    my ($self, $b64) = @_;
    return MIME::Base64::decode_base64($b64);
}

sub compare {
    my ($self, $bin1, $bin2) = @_;
    my $uuid1 = new OSSP::uuid;
    my $uuid2 = new OSSP::uuid;
    $uuid1->import("bin", $bin1);
    $uuid2->import("bin", $bin2);
    return $uuid1->compare($uuid2);
}

sub constant {
    my ($self, $arg) = @_;
    my $ns;
    if    ($arg eq "NameSpace_DNS")  { $ns = "ns:DNS";  }
    elsif ($arg eq "NameSpace_URL")  { $ns = "ns:URL";  }
    elsif ($arg eq "NameSpace_X500") { $ns = "ns:X500"; }
    elsif ($arg eq "NameSpace_OID")  { $ns = "ns:OID";  }
    else                             { $ns = "nil";     }
    my $uuid = new OSSP::uuid;
    $uuid->load($ns);
    return $uuid->export("bin");
}

sub NameSpace_DNS {
    my $self = new Data::UUID;
    return $self->constant("NameSpace_DNS");
}

sub NameSpace_URL {
    my $self = new Data::UUID;
    return $self->constant("NameSpace_URL");
}

sub NameSpace_X500 {
    my $self = new Data::UUID;
    return $self->constant("NameSpace_X500");
}

sub NameSpace_OID {
    my $self = new Data::UUID;
    return $self->constant("NameSpace_OID");
}

sub create_str {
    my ($self) = @_;
    my $uuid = $self->create();
    return $self->to_string($uuid);
}

sub create_hex {
    my ($self) = @_;
    my $uuid = $self->create();
    return $self->to_hexstring($uuid);
}

sub create_b64 {
    my ($self) = @_;
    my $uuid = $self->create();
    return $self->to_b64string($uuid);
}

sub create_from_name_str {
    my ($self, $nsid, $name) = @_;
    my $uuid = $self->create_from_name($nsid, $name);
    return $self->to_string($uuid);
}

sub create_from_name_hex {
    my ($self, $nsid, $name) = @_;
    my $uuid = $self->create_from_name($nsid, $name);
    return $self->to_hexstring($uuid);
}

sub create_from_name_b64 {
    my ($self, $nsid, $name) = @_;
    my $uuid = $self->create_from_name($nsid, $name);
    return $self->to_b64string($uuid);
}

1;

