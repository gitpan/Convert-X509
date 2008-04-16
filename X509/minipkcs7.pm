package Convert::X509::minipkcs7;

=head1 NAME

Convert::X509::minipkcs7 - parse pkcs7 messages just to get only SN list of recipients and/or signers

=head1 SYNOPSYS

use Convert::X509::minipkcs7;

use Data::Dumper;

open(F,'<', $ARGV[0]) or die;

binmode(F);

local $/;

my $data=<F>;

print Dumper(Convert::X509::minipkcs7::snlist(\$data));
        
=cut

use Carp;
use strict;
use warnings;
use Convert::ASN1;
use MIME::Base64;

our $VERSION = '0.1';

my %oid_db=(
   'PKCS7'	=> { 'asn'=>'ContentInfo' },
	'1.2.840.113549.1.7.1'	=> { 'asn'=>'Data' },
	'1.2.840.113549.1.7.2'	=> { 'asn'=>'SignedData' },
	'1.2.840.113549.1.7.3'	=> { 'asn'=>'EnvelopedData' },
	'1.2.840.113549.1.7.4'	=> { 'asn'=>'SignedAndEnvelopedData' },
	'1.2.840.113549.1.7.5'	=> { 'asn'=>'DigestedData' },
	'1.2.840.113549.1.7.6'	=> { 'asn'=>'EncryptedData' },
);

my $asn;

sub _prepare {
  my ($pdata) = @_;
  warn ('Parameter must be a scalar ref') && return undef unless ref($pdata) eq 'SCALAR';
  # first bytes for ASN.1 SEQUENCE are 3080 or 3082
  unless (unpack('H3',$$pdata) eq '308'){
    $$pdata = decode_base64(
      join("\n",
        $$pdata =~ m!^([A-Za-z01-9+/]{1,})[-=]*$!gm
      )
    );
  }
}

sub _int2hexstr {
  my $res='';
  my $m=$_[0];
  while ($m){
	  $res = unpack('H2',pack('C', $m & 255 )) . $res;
	  $m >>= 8;
  }
  return $res;
}

sub _decode {
  warn ("Error\n",$asn->error,"\nin ASN.1 code ") && return undef if $asn->error;
  my $type = shift;
  my $node= $asn->find( $oid_db{uc($type)}->{'asn'} || 'Any' );
  warn ('Error finding ',$type,'-', $oid_db{uc($type)}->{'asn'}, ' in module') && return undef unless $node;
  my @decoded = map {$node->decode($_)} @_;
  return ( @_ > 1 ? [@decoded] : $decoded[0] )
}

sub snlist {
  my $pdata = (ref($_[0]) ? $_[0] : \$_[0]);
  _prepare($pdata);
  warn ('Seems to be not PKCS7 data') && return undef unless (unpack('H3',$$pdata) eq '308');
  my $d = _decode('pkcs7'=>$$pdata);
  warn ('Error PKCS7 decoding') && return undef unless $d;
  $d->{'content'} = _decode($d->{'contentType'}=>$d->{'content'});
  warn ('Error PKCS7 content decoding') && return undef unless $d->{'content'};
  my $res = { }; # {'recipients'=>[],'signers'=>[]};
  for (@{ $d->{'content'}{'signerInfos'} }) {
    push @{ $res->{'signers'} },
     _int2hexstr( $_->{'issuerAndSerialNumber'}{'serialNumber'} );
  }
  for (@{ $d->{'content'}{'recipientInfos'} }) {
    push @{ $res->{'recipients'} },
     _int2hexstr(
      $_->{'keyAgreementRecipientInfo'}[0]{'recipientEncryptedKeys'}[0]{'recipientIdentifier'}
      {'issuerAndSerialNumber'}{'serialNumber'}
      # I don't have any reason to "foreach" in two those lists ([0] and [0] above)
     );
  }
  return $res;
}

$asn = Convert::ASN1->new;
$asn->prepare(<<ASN1);

-- http://www.ietf.org/rfc/rfc2315.txt
-- http://www.ietf.org/rfc/rfc3369.txt
-- http://www.alvestrand.no/objectid
-- http://www.itu.int/ITU-T/asn1/database
-- BUT BE CAREFUL !!!

Any ::= ANY -- do not remove!

ContentInfo ::= SEQUENCE {
     contentType OBJECT IDENTIFIER,
     content [0] EXPLICIT ANY }

EnvelopedData ::= SEQUENCE {
         version ANY,
         originatorInfo [0] ANY OPTIONAL,
         recipientInfos RecipientInfos,
         encryptedContentInfo ANY,
         unprotectedAttrs [1] ANY OPTIONAL
}
RecipientInfos ::= SET OF RecipientInfo
RecipientInfo ::= CHOICE {
  keyAgreementRecipientInfo      [1] SEQUENCE OF KeyAgreementRecipientInfo,
  keyTransportRecipientInfo      ANY
}
KeyAgreementRecipientInfo ::= SEQUENCE {
  version                 ANY,
  originator              ANY,
  userKeyingMaterial      [1] ANY OPTIONAL,
  keyEncryptionAlgorithm  ANY,
  recipientEncryptedKeys  SEQUENCE OF RecipientEncryptedKey
}
RecipientEncryptedKey ::= SEQUENCE {
  recipientIdentifier  SomebodyIdentifier,
  encryptedKey         ANY
}
SomebodyIdentifier ::= CHOICE {
  issuerAndSerialNumber  IssuerAndSerialNumber,
  recipientKeyIdentifier [0] ANY,
  subjectKeyIdentifier   [2] ANY
}
IssuerAndSerialNumber ::= SEQUENCE {
  issuer        ANY,
  serialNumber  INTEGER
}

SignedAndEnvelopedData ::= SEQUENCE {
  version               ANY,
  recipientInfos        RecipientInfos,
  digestAlgorithms      ANY,
  encryptedContentInfo  ANY,
  certificates          [0] ANY OPTIONAL,
  crls                  [1] ANY OPTIONAL,
  signerInfos           SET OF SignerInfo }

SignedData ::= SEQUENCE {
     version ANY,
     digestAlgorithms ANY,
     contentInfo ANY,
     certificates [0] ANY OPTIONAL,
     crls [1] ANY OPTIONAL,
     signerInfos SET OF SignerInfo }
SignerInfo ::= SEQUENCE {
     version ANY,
     issuerAndSerialNumber IssuerAndSerialNumber,
     digestAlgorithm ANY,
     authenticatedAttributes [0] ANY OPTIONAL,
     digestEncryptionAlgorithm ANY,
     encryptedDigest ANY,
     unauthenticatedAttributes [1] ANY OPTIONAL }

DigestedData ::= SEQUENCE {
  version          ANY,
  digestAlgorithm  ANY,
  contentInfo      ContentInfo,
  digest           ANY }
EncryptedData ::= SEQUENCE {
  version                ANY,
  encryptedContentInfo   EncryptedContentInfo,
  unprotectedAttributes  [1] ANY OPTIONAL }
EncryptedContentInfo ::= SEQUENCE {
  contentType          OBJECT IDENTIFIER,
  contentEncAlgorithm  ANY,
  encryptedContent     [0] ANY OPTIONAL }
Data ::= OCTET STRING

ASN1

1;
