package Convert::X509::CRL;

use strict;
use warnings;
use Convert::X509::Parser;

our $VERSION = '0.1';

sub new {
  my ($class,$data)=@_;
  Convert::X509::Parser::_prepare(\$data);
  my $d = Convert::X509::Parser::_decode('crl'=>$data);
  return undef unless $d;
  my $crl = {
    'crl'	=> {},
    'issuer'	=> Convert::X509::Parser::_decode_rdn($d->{'tbsCertList'}{'issuer'}{'rdnSequence'}),
    'from'	=> $d->{'tbsCertList'}{'thisUpdate'},
    'to'		=> $d->{'tbsCertList'}{'nextUpdate'},
    'extensions'	=> Convert::X509::Parser::_decode_ext ( $d->{'tbsCertList'}{'crlExtensions'} ),
    'signature'	=> {
		'sign'		=> $d->{'signatureValue'}[0], # bits
		'length'		=> $d->{'signatureValue'}[1],
		'algorithm'	=> $d->{'signatureAlgorithm'}{'algorithm'},
		'params'		=> $d->{'signatureAlgorithm'}{'parameters'},
	 },
  };
  for my $entry ( @{ $d->{'tbsCertList'}{'revokedCertificates'} } ){
    my $serial = Convert::X509::Parser::_int2hexstr( $entry->{'userCertificate'} );
    $crl->{'crl'}{$serial}{'date'} = $entry->{'revocationDate'};
    $crl->{'crl'}{$serial}{'ext'} = Convert::X509::Parser::_decode_ext( $entry->{'crlEntryExtensions'} )
      if $entry->{'crlEntryExtensions'};
  }
  return (bless $crl, $class);
}

sub issuer {
  my $self = shift;
  return Convert::X509::Parser::_rdn2str($self->{'issuer'},@_);
}

sub reason {
  my $self = shift;
  return Convert::X509::Parser::_crlreason(
    $self->{'crl'}{ lc($_[0]) }{'ext'}{'2.5.29.21'}{'value'}
  );
}

1;
