package Convert::X509::Certificate;

use strict;
use warnings;
use Convert::X509::Parser;

our $VERSION = '0.1';

sub new {
  my ($class,$data)=@_;
  Convert::X509::Parser::_prepare(\$data);
  my $d = Convert::X509::Parser::_decode('cert'=>$data);
  return undef unless $d;
  my $cert = {
    'subject'	=> Convert::X509::Parser::_decode_rdn($d->{'tbsCertificate'}{'subject'}{'rdnSequence'}),
    'issuer'	=> Convert::X509::Parser::_decode_rdn($d->{'tbsCertificate'}{'issuer'}{'rdnSequence'}),
    'from'	=> $d->{'tbsCertificate'}{'validity'}{'notBefore'},
    'to'		=> $d->{'tbsCertificate'}{'validity'}{'notAfter'},
    'serial'		=> Convert::X509::Parser::_int2hexstr($d->{'tbsCertificate'}{'serialNumber'}),
    'extensions'	=> Convert::X509::Parser::_decode_ext ( $d->{'tbsCertificate'}{'extensions'} ),
    'signature'	=> {
		'sign'		=> $d->{'signature'}[0], # bits
		'length'		=> $d->{'signature'}[1],
		'algorithm'	=> $d->{'signatureAlgorithm'}{'algorithm'},
		'params'		=> $d->{'signatureAlgorithm'}{'parameters'},
	 },
    'pkinfo'		=> {
		'algorithm'	=> $d->{'tbsCertificate'}{'subjectPKInfo'}{'algorithm'}{'algorithm'}, # yes, 2 times
		'params'	=> $d->{'tbsCertificate'}{'subjectPKInfo'}{'algorithm'}{'parameters'},
		'length'	=> $d->{'tbsCertificate'}{'subjectPKInfo'}{'subjectPublicKey'}[1],
		'key'		=> $d->{'tbsCertificate'}{'subjectPKInfo'}{'subjectPublicKey'}[0],
	 },
  };
  return (bless $cert, $class);
}

sub subject {
  my $self = shift;
  return Convert::X509::Parser::_rdn2str($self->{'subject'},@_);
}

sub issuer {
  my $self = shift;
  return Convert::X509::Parser::_rdn2str($self->{'issuer'},@_);
}

sub serial {
  my $self = shift;
  return $self->{'serial'};
}

sub eku {
  return Convert::X509::Parser::_eku($_[0]);
}

sub keyusage {
  return Convert::X509::Parser::_keyusage($_[0]);
}

1;
