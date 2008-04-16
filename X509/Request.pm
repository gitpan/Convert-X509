package Convert::X509::Request;

use strict;
use warnings;
use Convert::X509::Parser;

# require Exporter;
# our @ISA = qw(Exporter);
# our @EXPORT_OK = qw(new); # subject from to EKU extensions);
our $VERSION = '0.1';

sub new {
  my ($class,$data)=@_;
  Convert::X509::Parser::_prepare(\$data);
  my $d = Convert::X509::Parser::_decode('req'=>$data);
  return undef unless $d;
  my $req = {
    'subject'	=> Convert::X509::Parser::_decode_rdn($d->{'certificationRequestInfo'}{'subject'}{'rdnSequence'}),
    'attributes'	=> {},
    'signature'	=> {
		'sign'		=> $d->{'signature'}[0], # bits
		'length'		=> $d->{'signature'}[1],
		'algorithm'	=> $d->{'signatureAlgorithm'}{'algorithm'},
		'params'		=> $d->{'signatureAlgorithm'}{'parameters'},
	 },
    'pkinfo'		=> {
		'algorithm'	=> $d->{'certificationRequestInfo'}{'subjectPKInfo'}{'algorithm'}{'algorithm'}, # yes, 2 times
		'params'	=> $d->{'certificationRequestInfo'}{'subjectPKInfo'}{'algorithm'}{'parameters'},
		'length'	=> $d->{'certificationRequestInfo'}{'subjectPKInfo'}{'subjectPublicKey'}[1],
		'key'		=> $d->{'certificationRequestInfo'}{'subjectPKInfo'}{'subjectPublicKey'}[0],
	 },
  };
# $req->{'signature'}->{'hex'} = uc( unpack('H*',$req->{'signature'}->{'sign'}) );

# by "for" - more readable
  for my $attr ( @{ $d->{'certificationRequestInfo'}{'attributes'} } ){
      $req->{'attributes'}{ $attr->{'type'} } =
        Convert::X509::Parser::_decode( $attr->{'type'} , @{$attr->{'values'}} ) 
      ;
  }

  $req->{'extensions'}=
    Convert::X509::Parser::_decode_ext (
      $req->{'attributes'}{'1.3.6.1.4.1.311.2.1.14'},
      $req->{'attributes'}{'1.2.840.113549.1.9.14'}
  );

#  $req->{'extensions'}{'2.5.29.17'} =
#    Convert::X509::Parser::_decode_rdn($req->{'extensions'}{'2.5.29.17'}{'value'});

  return (bless $req, $class);
}

sub subject {
  my $self = shift;
  return Convert::X509::Parser::_rdn2str($self->{'subject'},@_);
}

sub eku {
  return Convert::X509::Parser::_eku($_[0]);
}

sub keyusage {
  return Convert::X509::Parser::_keyusage($_[0]);
}

1;
