#!/usr/bin/perl -w
use strict;
use LWP::UserAgent;
use HTTP::Request::Common qw(POST);
use JSON::XS;
use CGI;
use CGI::Carp qw(warningsToBrowser fatalsToBrowser); 
use Digest::SHA qw(sha256_hex sha256);
use POSIX;
use macommon;

# User define values

my $rpcuser = "";
my $rpcpw = "";
my $server = "";
my $port = 443;
my $https = 1;


print "Content-Type:text/html\n\n";
print "<HTML><BODY><PRE>\n";

my ($block, $height, $txid, $txindex, $txoindex, $ntx, $ntxo, $spk, %qs);

my $mincs = 20;

if (length ($ENV{'QUERY_STRING'}) > 0){
	my @pairs = split(/&/, $ENV{'QUERY_STRING'});
	foreach (@pairs) {
		my ($key, $value) = split(/=/);
		$qs{$key} = $value;
	}
	if ($qs{'mincs'} =~ /^[1-9]\d+$/) {
		$mincs = $qs{'mincs'};
	}
	if ($qs{'txid'} !~ /^[a-fA-F0-9]{64}$/) {
		print "Invalid transaction ID";
		&finish;
	}
	elsif ($qs{'txo'} !~ /^[1-9]\d*$/) {
		print "Invalid output ID (First output in a transaction = 1)";
		&finish;
	}
	else {
		$txoindex = $qs{'txo'} - 1;
		my ($url, $ua);
		if ($https) {
			$url= "https://$rpcuser:$rpcpw\@$server:$port/";
			$ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
		}

		else {
			$url= "http://$rpcuser:$rpcpw\@$server:$port/";
			$ua = LWP::UserAgent->new;
		}
		
		my $req = POST $url;
		
		my $grt;
		
		$grt->{'method'} = "getrawtransaction";
		my $one = 1;
		$grt->{'params'} = [$qs{'txid'},$one];
		#$grt = $grt->allow_blessed;
		$req->content(encode_json $grt);
		my $res = $ua->request($req);

		if ($res->is_success) {
			my $result = (decode_json $res->content)->{'result'};
			if ($result->{'vout'}->[$txoindex]) {
				$txid = $result->{'txid'};
				print "Transaction ID: $txid\n";
				$block = $result->{'blockhash'};
				print "In block: $block\n";
				my $gb;
				$gb->{'method'} = "getblock";
				$gb->{'params'} = [$block];
				$req->content(encode_json $gb);
				my $gbres = $ua->request($req);
				if ($gbres->is_success) {
					my $gbresult = (decode_json $gbres->content)->{'result'};
					$height = $gbresult->{'height'};
					print "Block height (First block = 0): $height\n";
					my $txs = join '', @{$gbresult->{'tx'}};
					if ($txs =~ /$result->{'txid'}/ && ($+[0]%64 == 0)) {
						$txindex = $+[0]/64 - 1;
						print "Transaction order (First transaction = 1): " . ($txindex + 1) . "\n";
					}
					else {
						print "Transaction not in the block";
						&finish;
					}
					$ntx = $#{$gbresult->{'tx'}}+1;
					print "Number of transactions in the block: $ntx\n";
				}
				else {
					print $res->status_line . "\n";
					print $res->content;
					&finish;
				}
				print "Output order (First output = 1): " . ($txoindex + 1) . "\n";
				$ntxo = $#{$result->{'vout'}}+1;
				print "Number of outputs in the transaction: $ntxo\n";
				if ($result->{'vout'}->[$qs{'txo'}-1]->{'scriptPubKey'}->{'type'} =~ /^(scripthash|pubkeyhash)$/) {
					print "Output type: Address\n";
					print "Address: $result->{'vout'}->[$qs{'txo'}-1]->{'scriptPubKey'}->{'addresses'}->[0]\n";
				}
				elsif ($result->{'vout'}->[$qs{'txo'}-1]->{'scriptPubKey'}->{'type'} eq "nulldata") {
					print "Output type: Null data\n";
				}
				else {
					print "Output type: Uncommon\n";
				}
				$spk = $result->{'vout'}->[$qs{'txo'}-1]->{'scriptPubKey'}->{'hex'};
				print "Output script: $result->{'vout'}->[$qs{'txo'}-1]->{'scriptPubKey'}->{'asm'}\n";
				#print "\n\n";
				#print $res->content;
				my ($w, $x, $y, $z, $height_b, $txindex_b, $txoindex_b);
				
				
				#Step 1:
				
				
				if ($height < 1048576) {
					$height_b = &bitorder (&dectobin ($height, 20));
					$height_b = "0" . $height_b;
					$x = 21;
				}
				elsif ($height < 8388608) {
					$height_b = &bitorder (&dectobin ($height, 23));
					$height_b = "1" . $height_b;
					$x = 24;
				}
				else {
					print "Height > 83886070 not supported\n";
					&finish;
				}
				print "\nStep 1\n";
				print "Height in binary: $height_b\n";
				print "Height bits: $x\n";
				
				
				#Step 2:
				my $ymin = &countbit($txindex);
				my $zmin = &countbit($txoindex);
				$w = ceil(($x + $ymin + $zmin + $mincs + 1)/11);
				print "\nStep 2:\n";
				print "Minimum bits to encode txIndex: $ymin\n";
				print "Minimum bits to encode txoIndex: $zmin\n";
				print "Minimun bits for checksum: $mincs\n";
				print "Lower bound of words required for the mnemonic address (w): $w\n";
				

				while (1) {
					#Step 3:
					my $y1 = &countbit($ntx - 1);
					my $y2 = (11 * $w) - 1 - $x - $mincs;
					if ($y1 < $y2) {
						$y = $y1;
					}
					else {
						$y = $y2;
					}
					
					print "\nStep 3:\n";
					print "y1: $y1\n";
					print "y2: $y2\n";
					print "txIndex bits: $y\n";
		
					#Step 4:
					my $z1 = &countbit($ntxo - 1);
					my $z2 = (11 * $w) - 1 - $x - $y - $mincs;
					if ($z1 < $z2) {
						$z = $z1;
					}
					else {
						$z = $z2;
					}
					print "\nStep 4:\n";

					print "z1: $z1\n";
					print "z2: $z2\n";
					print "txoIndex bits: $z\n";
					if ($zmin > $z) {
						print "Not enough bits to encode txoIndex, increase w by 1 and go back to step 3\n";
						$w += 1;
					}
					else {
						last;
					}
				}
				$txindex_b = &bitorder (&dectobin($txindex, $y));
				my ($tib, $toib);
				if ($txindex_b eq "") {
					$tib = "(Empty)";
				}
				else {
					$tib = $txindex_b;
				}
				print "txIndex in binary: $tib\n";
				$txoindex_b = &bitorder (&dectobin($txoindex, $z));
				if ($txoindex_b eq "") {
					$toib = "(Empty)";
				}
				else {
					$toib = $txoindex_b;
				}
				print "txoIndex in binary: $toib\n";
				print "Final number of words: $w\n";
				
				print "\nStep 5:\n";
				print "Blockhash in little endian: " . &byteorder($block) . "\n";
				print "txIndex in 32-bit little endian: " . &byteorder(&dectohex($txindex, 32)) . "\n";
				print "txoIndex in 32-bit little endian: " . &byteorder(&dectohex($txoindex, 32)) . "\n";
				print "scriptPubKey: $spk\n";
				my $tocshash = &byteorder($block).&byteorder(&dectohex($txindex, 32)).&byteorder(&dectohex($txoindex, 32)).$spk;
				print "String to hash: $tocshash\n";
				my $cshash = sha256_hex(sha256(pack 'H*', $tocshash));
				print "Double SHA-256: $cshash\n";
				my $c = (11 * $w) - 1 - $x - $y - $z;
				print "Actual checksum bits: $c\n";
				my $cs = substr &hextobin($cshash), 0, $c;
				print "Checksum (first $c bits of hash): $cs\n";
				
				print "\nStep 6:\n";
				my $rawaddress = $height_b.$txindex_b.$txoindex_b.$cs;
				print "Rawaddress: $rawaddress\n";
				
				print "\nStep 7:\n";
				my $encryptkey = substr $rawaddress, 0-$mincs;
				print "Encryption key: $encryptkey\n";
				
				my $addresstoencrypt = substr $rawaddress, 0, 0-$mincs;
				print "Address to encrypt:   $addresstoencrypt\n";
				
				print "\nStep 8:\n";
				my $finalencryptkey = ($encryptkey x int((length $addresstoencrypt) / $mincs)) . substr $encryptkey, 0, ((length $addresstoencrypt) % $mincs);
				print "Final encryption key: $finalencryptkey\n";
				
				print "\nStep 9:\n";
				my $encryptedaddress = &xorcrypt ($addresstoencrypt, $finalencryptkey);
				print "Encrypted address:    $encryptedaddress\n";
				
				print "\nStep 10:\n";
				my $finaladdress = $encryptedaddress.$encryptkey."0";
				print "Final address:        $finaladdress\n";
				
				print "\nStep 11:\n";
				print "Final address in base2048: ";
				my $mnemonic = &tobip39 ($finaladdress);
				while ($finaladdress ne "") {
					my $word = substr $finaladdress, 0, 11, "";
					$word = oct("0b".$word);
					print "$word ";
				}
				print "\n";
				print "Mnemonic address: $mnemonic\n";
				
				
			}
			else {
				print "No such output in this transaction (First output in a transaction = 1)";
				&finish;
			}
		}

		else {
			print $res->status_line . "\n";
			print $res->content;
			&finish;
		}
	}
}

&finish;




sub finish {
	print "</PRE><FORM action=\"ma1.pl\">\n";
	print "Transaction ID: <input type=\"text\" name=\"txid\" value=\"$qs{'txid'}\" size=\"100\" maxlength=\"64\">\n";
	print "<br><br>\n";
	print "Output index (First output = 1): <input type=\"text\" name=\"txo\" value=\"$qs{'txo'}\">\n";
	print "<br><br>\n";
	print "Minimum checksum bits: <input type=\"text\" name=\"mincs\" value=\"$mincs\">\n";
	print "<br><br>\n";
	print "<input type=\"submit\" value=\"Submit\">\n";
	print "</FORM></BODY></HTML>";
	exit;
}