require "pp"


# Mnemonic code for generating deterministic keys 
# 
# Why?
# * Get rid of a wordlist, be more language agnostic => improved portability
# * 4 version bits encoded as the last 5 bits of the words. This is version 0. Therefore, the first letter encodes the version.
# * Checksum is independent from wordlist.

require "securerandom"
require "openssl"
require "base64"

# 2 bits
VOVELS = "aiou"

# 4 bits
CONSONANTS = "bdfghjklmnprstvz"


# Converts a byte stream into readable string.
# Based on "A Proposal for Proquints: Identifiers that are Readable, Spellable, and Pronounceable"
# See https://arxiv.org/html/0901.4016
def to_text(blob)
	# unpack as 16-bit unsigned, network (big-endian) byte order	
	words = blob.unpack("n*").map do |n|
		word = ""
		word += CONSONANTS[(n >> 12) & 0b1111]
		word += VOVELS[(n >> 10) & 0b11]
		word += CONSONANTS[(n >> 6) & 0b1111]
		word += VOVELS[(n >> 4) & 0b11]
		word += CONSONANTS[(n >> 0) & 0b1111]
		word		
	end
	
	words.join(" ")
end

def from_text(text)
	# all non-letters are removed
	stripped = text.gsub(/[^a-zA-Z]/, "")
	
	# split into words
	words = stripped.downcase.scan(/.{5}/)
	
	word_nums = words.map do |w|
		n = 0
		n |= CONSONANTS.index(w[0]) << 12
		n |= VOVELS.index(w[1]) << 10
		n |= CONSONANTS.index(w[2]) << 6
		n |= VOVELS.index(w[3]) << 4
		n |= CONSONANTS.index(w[4])
		n
	end
	
	word_nums.pack("n*")
end


def key_stretching_bits(iteration_bits)
	11 + 3*iteration_bits
end

# calculate number of iterations of the KDF
# 0:         2_048
# 1:        16_384
# 2:       131_072
# 3:     1_048_576
# 4:     8_388_608
# 5:    67_108_864
# 6:   536_870_912
# 7: 4_294_967_296
#
# https://www.wolframalpha.com/input/?i=N(2**11*(((2**31-1)%2F(2**11))**(1%2F7))**n,+2)+where+n%3D0,1,2,3,4,5,6,7
def num_iterations(iteration_bits)
	1 << key_stretching_bits(iteration_bits)
end

def kdf(blob, passphrase, iterations)
	OpenSSL::PKCS5.pbkdf2_hmac(blob, 'mnemonic' + passphrase, iterations, 64, OpenSSL::Digest::SHA512.new)
end

# 8 bits are used for checksum.
# 3 bits are used for iteration calculation.
#
# on average 2^11 = 2048 iterations are required to find an entrophy.
def find_entrophy(version, bits_entrophy, iteration_bits)
	loop do
		blob = SecureRandom.random_bytes(bits_entrophy / 8)
		
		# the hightest 5 bits of the blob are replaced with the version => only bits_entrophy - 5 bits of entrophy.
		blob[0] = ((blob[0].ord & 0b00001111) | (version << 4)).chr

		# checksum grinding
		h = kdf(blob, "", 1)
		
		# return if checksum byte is 0 and the 3 iterations bit are as required
		return blob if (0 == h[0].ord) && iteration_bits == (h[1].ord >> 5)
	end
end

# see https://github.com/lian/bitcoin-ruby/blob/master/lib/bitcoin/trezor/mnemonic.rb
def to_seed(text, passphrase)
	# decode text
	blob = from_text(text)
	
	# check if we have a known version
	version = blob[0].ord >> 4
	throw "unknown version #{version}" if version != 0	
	
	# checksum, *without* password, to support plausible deniability.
	# checksum is performed on decoded text to support other encoding formats as well.
	h = kdf(blob, "", 1)
	throw "checksum not ok" if (0 != h[0].ord)
	
	# extract iterations
	num_iters = num_iterations(h[1].ord >> 5)

	# perform KDF to generate seed
	kdf(h, passphrase, num_iters)
end


# based on http://docs.electrum.org/en/latest/seedphrase.html
# Let n denote the number of entropy bits of the seed, and m the number of bits of difficulty added by key stretching: m = log2(stretching_iterations). Let k denote the length of the prefix, in bits.
# On each iteration of the attack, the probability to obtain a valid seed is p = 2^-k
# The number of hashes required to test a candidate seed is: p * (1+2^m) + (1-p)*1 = 1 + 2^(m-k)
# Therefore, the cost of an attack is: 2^n * (1 + 2^(m-k))
# This can be approximated as 2^(n + m - k) if m>k and as 2^n otherwise.
#
# With the standard values currently used in Electrum, we obtain: 2^(132 + 11 - 8) = 2^135. This means that a standard Electrum seed is equivalent, in terms of hashes, to 135 bits of entropy.
def bits_of_security(bits_encoding, iteration_bits)
	b = bits_encoding
	
	b -= 4 # version bits
	b += key_stretching_bits(iteration_bits)
	b -= 8 # checksum
	b -= 3 # iteration_bits
	
	b
end
	

version = 0
bits_encoding = 9*16 # 9 to 32 words (144 to 512 bits)
iteration_bits = 0 # 0 to 7, in steps of 1
passphrase = "my secret" # defaults to empty


# find an entrophy for the given settings. Does not need a password.
e = find_entrophy(version, bits_encoding, iteration_bits)
puts "entrophy:\n\t#{Base64.strict_encode64(e)}"
puts "mnemonic:\n\t#{to_text(e)}"
puts "seed:\n\t#{Base64.strict_encode64(to_seed(to_text(e), passphrase))}"
puts "bits of security:\n\t#{bits_of_security(bits_encoding, iteration_bits)}"


=begin
References:
* https://en.bitcoin.it/wiki/Mini_private_key_format
* https://en.bitcoin.it/wiki/Talk:Mini_private_key_format
* https://arxiv.org/html/0901.4016
* https://bitcointalk.org/index.php?topic=719813.0
* https://github.com/bitcoin/bips/pull/17
* https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
* https://bitcointalk.org/index.php?topic=102349.0
* https://github.com/bitcoin/bips/pull/17#issuecomment-34545139 on checksum-grinding
* https://github.com/bitcoin/bips/pull/17#issuecomment-34442152
* https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2014-March/004615.html
* delegateable KDF: https://bitcointalk.org/index.php?topic=258678.msg3698304#msg3698304
  Key = HMAC(  KDF(HMAC(passphrase,salt)), passphrase|salt)
* https://github.com/bitcoin/bips/wiki/Comments:BIP-0039
* http://docs.electrum.org/en/latest/seedphrase.html

* https://github.com/cetuscetus/btctool/blob/bip/bip-xxxx.mediawiki 

* emoji encoding
* render in a few different fonts, save as images: https://gist.githubusercontent.com/endolith/157796/raw/a37a313160a2e9d9de8d7c8151ddb9b3cc250e0d/Unicode%2520official%2520emojis.txt
* calculate difference metric between images, select top 256 visually most different entries

[root_key x*16, where x is between (9, 32)
[typo check 8 bit][KDF: 3 bits] => 2048 derivations required on average

* KDF 2 bits:  2^(11 + 2*x) => 2048, 8192, 32 768, 131 072, 524 288, 2 097 152, 8 388 608, 33 554 432
* Date field: 50 years, 1 week: 50*365/7 = 2607. 11 bits: 2048 => 39 years. Good enough for me. 19 years 2^10 still good enough.
  * 10 bits date field
* root_key: 128, 192, 256 bit.
* 


Some rules for generation:

Parameters:
* 128 bits of security
* 8 bit checksum has to be zero
*   1_000 rounds for checksum evaluation
* 100_000 rounds to generate the final seed
* starting seed is "bitcoin key derivation"

* creating a valid key: 100*1024 evaluations required on average.


repeat
	generate 128 bits of randomness (16 bytes)
	calculate 256 x HMAC_SHA512
until 256'th seed starts with 8 bits of zero. (requires 65536 HMAC-SHA512 steps on average)
The seed is the 255th iteration.

Represent the 128bits in 8 5-letter words as described in https://arxiv.org/html/0901.4016

* generate 8 words
* each word has 5 letters: cvcvc
* c is element from "BDFGHJKLMNPRSTVZ"
* v is element from "AIOU"

* concatenate all 8 words into a single string, e.g. "MIDIMSILODHORAHROBOSRAZOJVONUJRUTADRAPOB"
* calculate SHA256 for password concatenated with "?", e.g. "MIDIMSILODHORAHROBOSRAZOJVONUJRUTADRAPOB?"
* Generate password like above until first byte of SHA256 is zero, this is the checksum. (~256 generations required).

* If the 256th iteration starts with 8 zero bits, the 255th iteration is the hash.
* If the 513th iteration starts with 9 zero bits
* checksum: 1st derivation of HMAC_SHA512 has to start with byte 0.
* 

* split every 5 characters, join with " " and "\n" altering. Results in e.g.

midim silod
horah robos
razoj vonuj
rutad rapob

This is what the user has to write down.


Rules for decoding:

* Whatever the user enters, all non-[a-zA-Z] characters are removed.
* Toupper.
* SHA hash is calculated form the remaining characters, and verified if the first byte is 0.

* To encode as QR-code, it is enough to use AlphaNumeric data which generates a very compact QR code.

=end



=begin
vovels = "AIOU".split("")
consonants = "BDFGHJKLMNPRSTVZ".split("")
sha = Digest::SHA2.new(256)

begin
    pwd = ""
    s = 1
    9.times do |w|
        5.times do |l|
            if (0 == (l % 2))
                pwd += consonants.sample; s *= consonants.size
            else
                pwd += vovels.sample; s *= vovels.size
            end
        end
    end    
    sha.reset
    sha.update "#{pwd}?"
    hex = sha.hexdigest
end while !hex.start_with?("00")


digest = OpenSSL::Digest.new('sha512')
p digest

key = "Compact Mnemonic"
p OpenSSL::HMAC.hexdigest(digest, key, pwd)




less = "less"
f = (2**128*256)/(s.to_f)
if (f < 1)
    less = "more"
    f = 1/f
end

def pretty(pwd)
    pwd = pwd.downcase.scan(/.{5}/)
    str = "\t"
    pwd.size.times do |i|
        str += pwd[i]
        if i.even?
            str += " "
        else
            str += " "
        end
    end
    str
end

def decode(pwd)
    pwd = pwd.gsub(/[^a-zA-Z]/, "").upcase
    hex = Digest::SHA2.hexdigest("#{pwd}?")
	print "\tchecksum: #{hex[0...2]} "
    if !hex.start_with?("00")
        puts "NOT ok :("
    else 
        puts "OK :)"
    end
	
end

puts "compact mnemonic:"
puts pretty(pwd)
puts "QR code:"
puts "\thttps://chart.googleapis.com/chart?chs=250x250&cht=qr&chl=#{pwd}"
puts
puts "BIP 39 example:"
puts "\ticon shallow bar topic chest foster soap walnut judge junk anger glove"
puts
puts "SHA256:"
puts "\t#{Digest::SHA2.hexdigest(pwd)}"
puts
puts "#{Math.log(s/256)/Math.log(2)} bits of security (#{f} times #{less} secure than 2^128)"
puts
decode(pretty(pwd))


Let 
* n denote the number of entropy bits of the seed, and
* m the number of bits of difficulty added by key stretching: m = log2(stretching_iterations). Let 
* k denote the length of the prefix, in bits.

On each iteration of the attack, the probability to obtain a valid seed is p = 2^-k

The number of hashes required to test a candidate seed is: p * (1+2^m) + (1-p)*1 = 1 + 2^(m-k)

Therefore, the cost of an attack is: 2^n * (1 + 2^(m-k))

This can be approximated as 2^(n + m - k) if m>k and as 2^n otherwise.

With the standard values currently used in Electrum, we obtain: 2^(132 + 11 - 8) = 2^135. This means that a standard Electrum seed is equivalent, in terms of hashes, to 135 bits of entropy.

9 words:
9*16 + m - 11

2 ^

Next  Previous


=end


# from https://github.com/lian/shamir-secret-sharing/blob/master/lib/shamir-secret-sharing.rb
# stripped down to the bare minimum
require 'openssl'
require 'digest/sha1'

class ShamirSecretSharing
	def self.pack(shares); shares; end
	def self.unpack(shares); shares; end
	
	def self.encode(id, checksum0, checksum1, yHex); 
		[((id << 1) | (checksum0 & 1)), checksum1, yHex].pack("CCH*")
	end
	def self.decode(string); string; end

	def self.smallest_prime_of_bytelength(bytelength)
		n = OpenSSL::BN.new((2**(bytelength*8)+1).to_s)
		loop{ break if n.prime_fasttest?(20); n += 2 }
		n
	end

	def self.split(secret, available, needed)
		raise ArgumentError, "needed must be <= available" unless needed <= available
		raise ArgumentError, "needed must be >= 2"         unless needed >= 2
		raise ArgumentError, "available must be <= 250"    unless available <= 250

		num_bytes = secret.bytesize
		secret = OpenSSL::BN.new(secret.unpack("H*")[0], 16) rescue OpenSSL::BN.new("0") # without checksum
		raise ArgumentError, "bytelength of secret must be >= 1"   if num_bytes < 1
		raise ArgumentError, "bytelength of secret must be <= 512" if num_bytes > 512

		prime  = smallest_prime_of_bytelength(num_bytes)
		coef = [ secret ] + Array.new(needed-1){ OpenSSL::BN.rand(num_bytes * 8) }

		shares = (1..available).map{|x|
			x = OpenSSL::BN.new(x.to_s)
			y = coef.each_with_index.inject(OpenSSL::BN.new("0")){|acc, (c, idx)|
				acc + c * x.mod_exp(idx, prime)
			} % prime
			[x, num_bytes, y]
		}
		pack(shares, needed)
	end

	def self.combine(shares)
		return false if shares.size < 2
		shares = unpack(shares)
		num_bytes = shares[0][1]
		prime = smallest_prime_of_bytelength(num_bytes)

		secret = shares.inject(OpenSSL::BN.new("0")){|secret,(x,num_bytes,y)|
			l_x = l(x, shares, prime)
			summand = OpenSSL::BN.new(y.to_s).mod_mul(l_x, prime)
			secret = (secret + summand) % prime
		}
		secret = [ secret.to_s(16).rjust(num_bytes*2, '0') ].pack("H*")
	end

	# Part of the Lagrange interpolation.
	# This is l_j(0), i.e.  # \prod_{x_j \neq x_i} \frac{-x_i}{x_j - x_i}
	# for more information compare Wikipedia: # http://en.wikipedia.org/wiki/Lagrange_form
	def self.l(current_x, shares, prime)
		shares.select{|x,num_bytes,y| x != current_x }.map{|x,num_bytes,y|
			minus_xi = OpenSSL::BN.new((-x).to_s)
			one_over_xj_minus_xi = OpenSSL::BN.new((current_x - x).to_s).mod_inverse(prime)
			minus_xi.mod_mul(one_over_xj_minus_xi, prime)
		}.inject{|p,f| p.mod_mul(f, prime) }
	end

	class ShareChecksumError < ::StandardError; end
	class ShareDecodeError < ::StandardError; end
	class ShareSanityCheckError < ::StandardError; end

	class Packed < ShamirSecretSharing # packing format and checkum
		def self.pack(shares, needed)
			available = shares.size
			shares.map{|x,num_bytes,y|
				# 4 bit: version (currently 0)
				# 3 bit: n-of-m up to 3of3, with share.
				# 9 bit checksum (1/512. Calculated on whole data, where checkusm is set to 0.
				# == 16bit overhead.
				nr = x.to_s.to_i
				id, _ = find_id_or_nmx([needed, available, nr])
				yHex = y.to_s(16).rjust(num_bytes*2, '0')
				buf = encode(id, 0, 0, yHex)
				checksum = Digest::SHA512.digest(buf)[0...2].unpack("C*")
				
				# interleave with checksum
				blob = encode(id, checksum[0], checksum[1], yHex)
				to_text(blob)
			}
		end
		def self.unpack(shares)
			shares.map{|i|
				blob = from_text(i)
				# first, make sure checksum is ok.
				a, b, yHex = blob.unpack("CCH*")
				id = (a >> 1) & 0x7 # only 3 bits for id
				buf = encode(id, 0, 0, yHex)
				checksum = Digest::SHA512.digest(buf)[0...2].unpack("C*")
				# interleave with checksum
				buf = encode(id, checksum[0], checksum[1], yHex)
				raise ShareChecksumError, "share: #{i}" unless buf == blob

				id, n, m, x = find_id_or_nmx(id)

				[x, yHex.size/2, yHex.to_i(16)]
			}
		end
	end
end


# converts an ID to n-of-m and nr. of the share.
def find_id_or_nmx(id_or_nmx, max_m=30)
	return [0, 1, 1, 1] if id_or_nmx == 0 || id_or_nmx == [1,1,1]
	
	id = 0
	max_m.times do |m|
		m.times do |n|
			(m+1).times do |nr|
				nmx = [n+2, m+1, nr+1]
				return [id] + nmx if id_or_nmx == id || id_or_nmx == nmx
				id += 1
			end
		end
	end
	nil
end

id = 0
loop do
	r = find_id_or_nmx(id, 3)
	break unless r
	pp [id, r]
	id += 1
end

pp find_id_or_nmx(4)

entrophy = SecureRandom.random_bytes(128 / 8)
puts "entropy=#{entrophy.unpack("H*")}"
shares = ShamirSecretSharing::Packed.split(entrophy, 3, 3)

pp shares
puts "decoded: #{ShamirSecretSharing::Packed.combine(shares[0...3]).unpack("H*")}"


p [0, 1, 1, 1]

id = 0
5.times do |m|
	m.times do |n|
		(m+1).times do |nr|
			nmx = [n+2, m+1, nr+1]
			p [id] + nmx
			id += 1
		end
	end
end
puts Math.log(id)/Math.log(2)
nil
