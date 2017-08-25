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


class ProquintsEncoder
	class ProquintsEncoderError < ::StandardError; end
	
	# 2 bits
	VOVELS = "aiou"

	# 4 bits
	CONSONANTS = "bdfghjklmnprstvz"

	# Converts a byte stream into readable string.
	# Based on "A Proposal for Proquints: Identifiers that are Readable, Spellable, and Pronounceable"
	# See https://arxiv.org/html/0901.4016
	def self.encode(blob)
		raise ProquintsEncoderError, "blob size needs to be even number (multiple of 16 bit)" unless blob.size.even?

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

	def self.decode(text)
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
end


=begin
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
=end

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
* Use GF(256), see https://github.com/codahale/shamir/blob/master/src/main/java/com/codahale/shamir/GF256.java

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
require 'digest/sha1'
require './GF256.rb'

class BinaryEncoder
	class ShareChecksumError < ::StandardError; end
	class ShareDecodeError < ::StandardError; end
	class ShareSanityCheckError < ::StandardError; end
	class ShareVersionError < ::StandardError; end
	
	# 4 bit: version (currently 0)
	# 2 bit: x: 1,2,3 or 4.
	# 10 bit: checksum XOR (2 bit needed (1,2,3,4), 8 bit checksum payload)
	# == 16bit overhead.
	def self.pack(version, x, checksum_share, num_shares_needed, checksum_secret, bytes)
		cs0 = (checksum_share[0] ^ (num_shares_needed - 1)) & 0x3
		cs1 = checksum_share[1] ^ checksum_secret

		a = (version << 4) | ((x-1) << 2) | cs0
		b = cs1
		[ a, b, bytes ].pack("CCa*")
	end
	
	
	# encodes all shares into a save binary representation
	def self.encode(secret, num_shares_needed, shares)
		checksum_secret = Digest::SHA512.digest(secret)[0].unpack("C")[0]
		
		version = 0
		shares.map do |x, bytes|
			# calculate original checksum
			buf = pack(version, x, [0,0], 0, 0, bytes)
			
			# interleave with checksum
			checksum_share = Digest::SHA512.digest(buf)[0...2].unpack("C*")
			pack(version, x, checksum_share, num_shares_needed, checksum_secret, bytes)
		end
	end
	
	def self.unpack(shares)		
		result = shares.map{|blob|
			a,b,bytes = blob.unpack("CCa*")
			version = a>>4
			raise ShareVersionError, "unknown version #{version}" unless version == 0
			
			x = 1 + ((a >> 2) & 0x3)
			
			# calculate original checksum
			buf = pack(version, x, [0,0], 0, 0, bytes)
			checksum_share = Digest::SHA512.digest(buf)[0...2].unpack("C*")
			
			# xor here
			num_shares_needed = 1 + ((checksum_share[0] ^ a) & 0x3)
			checksum_secret = checksum_share[1] ^ b
			
			# puts "needed=#{needed}, checksum_secret=#{checksum_secret.to_s(16)}"

			[x, bytes, num_shares_needed, checksum_secret]
		}
		num_shares_needed = result[0][2]
		checksum_secret = result[0][3]
		result.each do |x, bytes, ns, cs|
			raise ShareChecksumError, "needed / checksum do not match" unless (num_shares_needed == ns && checksum_secret == cs)
		end
	
		# num required, checksum_secret, and mapping.
		{
			:num_required => result[0][2],
			:checksum_secret => result[0][3],
			:shares => result.map {|x,bytes| [x,bytes] }
		}
	end	
	
	def self.decode(shares)
		return false if shares.size < 2
		unpack(shares)
	end
end

class CompactMnemonic
	class ChecksumError < ::StandardError; end

	def self.encode(num_shares_needed, num_shares_total, secret)
		shares = GF256::split(num_shares_needed, num_shares_total, secret)
		BinaryEncoder::encode(secret, num_shares_needed, shares).map do |blob|
			ProquintsEncoder::encode(blob)
		end
	end

	def self.decode(shares)
		shares = shares.map do |proquint|
			ProquintsEncoder::decode(proquint)
		end
		shares = BinaryEncoder::decode(shares)
		decoded_secret = GF256::join(shares[:shares])
		
		# checksum
		checksum_decoded_secret = Digest::SHA512.digest(decoded_secret)[0].unpack("C")[0]
		raise ChecksumError, "checksum error!" unless checksum_decoded_secret == shares[:checksum_secret]
		decoded_secret
	end	
end




def diff(a, b)
	str = ""
	[a.size, b.size].max.times do |i|
		if a[i] == b[i]
			str += " "
		else
			str += "^"
		end
	end
	str
end

def modify(share)
	share = share.gsub(" ", "")
	pos = rand(share.size)
		
	letters = ProquintsEncoder::CONSONANTS 
	letters = ProquintsEncoder::VOVELS if 1 == ((pos%5)%2)
		
	l = nil
	begin
		l = letters[rand(letters.size)]
	end while l == share[pos]
	share[pos] = l
	share
end


require "pp"

#secret = SecureRandom.random_bytes(128 / 8)

num_collisions = 0
num_err_checksum = 0
num_err_version = 0
num_err_final_checksum = 0

num_runs = 0
loop do
	secret = "Hello, World !"
	shares = CompactMnemonic::encode(2, 3, secret)
	
	modified_share0 = modify(shares[0])
	begin
		decoded = CompactMnemonic::decode([modified_share0, shares[1]])
		num_collisions += 1
		
		puts "secret = #{secret.unpack("H*")}"
		puts "collis = #{decoded.unpack("H*")}"
		puts "         #{diff(secret.unpack("H*")[0], decoded.unpack("H*")[0])}"
	rescue BinaryEncoder::ShareChecksumError => e
		num_err_checksum += 1
	rescue BinaryEncoder::ShareVersionError => e
		num_err_version += 1
	rescue CompactMnemonic::ChecksumError => e
		num_err_final_checksum += 1
	end
	
	num_runs += 1
	if num_runs % 10000 == 0
		print "."
		STDOUT.flush
	end
end


=begin
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
		
		# compare checksum
		raise ShareDecodeError, "secret checksum does not match!" unless Digest::SHA512.digest(secret)[0].ord == shares[0][4]
		secret
	end

	
	def self.unpack(shares)
		
		result = shares.map{|i|
			blob = from_text(i)

			a,b,yHex = blob.unpack("CCH*")
			version = a>>4
			x = 1 + ((a >> 2) & 0x3)

			# calculate original checksum
			checksum_share = [0,0]
			checksum_secret = [0,0]
			buf = encode(version, x, [0,0], 0, [0,0], yHex)
			checksum_share = Digest::SHA512.digest(buf)[0...2].unpack("C*")
			
			# xor here
			needed = 1 + ((checksum_share[0] ^ a) & 0x3)
			checksum_secret = checksum_share[1] ^ b
			
			# puts "needed=#{needed}, checksum_secret=#{checksum_secret.to_s(16)}"

			[x, yHex.size/2, yHex.to_i(16), needed, checksum_secret]
		}
		needed = result[0][3]
		checksum_secret = result[0][4]
		result.each do |x|
			raise ShareChecksumError, "needed / checksum do not match" unless (needed == x[3] && checksum_secret == x[4])
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


def gen_prime_table
	(16..64).step(2) do |i|
		n = OpenSSL::BN.new((2**(i*8)).to_s)
		x = 1
		loop{ break if (n+x).prime_fasttest?(100); x += 2 }
		puts "#{i} => OpenSSL::BN.new((2**(8*#{i}) + #{x}).to_s),"
	end
end

def gen_prime_table
	(16..64).step(2) do |i|
		n = OpenSSL::BN.generate_prime(i*8)
		puts "#{i} => OpenSSL::BN.new('#{n.to_s(16)}', 16),"
	end
end


pp find_id_or_nmx(4)

def diff(a, b)
	str = ""
	[a.size, b.size].max.times do |i|
		if a[i] == b[i]
			str += " "
		else
			str += "^"
		end
	end
	str
end

def find_collision(needed, available)
	collisions = 0
	error_checksum_detected = 0
	error_decoding_detected = 0
	type_error = 0
	
	loop do
		entrophy = SecureRandom.random_bytes(128 / 8)
		shares = ShamirSecretSharing::Packed.split(entrophy, available, needed)

		# modify one random letter
		s = shares[0].clone
		s = s.gsub(" ", "")


		pos = rand(s.size-1)+1
		
		letters = CONSONANTS 
		letters = VOVELS if 1 == ((pos%5)%2)
		
		l = nil
		begin
			l = letters[rand(letters.size)]
		end while l == s[pos]
		s[pos] = l
		
		begin
			decoded = ShamirSecretSharing::Packed.combine([s, shares[1]])
			collisions += 1
			puts
			puts "errors checksum detected: #{error_checksum_detected}"
			puts "error decoding detected: #{error_decoding_detected}"
			puts "error probability: 1/#{(error_decoding_detected+error_checksum_detected)/collisions.to_f}"
			puts "collisions: #{collisions}"
			puts "type error: #{type_error}"
			puts "entrophy = #{entrophy.unpack('H*')[0]}"
			puts "decoded  = #{decoded.unpack('H*')[0]}"
			puts "           #{diff(entrophy.unpack('H*')[0], decoded.unpack('H*')[0])}"
			puts "equal? #{entrophy == decoded}"
			puts "share = #{shares[0].gsub(" ", "")}"
			puts "modif = #{s}"
			puts "        #{diff(s, shares[0].gsub(" ", ""))}"
		rescue ShamirSecretSharing::ShareChecksumError => e
			error_checksum_detected += 1
		rescue ShamirSecretSharing::ShareDecodeError => e
			error_decoding_detected += 1
		rescue TypeError => e
			type_error += 1
		end
		
		if (error_checksum_detected % 10000 == 0)
			puts "error probability: 1/#{(error_decoding_detected+error_checksum_detected)/collisions.to_f} (#{collisions+error_checksum_detected+error_decoding_detected+type_error} evals)"
			STDOUT.flush
		end
	end
end

#gen_prime_table

find_collision(2, 3)

# 1/228102.2 2of2
# 

=begin
entrophy = SecureRandom.random_bytes(128 / 8)
puts "entropy=#{entrophy.unpack("H*")}"
shares = ShamirSecretSharing::Packed.split(entrophy, 3, 2)


#shares[1][12]='l'
pp shares
decoded = ShamirSecretSharing::Packed.combine(shares[0...2])
puts "decoded: #{decoded.unpack("H*")}"

=end

