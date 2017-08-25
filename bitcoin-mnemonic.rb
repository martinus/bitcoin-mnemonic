=begin
Mnemonic code for generating deterministic keys 
 
Why?
* Get rid of a wordlist, be more language agnostic => improved portability, more compact.
* Added versioning: 4 version bits, which defines encoding.
* very compact representation: 16bit overhead.
* No password support because it is inherently unsafe.
* Support n-of-m shares, up to 4-of-4.
* Fast computation also on low end devices
* Good typo safety: probability for 2-of-n to generate a valid wrong key is 1 in 2^18.
* Checksum is independent from wordlist.
* very compact QR code: 128 bit encode into 45 Alphanumeric characters, so version 2 is enough: https://chart.googleapis.com/chart?chs=150x150&cht=qr&chl=BASABMIVAPPOTUFJULOHHIFOBRIGIJPAJIHLUTOLHAJAJ

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

require "securerandom"

class Crypto
	def self.hash(data)
		Digest::SHA512.digest(data)
	end
	
	def self.random_bytes(n)
		SecureRandom.random_bytes(n)
	end
	
	def self.rand(n)
		SecureRandom.random_number(n)
	end
end
	

class ProquintsEncoder
	class ProquintsEncoderError < ::StandardError; end
	
	# 2 bits
	VOVELS = "aiou".split("")

	# 4 bits
	CONSONANTS = "bdfghjklmnprstvz".split("")

	# Converts a byte stream into readable string.
	# Based on "A Proposal for Proquints: Identifiers that are Readable, Spellable, and Pronounceable"
	# See https://arxiv.org/html/0901.4016
	def self.encode(blob)
		raise ProquintsEncoderError, "blob size needs to be even number (multiple of 16 bit)" unless blob.size.even?

		# unpack as 16-bit unsigned, network (big-endian) byte order
		word = ""
		blob.unpack("n*").each do |n|
			word << CONSONANTS[(n >> 12) & 0b1111]
			word << VOVELS[(n >> 10) & 0b11]
			word << CONSONANTS[(n >> 6) & 0b1111]
			word << VOVELS[(n >> 4) & 0b11]
			word << CONSONANTS[(n >> 0) & 0b1111]
			word << " "
		end
		
		word.chomp
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


# This is a straight ruby port of Coda Hale's https://github.com/codahale/shamir
# A bit simplified.
# https://github.com/codahale/shamir/blob/master/src/main/java/com/codahale/shamir/GF256.java

class GF256
	LOG = [
		"ff00190132021ac64bc71b6833eedf036404e00e348d81ef4c7108c8f8691cc1" +
		"7dc21db5f9b9276a4de4a6729ac90978652f8a05210fe12412f082453593da8e" +
		"968fdbbd36d0ce94135cd2f14046833866ddfd30bf068b62b325e29822889110" +
		"7e6e48c3a3b61e423a6b2854fa853dba2b790a159b9f5eca4ed4ace5f373a757" +
		"af58a850f4ead6744faee9d5e7e6ade82cd7757aeb160bf559cb5fb09ca951a0" +
		"7f0cf66f17c449ecd8431f2da4767bb7ccbb3e5afb60b1863b52a16caa55299d" +
		"97b2879061bedcfcbc95cfcd373f5bd15339843c41a26d47142a9e5d56f2d3ab" +
		"441192d923202e89b47cb8267799e3a5674aeddec531fe180d638c80c0f77007" ].pack("H*").unpack("C*")
	EXP = [
		"0103050f113355ff1a2e7296a1f813355fe13848d87395a4f702060a1e2266aa" +
		"e5345ce43759eb266abed97090abe63153f5040c143c44cc4fd168b8d36eb2cd" +
		"4cd467a9e03b4dd762a6f10818287888839eb9d06bbddc7f8198b3ce49db769a" +
		"b5c457f9103050f00b1d2769bbd661a3fe192b7d8792adec2f7193aee92060a0" +
		"fb163a4ed26db7c25de73256fa153f41c35ee23d47c940c05bed2c749cbfda75" +
		"9fbad564acef2a7e829dbcdf7a8e89809bb6c158e82365afea256fb1c843c554" +
		"fc1f2163a5f407091b2d7799b0cb46ca45cf4ade798b8691a8e33e42c651f30e" +
		"12365aee297b8d8c8f8a8594a7f20d17394bdd7c8497a2fd1c246cb4c752f601" +
		"03050f113355ff1a2e7296a1f813355fe13848d87395a4f702060a1e2266aae5" +
		"345ce43759eb266abed97090abe63153f5040c143c44cc4fd168b8d36eb2cd4c" +
		"d467a9e03b4dd762a6f10818287888839eb9d06bbddc7f8198b3ce49db769ab5" +
		"c457f9103050f00b1d2769bbd661a3fe192b7d8792adec2f7193aee92060a0fb" +
		"163a4ed26db7c25de73256fa153f41c35ee23d47c940c05bed2c749cbfda759f" +
		"bad564acef2a7e829dbcdf7a8e89809bb6c158e82365afea256fb1c843c554fc" +
		"1f2163a5f407091b2d7799b0cb46ca45cf4ade798b8691a8e33e42c651f30e12" +
		"365aee297b8d8c8f8a8594a7f20d17394bdd7c8497a2fd1c246cb4c752f60000" ].pack("H*").unpack("C*")
		
	def self.add(a, b)
		a ^ b
	end
	
	def self.sub(a, b)
		add(a,b)
	end
	
	def self.mul(a, b)
		return 0 if a == 0 || b == 0
		EXP[(LOG[a] + LOG[b]) % 255]
	end
	
	def self.div(a, b)
		# multiply by the inverse of b
		mul(a, EXP[255 - LOG[b]])
	end

	def self.eval(p, x)
		# horner's method
		result = 0
		(p.length - 1).downto(0) do |i|
			result = add(mul(result, x), p[i].ord)
		end
		result
	end
	
	def self.degree(p)
		(p.length - 1).downto(0) do |i|
			return i if p[i].ord != 0
		end
		0
	end
	
	def self.generate(required_degree, x)
		# generate random polynomials until we find one of the given degree
		p = Crypto::random_bytes(required_degree + 1)
		while p[-1].ord == 0
			p[-1] = Crypto::random_bytes(1)
		end
		p[0] = x
		p
	end
	
	def self.interpolate(points)
		# calculate f(0) of the given points using Lagrangian interpolation
		x = 0
		y = 0
		points.size.times do |i|
			aX = points[i][0]
			aY = points[i][1]
			li = 1
			points.size.times do |j|
				bX = points[j][0]
				if (i != j)
					li = mul(li, div(sub(x, bX), sub(aX, bX)))
				end
			end
			y = add(y, mul(li, aY))
		end
		y
	end

	def self.split(num_shares_needed, num_shares_total, secret)
		# generate part values
		values = Array.new(num_shares_total) { Array.new(secret.length) }
		secret.length.times do |i|
			# for each byte, generate a random polynomial, p
			p = GF256::generate(num_shares_needed - 1, secret[i])			
			(1..num_shares_total).each do |x|
				# each part's byte is p(partId)
				values[x - 1][i] = GF256::eval(p, x)
			end
		end
		
		shares = []
		values.each_index do |i|
			shares.push [i+1, values[i].pack("C*")]
		end
		shares
	end
	
	def self.join(parts)
		length = parts[0][1].length
		
		secret = Array.new(length)
		secret.each_index do |i|
			points = parts.map do |nr, share|
				[nr, share[i].ord]
			end
			secret[i] = GF256::interpolate(points)
		end
		secret.pack("C*")
	end	
end


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
		checksum_secret = Crypto::hash(secret)[0].unpack("C")[0]
		
		version = 0
		shares.map do |x, bytes|
			# calculate original checksum
			buf = pack(version, x, [0,0], 0, 0, bytes)
			
			# interleave with checksum
			checksum_share = Crypto::hash(buf)[0...2].unpack("C*")
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
			checksum_share = Crypto::hash(buf)[0...2].unpack("C*")
			
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


TIMER = Hash.new do |h,k| h[k] = 0.0 end

class CompactMnemonic
	class ChecksumError < ::StandardError; end

	def self.encode(num_shares_needed, num_shares_total, secret)
		t = Time.now;
		shares = GF256::split(num_shares_needed, num_shares_total, secret)
		
		TIMER[:split] += Time.now - t; t = Time.now;
		enc = BinaryEncoder::encode(secret, num_shares_needed, shares)
		TIMER[:enc] += Time.now - t; t = Time.now;
		
		proquints = enc.map do |blob|
			ProquintsEncoder::encode(blob)
		end
		TIMER[:proquints] += Time.now - t;
		
		proquints
	end

	def self.decode(shares)
		shares = shares.map do |proquint|
			ProquintsEncoder::decode(proquint)
		end
		shares = BinaryEncoder::decode(shares)
		decoded_secret = GF256::join(shares[:shares])
		
		# checksum
		checksum_decoded_secret = Crypto::hash(decoded_secret)[0].unpack("C")[0]
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
	pos = Crypto::rand(share.size-1)+1
		
	letters = ProquintsEncoder::CONSONANTS 
	letters = ProquintsEncoder::VOVELS if 1 == ((pos%5)%2)
		
	l = nil
	begin
		l = letters[Crypto::rand(letters.size)]
	end while l == share[pos]
	share[pos] = l
	share
end


require "pp"

num_collisions = 0
num_err_checksum = 0
num_err_version = 0
num_err_final_checksum = 0
num_total_runs = 0

t_start = Time.now
secret = Crypto::random_bytes(128/8)



loop do
	shares = CompactMnemonic::encode(2, 3, secret)
	modified_share0 = shares[0]
	
	modified_share0 = modify(modified_share0)
	begin
		#pp [modified_share0, shares[1]]
		decoded = CompactMnemonic::decode([modified_share0, shares[1]])
		num_collisions += 1
		
		puts
		puts "num_err_checksum: #{num_err_checksum}"
		puts "num_err_version: #{num_err_version}"
		puts "num_err_final_checksum: #{num_err_final_checksum}"
		puts "num_collisions: #{num_collisions}"
		puts "num_total_runs: #{num_total_runs}"

		puts "share = #{shares[0].gsub(" ", "")}"
		puts "modif = #{modified_share0}"
		puts "        #{diff(shares[0].gsub(" ", ""), modified_share0)}"
		puts "secret = #{secret.unpack("H*")[0]}"
		puts "collis = #{decoded.unpack("H*")[0]}"
		puts "         #{diff(secret.unpack("H*")[0], decoded.unpack("H*")[0])}"
	rescue BinaryEncoder::ShareChecksumError => e
		num_err_checksum += 1
	rescue BinaryEncoder::ShareVersionError => e
		num_err_version += 1
	rescue CompactMnemonic::ChecksumError => e
		num_err_final_checksum += 1
	end
	
	num_total_runs += 1
	if num_total_runs % 10000 == 0
		pp TIMER
		if num_collisions != 0
			puts "1/#{num_total_runs / num_collisions}, #{num_total_runs/(Time.now - t_start)}"
		else
			puts "#{num_total_runs}, #{num_total_runs/(Time.now - t_start)}"
		end
	end
end
