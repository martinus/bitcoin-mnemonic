# This is a straight ruby port of Coda Hale's https://github.com/codahale/shamir
# A bit simplified.
# https://github.com/codahale/shamir/blob/master/src/main/java/com/codahale/shamir/GF256.java

require "securerandom"

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
			return i unless p[i].ord == 0
		end
		0
	end
	
	def self.generate(required_degree, x)
		# generate random polynomials until we find one of the given degree
		loop do			
			p = SecureRandom.random_bytes(required_degree + 1)
			if degree(p) == required_degree
				# set y intercept
				p[0] = x
				return p
			end
		end 
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

=begin
shares = nil
t = Time.now
10000.times do 
	shares = GF256::split(3, 10, "yayasdfase")
end
puts Time.now - t
pp shares

secret = GF256::join([shares[0], shares[7], shares[2]])
pp secret
=end

#p [1,2, "asdf\x00a"].pack("CCa*")