-- **** WIP ****
-- Lamport Digital Signatures using the "Rung'd Ladder" approach to compressing signatures.
math.randomseed(os.time())

function string.to_hex(str)
	return (str:gsub('.', function(c)
		return string.lower(string.format('%02x', string.byte(c)))
	end))
end

function string.from_hex(str)
	return (str:gsub('..', function(cc)
		return string.char(tonumber(cc,16))
	end))
end

function rand(n)
	t = {}
	for i = 1, n do
		t[i] = string.char(math.random(0,255))
	end
	--return table.concat(t)
	return digest(tostring(table.concat(t)), n*8)
end

function xor(a,b)
	local t = {}
	for i = 1, #a do
		t[i] = string.char(bit.bxor(a:byte(i,i),b:byte(i,i)))
	end
	return table.concat(t)
end

function digest(message, hashlen, sb, sc, sd, se)
	hashlen = hashlen or 256
	local stsz = hashlen --2 ^ 8
	local stm1 = stsz - 1
	local b, c, d, e = sb or 3, sc or 5, sd or 8, se or 13
	local state = {}
	local rsl = "0"
	local hash = {}
	for j = 1, #message do
		for i = 0, stsz do
			e = (state[bit.band(d,stm1)] or 0 + string.byte(string.sub(message,j,j)))
			state[bit.band(d,stm1)] = bit.bxor(b,c)
			b = c - d
			c = d + e
			d = e + (state[i] or 0)
			rsl = (rsl + d) % 256
		end
	end
	for j = 1, hashlen/8 do
		for i = 0, stsz do
			e = (state[bit.band(d,stm1)] or 0) + i
			state[bit.band(d,stm1)] = bit.bxor(b,c)
			b = c - d
			c = d + e
			d = e + (state[i] or 0)
			rsl = (rsl + d) % 256
		end
		hash[j] = string.format("%02x", rsl):from_hex()
	end
	return table.concat(hash)
end

-- **************** SIGNING ****************

-- 1.	Take the 256-bit hash of the document to sign
io.write("Message: ")
message = io.read()
message_hash = digest(message, 256)
print("Hash:", message_hash:to_hex())

-- 2.	Split the hash into 32 8-bit chunks
--print("\n******** CHUNKS ********")
chunks = {}
for i = 1, 32 do
	chunks[i] =  message_hash:sub(i,i)
--	print(i, chunks[i]:to_hex())
end

-- 3.	For each chunk, generate a pair of secret random 256-bit numbers.
-- These 64 numbers are the private key.
print("\n******** PRIVATE-KEYS ********")
private_keys = {}
for i = 1, 32 do
	private_keys[i] = {}
	private_keys[i][1] = rand(32)
	private_keys[i][2] = rand(32)
	print(i, private_keys[i][1]:to_hex(), private_keys[i][2]:to_hex())
end

-- 4.	Hash each of these numbers 258 times, saving the results. The final sets of the 32 pairs of
-- 2 hashes each are the public key. (Note: Use a hash chain and this public key
-- becomes just 256 bits)
print("\n******** PUBLIC-KEYS ********")
ladders = {}
public_keys = {}
for i = 1, 32 do
	ladders[i] = {}
	for j = 1, 258 do
		if j == 1 then
			ladders[i][j] = {}
			ladders[i][j][1] = digest(private_keys[i][1])
			ladders[i][j][2] = digest(private_keys[i][2])
		else
			ladders[i][j] = {}
			ladders[i][j][1] = digest(ladders[i][j-1][1])
			ladders[i][j][2] = digest(ladders[i][j-1][2])
		end
		--print("Ladder "..i..":"..j, ladders[i][j][1]:to_hex(), ladders[i][j][2]:to_hex())
	end
	public_keys[i] = {}
	public_keys[i][1] = ladders[i][258][1]
	public_keys[i][2] = ladders[i][258][2]
	print(i, public_keys[i][1]:to_hex(), public_keys[i][2]:to_hex())
end

-- 5.	To create your signature, examine each chunk again. Let the value of this chunk
-- be "n" with the range [0, 255]. There are 2 256-bit numbers of the private key
-- associated with that chunk. Let "a" equal the first of these numbers hashed "n+1"
-- times. Let "b" equal the second of these numbers hashed 256-n times. Publish the
-- result "(a,b)". This pair is the signature for this 8-bit chunk.
print("\n******** SIGNATURE GENERATION ********")
signature = {}
for i = 1, 32 do
	signature[i] = {}
	n = chunks[i]:byte()+1
	a = ladders[i][n+1][1]
	b = ladders[i][257-n][2]
	signature[i][1] = a
	signature[i][2] = b
	print("Signature "..i..":", a:to_hex(), b:to_hex())
end

-- 6.	Collect up the "32" signatures from each chunk and this becomes a "32*2*(256/8) = 2kb"
-- signature! This is 4x smaller than the usual Lamport signature.

-- **************** VERIFYING ****************
print("\n******** SIGNATURE VERIFICATION ********")
num_valid = 0

-- 1.	Take the 256-bit hash of the document to verify
print("Message: ", message)
print("Message Hash: ", message_hash:to_hex())

-- 2.	Split the 256-bit hash of the document into 32 8-bit chunks
verify_chunks = {}
for i = 1, 32 do
	verify_chunks[i] = message_hash:sub(i,i)
	--print(verify_chunks[i]:to_hex())
end

-- 3.	For each chunk, let the chunk's value from the hash be "v", the signature pair
-- of numbers be "(a,b)" and the corresponding public key pair be "(Pa, Pb)".
for i = 1, 32 do
	v = verify_chunks[i]:from_hex():byte()+1
	v = string.byte(v)
	a = signature[i][1]
	b = signature[i][2]
	print("Signature: ", a:to_hex(), b:to_hex())
	Pa = public_keys[i][1]
	Pb = public_keys[i][2]

-- 4.	Hash "a" and count the iterations until it equals "Pa" or it has been hashed
-- 256 times. If it was hashed 256 times without reaching "Pa", the signature is
-- invalid. Save the number of iterations it took to reach "Pa" from "a" as "i_a".
	alive = true
	i_a = 0
	while alive == true do
		--print("**** Pa:",Pa:to_hex(),"a:",a:to_hex())
		--io.read()
		if a ==  Pa then
			alive = false
--			print("Match!")
--			print(i, i_a, a:to_hex(), Pa:to_hex())
			--io.read()
		else
			a = digest(a)
			i_a = i_a + 1
			if i_a > 257 then
				alive = false
			end
		end
	end

-- 5.	Repeat step (4) for "b", saving the number of iterations to reach
-- "Pb" from "b" as "i_b".
	alive = true
	i_b = 0
	while alive == true do
		if b == Pb then
			alive = false
--			print(i, i_b, b:to_hex(), Pb:to_hex())
		else
			b = digest(b)
			i_b =i_b + 1
			if i_b > 257 then
				alive = false
			end
		end
	end

-- 6.	If "256-i_a != i_b-1" or "256-i_a != v", this signature is invalid.
--	print(257-i_a, i_b-1)
	if 257-i_a ~= i_b-1 then --or 258-i_a ~= v then
		--print("Invalid Signature")
	else
		--print("Valid Signature")
		num_valid = num_valid + 1
	end

-- 7.	If there are more chunks, check the next chunk starting with step (3)
end

-- 8.	The signature is valid if all chunks are signed correctly.
if num_valid == 32 then
	print("Valid Signature")
else
	print("Invalid Signature", num_valid)
end

-- **************** DETAILS ****************

-- If "n" is the bits of the hash function and "k" is the bit size of each chunk.
-- *	"(n/8)*2*(n/k)" bytes is the size of the public key
-- *	"n/k * 2^k" is the number of hashes that must be computed to verify.
