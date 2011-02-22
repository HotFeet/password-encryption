open System
open System.Text
open System.Text.RegularExpressions
open System.Security.Cryptography

//	type PasswordHash =

// (...BitLength % 8 == 0)		
let saltBitLen = 96
let hashBitLen = 512

let base64Len bitLen = (bitLen + 5) / 6
let bytes (s: string) = Encoding.UTF8.GetBytes(s)

let base64Str (bytes: byte[]) = "Test"
let base64Bytes (s: string) = [|0uy|]

let formatHash salt hash = sprintf "$6$%s$%s" (base64Str salt) (base64Str hash) 
let base64Group bitLen = sprintf "(.{%d})" (bitLen |> base64Len)
let hashPattern = sprintf "\$6\$%s\$%s" (base64Group saltBitLen) (base64Group hashBitLen) 
let hashRegex = new Regex(hashPattern)
		
let base64Zero = Convert.ToBase64String([|0uy; 0uy; 0uy|]).[0]

let hashAlgo = HashAlgorithm.Create("SHA512")
let hashBytes bytes =
	hashAlg.TransformFinalBlock(bytes, 0, bytes.Length)
	let hash = hashAlg.Hash
	hashAlg.Clear()
	hash
	 
let randGen = RandomNumberGenerator.Create()
let random len =
	let bytes = byte[len]
	rangGen.GetBytes(bytes)
	bytes

(*
	static string ToFilledBase64(byte[] bytes) {
		int mod = bytes.Length % 3;
		if(mod == 0)
			return Convert.ToBase64String(bytes);
	
		int strLen = (bytes.Length * 8 + 5) / 6;
		int excess = 3 - mod;
		byte[] paddedBytes = new byte[bytes.Length + excess];
		Buffer.BlockCopy(bytes, 0, paddedBytes, 0, bytes.Length);
		for(int i = 0; i < excess; i++)
			paddedBytes[bytes.Length + i] = 0;
	 
		return Convert.ToBase64String(paddedBytes).Substring(0, strLen);
	}
	
	static byte[] FromFilledBase64(string s) {
		int filledBits = s.Length * 6;
		if(filledBits % 8 == 0)
			return Convert.FromBase64String(s);
	
		//FIXME: don't hardcode the count
		s += new String(zeroChar, 2);
		byte[] bytesExcessive = Convert.FromBase64String(s);
		byte[] bytes = new byte[filledBits >> 3];
		Array.Copy(bytesExcessive, bytes, bytes.Length);
	
		return bytes;
	}
*)

let Hash password =
	let salt = random (saltBitLength >> 3)
	let hash = HashSalted (bytes password) salt
	formatHash salt hash

let HashSalted password salt =
	let (+) x y = Array.append x y 
	hashBytes (salt + password + salt)
		
let Verify password hash =
	let m = hashRegex.Match(hash)
	if !m.Success
		throw new ArgumentException("codedHash");

	let grp idx = m.Groups.[idx + 1]
	let storedSalt = base64Bytes (grp 0)
	let storedHash = base64Bytes (grp 1)

	(HashSalted (getBytes password) storedSalt) == storedHash
