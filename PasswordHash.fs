open System
open System.Text
open System.Text.RegularExpressions
open System.Security.Cryptography

//	type PasswordHash =

// (...BitLength % 8 == 0)		
let saltBitLen = 96
let hashBitLen = 512

let base64Len (bitLen : int) = (bitLen + 5) / 6
let bytes (s: string) = Encoding.UTF8.GetBytes(s)

let fromBase64 = Convert.FromBase64String
let toBase64 = Convert.ToBase64String

let base64Str (bytes : byte[]) =
	let extend bytes = Array.append bytes (Array.zeroCreate 2)
	let trim (str: string) = str.Substring(0, bytes.Length)
	match (bytes.Length) with
	| len when (len % 3 = 0) -> bytes |> toBase64
	| _ -> bytes |> extend |> toBase64 |> trim

let base64Bytes (str : string) =
	match (str.Length * 6) with
	| len when (len % 8 = 0) -> Convert.FromBase64String(str)
	| len -> Convert.FromBase64String(str + "AA").[0..(len >>> 3)]

let formatHash salt hash = sprintf "$6$%s$%s" (base64Str salt) (base64Str hash) 
let base64Group bitLen = sprintf "(.{%d})" (bitLen |> base64Len)
let hashPattern = sprintf "\$6\$%s\$%s" (base64Group saltBitLen) (base64Group hashBitLen) 
let hashRegex = new Regex(hashPattern)
		
let base64Zero = 'A'

let hashAlgo = HashAlgorithm.Create("SHA512")
let hashBytes bytes =
	let _ = hashAlgo.TransformFinalBlock(bytes, 0, bytes.Length)
	let hash = hashAlgo.Hash
	hashAlgo.Clear()
	hash
	 
let HashSalted password salt =
	let (+) x y = Array.append x y
	hashBytes (salt + password + salt)

let randGen = RandomNumberGenerator.Create()
let random len =
	let (bytes : byte[]) = Array.zeroCreate len
	randGen.GetBytes(bytes)
	bytes

let Hash password =
	let salt = random (saltBitLen >>> 3)
	let hash = HashSalted (bytes password) salt
	formatHash salt hash

let Verify password hash =
	let m = hashRegex.Match(hash)
	if not m.Success then failwith "Invalid hash format."

	let grp idx = m.Groups.[idx + 1].Value
	let storedSalt = base64Bytes (grp 0)
	let storedHash = base64Bytes (grp 1)

	(HashSalted (bytes password) storedSalt) = storedHash
