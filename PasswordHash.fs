open System
open System.Text
open System.Text.RegularExpressions
open System.Security.Cryptography

//	type PasswordHash =

// (...BitLength % 8 == 0)
let hashAlgoName = "SHA512"		
let saltBitLen = 96
let hashBitLen = 512

(* base64 encoding *)
let base64Len (bitLen : int) = (bitLen + 5) / 6
let fromBase64 = Convert.FromBase64String
let toBase64 = Convert.ToBase64String

let base64Str (bytes : byte[]) =
	let appendZero count bs = Array.append bs (Array.zeroCreate count)
	let trim (str: string) = str.Substring(0, base64Len (bytes.Length * 8))
	match (bytes.Length) with
	| len when (len % 3 = 0) -> bytes |> toBase64
	| _ -> bytes |> appendZero 2 |> toBase64 |> trim

let base64Zero = 'A'
let base64Bytes (str : string) =
	match (str.Length * 6) with
	| len when (len % 8 = 0) -> Convert.FromBase64String(str)
	| len -> ((str + "AA") |> fromBase64).[0..((len >>> 3) - 1)]

(* hash output formatting *)
let formatHash salt hash = sprintf "$6$%s$%s" (base64Str salt) (base64Str hash) 

(* hash input parsing *)
let base64Group bitLen = sprintf "(.{%d})" (bitLen |> base64Len)
let hashPattern = sprintf "\$6\$%s\$%s" (base64Group saltBitLen) (base64Group hashBitLen) 
let hashRegex = new Regex(hashPattern)
let extractSaltAndHash s =
	let m = hashRegex.Match(s)
	let groupBytes idx = base64Bytes m.Groups.[idx + 1].Value
	if m.Success then (groupBytes 0, groupBytes 1) else failwith "Invalid hash format."	

(* Crypto primitives *)
let hashAlgo = HashAlgorithm.Create(hashAlgoName)
let hashBytes bytes =
	let _ = hashAlgo.TransformFinalBlock(bytes, 0, bytes.Length)
	let hash = hashAlgo.Hash
	hashAlgo.Clear()
	hash
	 
let randGen = RandomNumberGenerator.Create()
let random len =
	let mutable (bytes : byte[]) = Array.zeroCreate len
	randGen.GetBytes(bytes)
	bytes

(* salted password hashing *)
let hashSalted password salt =
	let (+) x y = Array.append x y
	hashBytes (salt + password + salt)

let bytes (s: string) = Encoding.UTF8.GetBytes(s)

(* public methods *)
let Hash password =
	let salt = random (saltBitLen >>> 3)
	let hash = hashSalted (bytes password) salt
	formatHash salt hash

let Verify password hash =
	let (storedSalt, storedHash) = extractSaltAndHash(hash)
	hashSalted (bytes password) storedSalt = storedHash
