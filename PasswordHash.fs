//
// PasswordHash
//
// Authors:
//    Juraj Skripsky <js@hotfeet.ch>
//
// Copyright 2011 HotFeet GmbH (http://www.hotfeet.ch)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

open System
open System.Text
open System.Text.RegularExpressions
open System.Security.Cryptography

module public PasswordHash =
	(* hash format *)
	let baseFormat = sprintf "$6$%s$%s"
	let hashAlgoName = "SHA512"		
	let hashBitLen = 512 //(len % 8 = 0)
	let saltBitLen = 96 //(len % 8 = 0)

	(* input/ouput character encoding *)
	let enc = Encoding.UTF8
	let bytes (s: string) = enc.GetBytes (s)
	let str (bytes: byte[]) = enc.GetString (bytes)
	 
	(* base64 encoding *)
	let trim len (bs: byte[]) = bs.[0..(len - 1)]
	let pad value len (bs : byte[]) =
		match len with
		| 0 -> bs
		| _ -> Array.append bs (Array.create len value)

	let transform (ct : ICryptoTransform) (bs : byte[]) =
		let (ibs, obs) = (ct.InputBlockSize, ct.OutputBlockSize)
		let res = Array.zeroCreate ((bs.Length * obs + ibs - 1) / ibs)
		let mutable (srcIdx, dstIdx) = (0, 0)
		while bs.Length - srcIdx > ibs do
			let _ = ct.TransformBlock(bs, srcIdx, ibs, res, dstIdx)
			srcIdx <- srcIdx + ibs
			dstIdx <- dstIdx + obs
		Array.append (trim dstIdx res) (ct.TransformFinalBlock(bs, srcIdx, bs.Length - srcIdx))
	
	let base64Len (bitLen : int) = (bitLen + 5) / 6
	let fromBase64 (s: string) = s |> bytes |> transform (new FromBase64Transform())
	let toBase64 (bs: byte[]) = bs |> transform (new ToBase64Transform()) |> trim (base64Len (bs.Length * 8)) |> str
	
	(* hash output formatting *)
	let formatHash (salt, hash) = baseFormat (toBase64 salt) (toBase64 hash) 
	
	(* hash input parsing *)
	let hashRegex =
		let base64Group bitLen = sprintf "(.{%d})" (bitLen |> base64Len)
		let pattern = baseFormat (base64Group saltBitLen) (base64Group hashBitLen)
		new Regex(pattern.Replace("$", @"\$")) 

	let extractSaltAndHash s =
		let m = hashRegex.Match(s)
		let groupBytes idx = fromBase64 m.Groups.[idx + 1].Value
		if m.Success then (groupBytes 0, groupBytes 1) else failwith "Invalid hash format."	
	
	(* Crypto primitives *)
	let (hashAlgo, hashAlgoLock) = (HashAlgorithm.Create (hashAlgoName), new obj())
	let hashBytes bytes =
		let calcHash =
			let _ = hashAlgo.TransformFinalBlock (bytes, 0, bytes.Length)
			let hash = hashAlgo.Hash
			hashAlgo.Clear()
			hash
		lock hashAlgoLock (fun _ -> calcHash)
		 
	let (randGen, randGenLock) = (RandomNumberGenerator.Create (), new obj())
	let random (bytes : byte[]) =
		lock randGenLock (fun _ -> randGen.GetBytes (bytes))
		bytes

	let randomBytes len =
		let mutable (bs : byte[]) = Array.zeroCreate len
		random bs
	
	(* salted password hashing *)
	let hashSalted password salt =
		let (+) x y = Array.append x y
		hashBytes (salt + (bytes password) + salt)
	
	(* main methods *)
	let public hash password =
		let salt = randomBytes (saltBitLen >>> 3)
		let hash = hashSalted password salt
		formatHash (salt, hash)
	
	let public verify password hash =
		let (storedSalt, storedHash) = extractSaltAndHash hash
		(hashSalted password storedSalt) = storedHash
