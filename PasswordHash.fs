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
	(* utility *)
	let regex s = new Regex (s)
	let (=~) (r: Regex) (input: string) = r.Match input
	let (|Match|_|) (r : Regex) input =
		let m = (r =~ input) in
		if m.Success then Some (List.tail [for g in m.Groups -> g.Value]) else None

	(* input/ouput character encoding *)
	let enc = Encoding.UTF8
	let toBytes (s: string) = enc.GetBytes (s)
	let toString (bytes: byte[]) = enc.GetString (bytes)
	 
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
	let fromBase64 (s: string) = s |> toBytes |> transform (new FromBase64Transform())
	let toBase64 (bs: byte[]) = bs |> transform (new ToBase64Transform()) |> trim (base64Len (bs.Length * 8)) |> toString
	
	(* Crypto primitives *)
	let hashAlgoName = "SHA512"		
	let hashBitLen = 512 //(len % 8 = 0)
	let saltBitLen = 96 //(len % 8 = 0)

	let (hashAlgo, hashAlgoLock) = (HashAlgorithm.Create (hashAlgoName), new obj())
	let hashBytes bytes =
		let calcHash =
			let (_, hash) = (hashAlgo.TransformFinalBlock (bytes, 0, bytes.Length), hashAlgo.Hash)
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
	
	let saltPassword password salt =
		let (+) x y = Array.append x y
		salt + password + salt

	(* crypted password format *)
	let format = sprintf "$6$%s$%s"
	let cryptedPasswordRegex =
		let base64Group bitLen = sprintf "(.{%d})" (bitLen |> base64Len)
		let pattern = format (base64Group saltBitLen) (base64Group hashBitLen)
		regex (pattern.Replace ("$", @"\$")) 

	(* input / output *)
	let compose (salt, hash) = format (toBase64 salt) (toBase64 hash) 
	let decompose s =
		match s with
		| Match cryptedPasswordRegex [salt; hash] -> (toBytes salt, toBytes hash)
		| _ -> failwith "Invalid hash format."

	(* main methods *)
	let hash password salt = hashBytes (saltPassword password salt)
	let crypt password =
		let salt = randomBytes (saltBitLen >>> 3)
		(salt, hash password salt)
	
	let verify password (salt, hash) =
		hashBytes (saltPassword password salt) = hash
	
	let public Crypt password = compose (crypt password)
	let public Verify (password, cryptedPassword) =
		verify (toBytes password) (decompose cryptedPassword)
