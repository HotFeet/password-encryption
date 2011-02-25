//
// Base64
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
open System.Security.Cryptography

namespace HotFeet.Text
	module Base64 =
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
		
		let public GetStringLen (bitLen : int) = (bitLen + 5) / 6
		let public ToString (s: string) = s |> toBytes |> transform (new FromBase64Transform())
		let public FromString (bs: byte[]) = bs |> transform (new ToBase64Transform()) |> trim (GetByteLen (bs.Length * 8)) |> toString
