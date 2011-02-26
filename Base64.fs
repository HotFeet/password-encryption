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

namespace HotFeet.Text
	module Base64 =
		let fromBase64 = Convert.FromBase64String
		let toBase64 = Convert.ToBase64String
		
		let public toString (bs : byte[]) =
			let appendZero count bs = Array.append bs (Array.zeroCreate count)
			let trim (str: string) = str.Substring(0, base64Len (bs.Length * 8))
			match (bs.Length) with
			| len when (len % 3 = 0) -> bs |> toBase64
			| _ -> bs |> appendZero 2 |> toBase64 |> trim
		
		let public zero = 'A'
		let public ofString (s : string) =
			match (s.Length * 6) with
			| len when (len % 8 = 0) -> s |> fromBase64
			| len -> ((str + "AA") |> fromBase64).[0..((len >>> 3) - 1)]

		let public getStringLen (bitLen : int) = (bitLen + 5) / 6
