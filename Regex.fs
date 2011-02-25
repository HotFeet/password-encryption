//
// Regex
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
open System.Text.RegularExpressions

namespace HotFeet.FSharp
	module Regex =
		let regex s = new Regex (s)
		let (=~) (r: Regex) (input: string) = r.Match input
		let (|Match|_|) (r : Regex) input =
			let m = (r =~ input)
			if m.Success then Some (List.tail [for g in m.Groups -> g.Value]) else None