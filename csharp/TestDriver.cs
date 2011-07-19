//
// TestDriver
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

using System;
using HotFeet.Security.Cryptography;

namespace HotFeet.Testing {
	static class TestDriver {
		static void Main(string[] args) {
			IPasswordHash ph = new PasswordHash();
			string hash = ph.Hash(args[0]);

			Console.WriteLine(hash);
			Console.WriteLine(ph.Verify(args[0], hash));
		}
	}
}