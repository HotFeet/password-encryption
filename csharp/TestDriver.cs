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
			string password = args[0];

			WriteTestHash(new IdentityPasswordHash(), password);
			WriteTestHash(new SHA512PasswordHash(), password);
		}
		
		static void WriteTestHash(IPasswordHash ph, string password) {
			Console.WriteLine("Class:    {0}", ph.GetType());

			string hash = ph.Hash(password);
			Console.WriteLine("Password: {0}", password);
			Console.WriteLine("Hash:     {0}", hash);

			Console.WriteLine("Match:    {0}", ph.Verify(password, hash));
			Console.WriteLine();
		}
	}
}