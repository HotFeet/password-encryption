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

using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace HotFeet.Security.Cryptography {
	public class PasswordHash : IPasswordHash {
		// condition: (...BitLength % 8 == 0)		
		static readonly int saltBitLength = 96;
		static readonly int hashBitLength = 512;

		static readonly string hashFormat = "$6${0}${1}";
		static readonly string base64Group = "(.{{{0}}})";
		static readonly string hashPattern = String.Format(
			hashFormat.Replace("$", @"\$"),
			String.Format(base64Group, toBase64Length(saltBitLength)),
			String.Format(base64Group, toBase64Length(hashBitLength))
		);
		static Regex hashRegex = new Regex(hashPattern);
		
		static readonly char zeroChar = Convert.ToBase64String(new byte[3] {0, 0, 0})[0];

		static int toBase64Length(int bitLength) {
			return (bitLength + 5) / 6;
		}
		
		static byte[] getBytes(string s) {
			return Encoding.UTF8.GetBytes(s);
		}

		HashAlgorithm hashAlg = HashAlgorithm.Create("SHA512");
		RandomNumberGenerator random = RandomNumberGenerator.Create();
		object hashAlgoLock = new object();
		object entropyLock = new object();
		
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

		public string Hash(string password) {
			byte[] salt = new byte[saltBitLength >> 3];
			lock(entropyLock) {
				random.GetBytes(salt);
			}
				
			byte[] pass = getBytes(password);
			byte[] hash = Hash(pass, salt);
				
			return String.Format(
				hashFormat,
				ToFilledBase64(salt),
				ToFilledBase64(hash)
			);
		}
		
		byte[] Hash(byte[] password, byte[] salt) {
			byte[] plain = new byte[password.Length + 2 * salt.Length];
			Buffer.BlockCopy(salt, 0, plain, 0, salt.Length);
			Buffer.BlockCopy(password, 0, plain, salt.Length, password.Length);
			Buffer.BlockCopy(salt, 0, plain, salt.Length + password.Length, salt.Length);

			//HashAlgorithm is stateful 
			byte[] hash;
			lock(hashAlgoLock) {
				hashAlg.TransformFinalBlock(plain, 0, plain.Length);
				hash = hashAlg.Hash;

				hashAlg.Clear();
			}
			return hash;
		}
		
		public bool Verify(string password, string hash) {
			Match m = hashRegex.Match(hash);
			if(!m.Success)
				throw new ArgumentException("codedHash");

			byte[] storedSalt = FromFilledBase64(m.Groups[1].Value);
			byte[] storedHash = FromFilledBase64(m.Groups[2].Value);

			byte[] freshHash = Hash(getBytes(password), storedSalt);
			for(int i = 0; i < freshHash.Length; i++) {
				if(freshHash[i] != storedHash[i])
					return false;
			}
			
			return true;
		}
	}
}