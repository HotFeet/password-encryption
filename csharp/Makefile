all:
	gmcs IPasswordHash.cs SHA512PasswordHash.cs IdentityPasswordHash.cs /debug /t:library /out:HotFeet.PasswordHash.dll
	gmcs TestDriver.cs /debug /t:exe /out:TestDriver.exe /r:HotFeet.PasswordHash.dll 
