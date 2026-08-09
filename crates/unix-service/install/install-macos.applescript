on run argv
	if (count of argv) is not 5 then error "invalid helper installer arguments"
	set installerPath to item 1 of argv
	set ownerUid to item 2 of argv
	set helperPath to item 3 of argv
	set wireguardGoPath to item 4 of argv
	set amneziawgGoPath to item 5 of argv
	set commandText to "/bin/sh " & quoted form of installerPath & " " & quoted form of ownerUid & " " & quoted form of helperPath & " " & quoted form of wireguardGoPath & " " & quoted form of amneziawgGoPath
	do shell script commandText with administrator privileges
end run
