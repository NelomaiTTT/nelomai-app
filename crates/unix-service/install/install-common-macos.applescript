on run argv
    if (count of argv) is not 3 and (count of argv) is not 4 then error "invalid common installer arguments"
    set installerPath to item 1 of argv
    set ownerUid to item 2 of argv
    set sourceApp to item 3 of argv
    set commandText to "/bin/sh " & quoted form of installerPath & " " & quoted form of ownerUid & " " & quoted form of sourceApp
    if (count of argv) is 4 then set commandText to commandText & " " & quoted form of (item 4 of argv)
    do shell script commandText with administrator privileges
end run
