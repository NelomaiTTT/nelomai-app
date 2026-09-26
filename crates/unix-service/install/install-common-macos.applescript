on run argv
    if (count of argv) is not 2 and (count of argv) is not 3 then error "invalid common installer arguments"
    set installerPath to item 1 of argv
    set sourceApp to item 2 of argv
    set commandText to "/bin/sh " & quoted form of installerPath & " " & quoted form of sourceApp
    if (count of argv) is 3 then set commandText to commandText & " " & quoted form of (item 3 of argv)
    do shell script commandText with administrator privileges
end run
