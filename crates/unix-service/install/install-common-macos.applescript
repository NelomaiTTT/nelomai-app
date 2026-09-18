on run argv
    if (count of argv) is not 2 then error "invalid common installer arguments"
    set installerPath to item 1 of argv
    set sourceApp to item 2 of argv
    set commandText to "/bin/sh " & quoted form of installerPath & " " & quoted form of sourceApp
    do shell script commandText with administrator privileges
end run
