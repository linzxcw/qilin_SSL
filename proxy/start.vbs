createobject("wscript.shell").run getfolder() & "\bootstrap.bat",vbhide
wscript.quit
function getfolder() 
getfolder=left(wscript.scriptfullname,instrrev(wscript.scriptfullname,"\")-1) 
end function 
