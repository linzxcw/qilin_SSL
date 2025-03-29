@echo off  

color 0a  

set base_dir=%~dp0  

%base_dir:~0,2%  

pushd %base_dir%  

proxy.exe http -p :33080 --nolog
popd  
