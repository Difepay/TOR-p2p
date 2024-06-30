@echo off
setlocal enabledelayedexpansion

set count=5
for /L %%i in (1, 1, %count%) do (
	start cmd /k "title=!i! & py GUI.py
)