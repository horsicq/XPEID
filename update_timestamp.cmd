@echo off
echo date=%DATE%>peid\info.ini
git add peid\info.ini
git commit -m "Updated timestamp for info.ini" >/dev/null 2>&1 && git push
echo "Date updated in peid/info.ini to the current date"
pause