netsh wlan add profile filename=c:\temp\Wi-Fi-MWH.xml
netsh wlan connect ssid="MWH" name="MWH"
netsh wlan set profileparameter name="MWH" autoswitch=Yes
