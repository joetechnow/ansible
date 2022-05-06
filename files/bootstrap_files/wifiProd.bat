netsh wlan add profile filename=c:\temp\Wi-Fi-AzureProduction.xml
netsh wlan connect ssid="AzureProduction" name="AzureProduction"
netsh wlan set profileparameter name="AzureProduction" autoswitch=Yes