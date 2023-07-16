
#imports the 'winreg' module
import winreg 

#this connects to HKLM using the 'ConnectRegistry' method and places that connection inside the mainKey variable 
mainKey = winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE)#winreg.ConnectRegistry(<remoteHostName>,<registryKey>)

#this uses the previous registry connection to open an actual registry key and place that open key into variable 'subKey'
subKey = winreg.OpenKey(mainKey,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\")#winreg.OpenKey(<alreadyOpenedKey>,<subKey>,<reservedArgument>,<accessLevel>)

#plug this string into the 'subKeyString' variable. This will be concatenated later with other variables to open different subkeys
subKeyString = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\" 

try:
    counter = 0
    #'while' loop that loops through each network profile GUID
    while 1:
         #grabs the GUID at the specified position
        subKeyGuid = winreg.EnumKey(subKey,counter)#subKeyGuid = winreg.EnumKey(subKey,0)
        try:
            count = 0
            #inner 'while' loop that enumerates each row of the current profile GUID (or current 'subKeyGUID')
            while 1:
                #opens the key by combining the 'mainKey', 'subKeyString' and 'subKeyGuid'
                tempSubKey = winreg.OpenKey(mainKey,subKeyString+subKeyGuid)#tempSubKey = winreg.OpenKey(mainKey,subKeyString+subKeyGuid)
                #grabs the 3 variables for each row, the 'name', 'value', and 'type'
                name, value, type = winreg.EnumValue(tempSubKey, count) #EnumValue(<alreadyOpenKey>,<indexOfValueToRetrieve>)
                #the line below ensures that we only grab the 'name', 'value' and 'type' of the rows that we wish to see
                if name in ("ProfileGuid","DnsSuffix","FirstNetwork","DefaultGatewayMac"): 
                    #the 'if' statement below identifies if we have a bytestring MAC and if so, will convert the bytestring MAC to a hexadecimal MAC
                    if name == "DefaultGatewayMac" and value != None:
                        hexmac = value.hex().upper() #forces all letters to be uppercase for readability
                        mac = "-".join(hexmac[i:i+2] for i in range(0,12,2)) #places a '-' between every hexdecimal value
                        print(f'Gateway MAC: {mac}\n') #prints the string "DefaultGatewayMac" and the newly formatted MAC address
                        count = count + 1
                        continue
                    #the 'if' statement below identifies if the Gateway MAC for this GUID does NOT have a MAC value, and prints the appropriate message
                    if name == "DefaultGatewayMac" and value == None:
                        print(f'{name}: No default gateway MAC for this network\n')
                        count = count + 1
                        continue
                    #the 'else if' statement below takes the name "DnsSuffix" and changes it to the more understandable "Domain Name" field name
                    elif name == "DnsSuffix":
                        print(f'Domain Name: {value}')
                        count = count +1
                        continue
                    #the 'else if' statement below takes the name "FirstNetwork" and changes it to the more understandable "Network name" field name
                    elif name == "FirstNetwork":
                        print(f'Network name: {value}')
                        count = count + 1
                        continue
                    #finally, this takes the name "ProfileGUID" and changes it to the more understandable "Profile ID" field 
                    print(f'Profile ID (GUID): {value}')
                    count = count + 1
                else:
                    count = count +1
                    continue
        #'except' for inner 'try'
        except WindowsError as err:
            print('\n')
            counter += 1
#'except' for outer 'try'
except WindowsError as error:
    print(f'No more profiles to enumerate \nError code is: {error}')
