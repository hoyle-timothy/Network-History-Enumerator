
import winreg 

mainKey = winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE)

subKey = winreg.OpenKey(mainKey,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\")

subKeyString = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\" 

try:
    counter = 0
    while 1:
        subKeyGuid = winreg.EnumKey(subKey,counter)
        try:
            count = 0
            while 1:
                tempSubKey = winreg.OpenKey(mainKey,subKeyString+subKeyGuid)
                name, value, type = winreg.EnumValue(tempSubKey, count) 
                if name in ("ProfileGuid","DnsSuffix","FirstNetwork","DefaultGatewayMac"): 
                    if name == "DefaultGatewayMac" and value != None:
                        hexmac = value.hex().upper() 
                        mac = "-".join(hexmac[i:i+2] for i in range(0,12,2)) 
                        print(f'Gateway MAC: {mac}\n')
                        count = count + 1
                        continue
                    if name == "DefaultGatewayMac" and value == None:
                        print(f'{name}: No default gateway MAC for this network\n')
                        count = count + 1
                        continue
                    elif name == "DnsSuffix":
                        print(f'Domain Name: {value}')
                        count = count +1
                        continue
                    elif name == "FirstNetwork":
                        print(f'Network name: {value}')
                        count = count + 1
                        continue
                    print(f'Profile ID (GUID): {value}')
                    count = count + 1
                else:
                    count = count +1
                    continue
        except WindowsError as err:
            print('\n')
            counter += 1
except WindowsError as error:
    print(f'No more profiles to enumerate \nError code is: {error}')
