
import winreg 

def dateTranslator(rawDate):
    '''
    this function takes a windows bytestring that contains a date, converts it to a bytearray, reverses it from little endian to big endian, 
    then translates the big endian bytearray to hexadecimal, then translates the hexadecimal value to decimal, then wherever needed, it
    translates that decimal to it's human readable date equivelent    
    '''
    def translateMonth(rawMonth): 
        '''takes the 'rawMonth' decimal value and translates it to month of the year (e.g. decimal '10' stands for 'October')'''
        month_dict = {1:'January', 2:'February', 3:'March', 4:'April', 5:'May', 6:'June', 7:'July', 8:'August', 9:'September', 10:'October', 11:'November', 12:'December'}
        monthTranslation = month_dict.get(rawMonth)
        return monthTranslation

    def translateDOW(rawDOW): 
        '''takes the 'rawDOW' (raw Day of Week) decimal value and translates into the day of the week (e.g. decimal '3' stands for 'Wednesday')'''
        dow_dict = {0:'Sunday', 1:'Monday', 2:'Tuesday', 3:'Wednesday', 4:'Thursday', 5:'Friday', 6:'Saturday'}
        dowTranslation = dow_dict.get(rawDOW) 
        return dowTranslation
    
    ba = bytearray(rawDate)
    ba.reverse() 
    hex = ba.hex() 
    n = 0
    hexValue = [] 
    decValue = []
    for i in range(0,len(hex),4): 
        hexValue.append(hex[i:i+4]) 
        decValue.append(int(hexValue[n],16)) 
        n = n + 1 

    month = translateMonth(decValue[6])
    dow = translateDOW(decValue[5]) 

    formattedDate = (f'{dow}, {month} {decValue[4]}, {decValue[7]} @ {decValue[3]}:{decValue[2]}:{decValue[1]}') 
    return formattedDate

def dateSubKeyEnum(mainKey,profileGUID):
    '''
    this function takes the 'mainKey' and 'profileGUID' variables as arguments, and uses those to open the windows key that matches the value of the 'profileGUID'
    argument, and extract the fields/values that we wish to see from within. This function specifically gives us the 'Network security level', the 'First Connected' date, 
    the 'Last time connected' date, the 'Domain name',  and 'Type of connection' fields underneath the 'profileGUID' value that we fed it
    '''
    dateSubKeyString = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\"
    try: 
        count = 0
        while 1: 
        
            tempSubKey = winreg.OpenKey(mainKey,dateSubKeyString+profileGUID)
            name, value, type = winreg.EnumValue(tempSubKey, count)
            
            if name in ("Category","DateCreated","DateLastConnected","Managed","NameType"): 
                if name == "Category": 
                    match value:
                        case 0:
                            cat = "public network"
                        case 1:
                            cat = "private network"
                        case 2:
                            cat = "domain network"
                        case _:
                            cat = "network type unknown"
                    count = count + 1 
                    
                elif name == "Managed": 
                    match value:
                        case 0:
                            mngd = "No (no domain membership)"
                        case 1:
                            mngd = "domain member"
                        case _:
                            mngd = "domain membership unknown"
                    count = count + 1 
                    
                elif name == "DateCreated":
                    originated = dateTranslator(value) 
                    count = count + 1 
                    
                elif name == "DateLastConnected": 
                    lastConnected = dateTranslator(value)
                    count = count + 1 
                    
                elif name == "NameType": 
                    match value:
                        case 6:
                            ntype = "Wired Network" 
                        case 23:
                            ntype = "VPN"
                        case 71:
                            ntype = "Wireless"
                        case 243:
                            ntype = "Mobile Broadband"
                        case _:
                            ntype = "Connection type unknown"
                    count = count + 1 
            else: 
                count += 1  
                         
    except WindowsError as error: 
        pass 
    return cat, mngd, originated, lastConnected, ntype 

def profileEnum():
    '''
    Main function of this script. Opens the first Windows key to enumerate the 'Gateway mac', 'Domain name', 'Network name', and 'Profile ID'.
    It also calls the 'dateSubKeyEnum' function to enumerate and enrich each network with additional fields
    '''
    try:
        mainKey = winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) 
        subKey = winreg.OpenKey(mainKey,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\") 
        
        subKeyString = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\"
        counter = 0
        
        while 1: 
            subKeyGuid = winreg.EnumKey(subKey,counter) 
            try:
                count = 0
                while 1: 
                    tempSubKey = winreg.OpenKey(mainKey,subKeyString+subKeyGuid) 
                    name, value, type = winreg.EnumValue(tempSubKey, count)  
                    if name in ("ProfileGuid","DnsSuffix","FirstNetwork","DefaultGatewayMac"): 
                        if name == "DefaultGatewayMac" and value != None: #
                            hexmac = value.hex().upper() 
                            mac = "-".join(hexmac[i:i+2] for i in range(0,12,2)) 
                            count = count + 1 
                            continue 
                        if name == "DefaultGatewayMac" and value == None: 
                            mac = "No Gateway MAC provided" 
                            count = count + 1 
                            continue 
                        elif name == "DnsSuffix": 
                            dns = value 
                            count = count +1 
                            continue 
                        elif name == "FirstNetwork": 
                            nname = value 
                            count = count + 1 
                            continue 
                        elif name == "ProfileGuid": 
                            guid = value 
                        count = count + 1 
                    else: 
                        count = count +1 
                        continue 
            except WindowsError as err: 
            
                cat, mnged, originated, lastConnected, ntype = dateSubKeyEnum(mainKey,guid) 
                print(f'Network name: {nname}\nDomain name: {dns}\nType of connection: {ntype}\nFirst connected: {originated}\nLast time connected: {lastConnected}\nGateway MAC: {mac}\nNetwork security level: {cat}\nProfile ID (GUID): {guid}\n\n')
                counter += 1 #
    except WindowsError as error: 
        print(f'No more network profiles to enumerate') 

profileEnum() 