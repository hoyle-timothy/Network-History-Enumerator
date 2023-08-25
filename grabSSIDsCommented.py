
import winreg #imports the winreg python module which exposes the Windows API to Python

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
    
    ba = bytearray(rawDate) #take the bytestring 'rawDate' and converts it to bytearray because we need to reverse it and bytearrays are mutable, bytestrings are not
    ba.reverse() #change the bytearray from little endian to big endian
    hex = ba.hex() #converts the big endian bytearray to hexadecimal
    n = 0
    hexValue = [] 
    decValue = []
    for i in range(0,len(hex),4): #this chops up the hexadecimal into 2 byte chunks so we can extract different portions of the date
        
        #below will split the hex into 4 character chunks (2-bytes each). Each two bytes represents a different portion of a date (e.g. month, day-of-week etc) 
        #then it assigns each 2-byte chunk to a different index in the 'hexValue' array
        hexValue.append(hex[i:i+4]) 
        decValue.append(int(hexValue[n],16)) #converts each 2-byte hex chunk into it's equivelant decimal value and saves that value to the 'decValue' array
        n = n + 1 

    #calls the 'translateMonth' function, hands it the correct 'decValue' index that represents the month portion of the date, and plugs the result into the 'month' variable
    month = translateMonth(decValue[6])
    
    #calls the 'translateDOW' function and hands it the correct 'decValue' index that represents the day-of-week portion of the date, then plugs the returning result into the 'dow' variable
    dow = translateDOW(decValue[5]) 

    #this takes all the different formatted pieces of the date, and arranges them in a human-readable way. Then it plugs that nice presentation into the 'formattedDate' variable
    formattedDate = (f'{dow}, {month} {decValue[4]}, {decValue[7]} @ {decValue[3]}:{decValue[2]}:{decValue[1]}') #creates a nicely formatted date and plugs it into a variable
    return formattedDate

def dateSubKeyEnum(mainKey,profileGUID):
    '''
    this function takes the 'mainKey' and 'profileGUID' variables as arguments, and uses those to open the windows key that matches the value of the 'profileGUID'
    argument, and extract the fields/values that we wish to see from within. This function specifically gives us the 'Network security level', the 'First Connected' date, 
    the 'Last time connected' date, the 'Domain name',  and 'Type of connection' fields underneath the 'profileGUID' value that we fed it
    '''
    
    #below contains the string of the subkey that we wish to open. We will combine this with the 'profileGUID'  argument that we fed this function
    dateSubKeyString = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\"
    
    try: #begin error catching
        count = 0
        while 1: #meaning 'while true' as in, 'While there are still key/value pairs to enumerate'
        
            #this opens the subkey whose values within we wish to enumerate, and assigns this opened key to the variable 'tempSubKey'
            #possible arguments for this method are: winreg.OpenKey(<alreadyOpenedKey>,<subKey>,<reservedArgument>,<accessLevel>)
            tempSubKey = winreg.OpenKey(mainKey,dateSubKeyString+profileGUID)
            
            #for each row under the opened 'tempSubKey', this assigns the 'name', 'value' and 'type' key/values to variables under the same name
            name, value, type = winreg.EnumValue(tempSubKey, count)
            
            
            if name in ("Category","DateCreated","DateLastConnected","Managed","NameType"): #this ensures we only grab data from the key/value pairs that we wish to see
                if name == "Category": #this will grab the value for the key 'Category' and translate it to the actual meaning
                    match value:
                        case 0:
                            cat = "public network"
                        case 1:
                            cat = "private network"
                        case 2:
                            cat = "domain network"
                        case _:
                            cat = "network type unknown"
                    count = count + 1 #increase the count forcing the code to iterate the next row
                    
                elif name == "Managed": #this will grab the value for the key 'Managed' and translate it to it's actual meaning
                    match value:
                        case 0:
                            mngd = "No (no domain membership)"
                        case 1:
                            mngd = "domain member"
                        case _:
                            mngd = "domain membership unknown"
                    count = count + 1 #increase the count forcing the code to iterate the next row
                    
                elif name == "DateCreated": #this will grab the 'DateCreated' key/value pair and call the 'dateTranslator' function using the key's associated value as an argument
                    originated = dateTranslator(value) 
                    count = count + 1 #increase the count forcing the code to iterate the next row
                    
                elif name == "DateLastConnected": #this will grab the 'DateLastConnected' key/value pair and call the 'dateTranslator' function using the key's associated value as an argument
                    lastConnected = dateTranslator(value)
                    count = count + 1 #increase the count forcing the code to iterate the next row
                    
                elif name == "NameType": #this will grab the value for the key 'Wired Network' and translate it to it's actual meaning
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
                    count = count + 1 #increase the count forcing the code to iterate the next row
            else: #if no matches are found, run what's underneath this causes the 'while 1:' (while true) loop to turn 'false' forcing the while loop to exit
                count += 1  #iterate to the next row, which will not exist, causing the 'while 1:' (while true) loop to become 'false', forcing the while loop to exit.
                         
    except WindowsError as error: #catches exceptions to the 'try' statement at the top
        pass #simply passes
    return cat, mngd, originated, lastConnected, ntype #returns the variables we wish to obtain from this function

def profileEnum():
    '''
    Main function of this script. Opens the first Windows key to enumerate the 'Gateway mac', 'Domain name', 'Network name', and 'Profile ID'.
    It also calls the 'dateSubKeyEnum' function to enumerate and enrich each network with additional fields
    '''
    try:
        #line below opens the HKEY_LOCAL_MACHINE main key and assigns that handle to the variable 'mainKey'
        mainKey = winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) #winreg.ConnectRegistry(<computerName>,<key>) if <computerName> = 'None', local machine is used
        
        #line below takes the 'mainKey' handle, and adds the subkey to it, creating a larger, more specific registry key handle
        subKey = winreg.OpenKey(mainKey,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\") #winreg.OpenKey(<key>,<subKey>)
        
        #line below creates a string with the value of the desired subkey. We need this subkey in a string format to use in the 'winreg.OpenKey' function
        subKeyString = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\"
        counter = 0
        
        while 1: #when there are no remaining network profiles to enumerate, this resolves to 'false' and exits the while loop - this causes the 'try' statement above to fail
            subKeyGuid = winreg.EnumKey(subKey,counter) #winreg.EnumKey(<key>, <index>)
            try:
                count = 0
                while 1: #meaning 'while true' as in, 'While there are still key/value pairs to enumerate'
                    tempSubKey = winreg.OpenKey(mainKey,subKeyString+subKeyGuid) #creates a new handle using the subKey and the current GUID, new handle is named 'tempSubKey'
                    name, value, type = winreg.EnumValue(tempSubKey, count)  # grabs the 'name', 'value' and 'type' fields from the current row
                    if name in ("ProfileGuid","DnsSuffix","FirstNetwork","DefaultGatewayMac"): #tests to see if the 'name' field contains one of the values in this list
                        if name == "DefaultGatewayMac" and value != None: #tests to see if the 'name' value in the current row is 'DefaultGatewayMac' and it's  associated 'value' field is not empty
                            hexmac = value.hex().upper() #takes the raw binary MAC, changes it to hexadecimal and forces it all into uppercase format
                            mac = "-".join(hexmac[i:i+2] for i in range(0,12,2)) #splits up the hexadecimal into two character chunks and places a - in between each chunk
                            count = count + 1 #increment the counter, which will cause the 'while' loop to open the next row
                            continue #exit the 'if' statement
                        if name == "DefaultGatewayMac" and value == None: #tests to see if the 'name' value in the current row is 'DefaultGatewayMac' and if it's associated 'value' is empty
                            mac = "No Gateway MAC provided" #if the associated 'value' field is empty, place this string in the 'mac' field
                            count = count + 1 #increment the counter, which will cause the 'while' loop to open the next row
                            continue #exit the 'if' statement
                        elif name == "DnsSuffix": #tests to see if the 'name' value in the current row is 'DnsSuffix'. If it is, execute the statements below
                            dns = value #plug the value contained in the variable 'value' in this row into a new variable called 'dns'
                            count = count +1 #increment the counter, which will cause the 'while' loop to open the next row
                            continue #exit the 'if' statement
                        elif name == "FirstNetwork": #tests to see if the 'name' value in the current row is 'FirstNetwork'. If it is, execute then it will statements below
                            nname = value #plug the value contained in the variable 'value' in this row into a new variable called 'nname'
                            count = count + 1 #increment the counter, which will cause the 'while' loop to open the next row
                            continue #exit the 'if' statement
                        elif name == "ProfileGuid": #tests to see if the 'name' value in the current row is 'ProfileGuid'. If it is, execute then it will statements below
                            guid = value #plug the value contained in the variable 'value' in this row into a new variable called 'guid'
                        count = count + 1 #increment the counter, which will cause the 'while' loop to open the next row
                    else: #if the value in the 'name' container (variable) does not match the list above, then execute the statements below
                        count = count +1 #increment the counter, which will cause the 'while' loop to open the next row
                        continue #exit the 'if' statement
            except WindowsError as err: #if the 'while 1:' loop becomes false, then this 'except' statement will be activated, and the statements below will execute
            
                #calls the 'dateSubKeyEnum' function, and plugs it's return variables into 'cat', 'mnged', 'originated', 'lastConnected' and 'ntype'
                #this passes the 'mainKey' handle and the current value of 'guid' as arguments when calling the 'dateSubKeyEnum' function
                cat, mnged, originated, lastConnected, ntype = dateSubKeyEnum(mainKey,guid) 
                
                #print all of our relevant findings from the current network profile guid
                print(f'Network name: {nname}\nDomain name: {dns}\nType of connection: {ntype}\nFirst connected: {originated}\nLast time connected: {lastConnected}\nGateway MAC: {mac}\nNetwork security level: {cat}\nProfile ID (GUID): {guid}\n\n')
                counter += 1 #adds to the 'counter' variable which applies to the outer 'try'. This will move us to the next GUID (network) listed in the registry
    except WindowsError as error: #once there are not more profiles to enumerate, the 'while 1:' loop will become false and this 'except' statement will be activated, causing the code below it to run
        print(f'No more network profiles to enumerate') 

profileEnum() #calls the main function 'profileEnum' to start the whole program