function Convert-HexStringToByteArray 
{
    ################################################################
    #.Synopsis
    # Convert a string of hex data into a System.Byte[] array. An
    # array is always returned, even if it contains only one byte.
    #.Parameter String
    # A string containing hex data in any of a variety of formats,
    # including strings like the following, with or without extra
    # tabs, spaces, quotes or other non-hex characters:
    # 0x41,0x42,0x43,0x44
    # \x41\x42\x43\x44
    # 41-42-43-44
    # 41424344
    # The string can be piped into the function too.
    ################################################################
    [CmdletBinding()]
    Param ( [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [String] $String )
     
    #Clean out whitespaces and any other non-hex crud.
    $String = $String.ToLower() -replace '[^a-f0-9\\,x\-\:]',"
     
    #Try to put into canonical colon-delimited format.
    $String = $String -replace '0x|\x|\-|,',':'
     
    #Remove beginning and ending colons, and other detritus.
    $String = $String -replace '^:+|:+$|x|\',"
     
    #Maybe there's nothing left over to convert...
    if ($String.Length -eq 0) { ,@() ; return }
     
    #Split string with or without colon delimiters.
    if ($String.Length -eq 1)
    { ,@([System.Convert]::ToByte($String,16)) }
    elseif (($String.Length % 2 -eq 0) -and ($String.IndexOf(":") -eq -1))
    { ,@($String -split '([a-f0-9]{2})' | foreach-object { if ($_) {[System.Convert]::ToByte($_,16)}}) }
    elseif ($String.IndexOf(":") -ne -1)
    { ,@($String -split ':+' | foreach-object {[System.Convert]::ToByte($_,16)}) }
    else
    { ,@() }
    #The strange ",@(...)" syntax is needed to force the output into an
    #array even if there is only one element in the output (or none).
}

function Send-UdpDatagram
{
    param (
        [string] $IpAddress, 
        [int] $Port, 
        [string] $Body,
        [bool] $GetResponse = $true,
        [int] $Timeout = 10
    )

    $EncodedBody = (Convert-HexStringToByteArray -String $Body)
    Send-UdpDatagram -IpAddress $IpAddress -Port $Port -Body ([byte[]]$EncodedBody) -GetResponse $GetResponse -Timeout $Timeout
}

function Send-DNSPacket
{
    param (
        [string] $IpAddress, 
        [int] $Port, 
        [DNSPacket] $Body,
        [bool] $GetResponse = $true,
        [int] $Timeout = 10
    )

    $EncodedBody = $Body.GetData()
    Send-UdpDatagram -IpAddress $IpAddress -Port $Port -Body ([byte[]]$EncodedBody) -GetResponse $GetResponse -Timeout $Timeout
}

function Send-UdpDatagram
{
    param (
        [string] $IpAddress, 
        [int] $Port, 
        [byte[]] $Body,
        [bool] $GetResponse = $true,
        [int] $Timeout = 10
    )

    if($Body -eq $null)
    {
        return $null
    }
    $EncodedBody = $Body


    $ResponsePacket = New-Object DNSPacket
    $Socket = [System.Net.Sockets.UDPClient]::new($IpAddress, $Port)
    try
    {  
        $BytesSent = $Socket.Send($EncodedBody, $EncodedBody.Length)
        
        if($GetResponse -eq $true)
        {
            $Task = $Socket.ReceiveAsync()

            $TimeoutHit = $false
            $Counter = 0
            while($Task.IsCompleted -eq $false)
            {
                $Counter += 1
                Start-Sleep -Milliseconds 500
        
                if($Counter -gt ($Timeout * 2))
                {
                    $TimeoutHit = $true
                    break
                }
            }
    
            if($TimeoutHit -eq $true)
            {
                "Did not receive response in {0} seconds." -F $Timeout | Write-Host
            }
            else
            {
                #($Task.Result.Buffer | ForEach-Object ToString X2) -join '' | Write-Host
                $ResponsePacket.AddData($Task.Result.Buffer)
            }

            $Task.Dispose()
        }
    }
    catch {}
    
    $Socket.Close() 

    return $ResponsePacket
}



Enum RCODEValues
{
    NoError = 0
    FormatError = 1
    ServerFailure = 2
    NameError = 3
    NotImplemented = 4
    Refused = 5
}

Enum TYPEValues
{
    A_HostAddress = 1
    NS_AuthoritativeNameServer = 2
    MD_MailDestination = 3
    MF_MailForwarder = 4
    CNAME_Alias = 5
    SOA_ZoneAuthroity = 6
    MB_MailboxDomainName = 7
    MG_MailGroupMember = 8
    MR_MailRenameDomainName = 9
    NULL_NullRR = 10
    WKS_WellKnownServiceDescription = 11
    PTR_DomainNamePointer = 12
    HINFO_HostInformation = 13
    MINFO_MailListInformation = 14
    MX_MailExchange = 15
    TXT_Strings = 16
    SRV_ServiceRecord = 33
    AFXR_ZoneTransfer = 252
    MAILB_MailboxRecord = 253
    MAILA_MailAgentRecord = 254
    ALL_AllRecords = 255
}

Enum CLASSValues
{
    IN_Internet = 1
    CS_CSNETClass = 2
    CH_CHAOSClass = 3
    HS_Hesiod = 4
    ANY_AnyClass = 255
}

Class DNSPacket
{
    <# 
       ID - A 16 bit identifier assigned by the program that
       generates any kind of query.  This identifier is copied
       the corresponding reply and can be used by the requester
       to match up replies to outstanding queries. 
    #>
    [uint16] $ID = 0

    <# 
       QR - A one bit field that specifies whether this message is a
       query (0), or a response (1). 
    #>
    [int] $QR = 0

    <# 
       OPCODE - A four bit field that specifies kind of query in this
       message.  This value is set by the originator of a query
       and copied into the response.  The values are:

        0               a standard query (QUERY)
        1               an inverse query (IQUERY)
        2               a server status request (STATUS)
        3-15            reserved for future use
    #>
    [int] $OPCODE = 0

    <# 
       AA - Authoritative Answer - this bit is valid in responses,
       and specifies that the responding name server is an
       authority for the domain name in question section.

       Note that the contents of the answer section may have
       multiple owner names because of aliases.  The AA bit
       corresponds to the name which matches the query name, or
       the first owner name in the answer section.
    #>
    [bool] $AA = $false

    <# 
       TC - TrunCation - TrunCation - specifies that this message was truncated
       due to length greater than that permitted on the
       transmission channel.
    #>
    [bool] $TC = $false

    <# 
       RD - Recursion Desired - this bit may be set in a query and
       is copied into the response.  If RD is set, it directs
       the name server to pursue the query recursively.
       Recursive query support is optional.
    #>
    [bool] $RD = $false

    <# 
       RA - Recursion Available - this be is set or cleared in a
       response, and denotes whether recursive query support is
       available in the name server.
    #>
    [bool] $RA = $false

    <# 
       Z - Reserved for future use.  Must be zero in all queries
       and responses.
    #>
    [int] $Z = 0

    <# 
       RCODE - Response code - this 4 bit field is set as part of
       responses.  The values have the following interpretation:

            0               No error condition

            1               Format error - The name server was
                            unable to interpret the query.

            2               Server failure - The name server was
                            unable to process this query due to a
                            problem with the name server.

            3               Name Error - Meaningful only for
                            responses from an authoritative name
                            server, this code signifies that the
                            domain name referenced in the query does
                            not exist.

            4               Not Implemented - The name server does
                            not support the requested kind of query.

            5               Refused - The name server refuses to
                            perform the specified operation for
                            policy reasons.  For example, a name
                            server may not wish to provide the
                            information to the particular requester,
                            or a name server may not wish to perform
                            a particular operation (e.g., zone
                            transfer) for particular data.

            6-15            Reserved for future use
    #>
    [int] $RCODE = 0

    <# 
       QDCOUNT - an unsigned 16 bit integer specifying the number of
        entries in the question section.
    #>
    [uint16] $QDCOUNT = 0
    
    <# 
       ANCOUNT - an unsigned 16 bit integer specifying the number of
        resource records in the answer section.
    #>
    [uint16] $ANCOUNT = 0
    
    <# 
       NSCOUNT - an unsigned 16 bit integer specifying the number of name
        server resource records in the authority records section.
    #>
    [uint16] $NSCOUNT = 0
    
    <# 
       ARCOUNT - an unsigned 16 bit integer specifying the number of
        resource records in the additional records section.
    #>
    [uint16] $ARCOUNT = 0

    
    [Byte[]] $ByteArray = $null

    $IsValid = $false

    # Maps offsets to labels (used when adding raw packet data).
    $LabelDictionary = @{}

    # Maps labels to offsets (used for compression when getting raw packet data).
    $CompressionDictionary = @{}

    $QuestionRecords = @()
    $AnswerRecords = @()
    $AuthorityRecords = @()
    $AdditionalRecords = @()

    DNSPacket() { }

    [PSObject] ParseLabel([int]$Offset, [int]$RecursionDepth)
    {
        $ReturnValue = New-Object System.Object
        $ReturnValue | Add-Member -type NoteProperty -name Label -Value ""
        $ReturnValue | Add-Member -type NoteProperty -name NewOffset -Value $Offset

        # Bool tracking the end of label parsing.
        $EncounteredEnd = $false

        $Labels = @()
        
        while($EncounteredEnd -eq $false -and $Offset -lt $this.ByteArray.Count)
        {
            $LabelLength = $this.ByteArray[$Offset]
            
            # Check to see if this label is a pointer.
            if((($LabelLength -band 0xC0) -shr 6) -eq 0x3)
            {
                $NewOffsetValueArray = @($this.ByteArray[($Offset+1)], ($this.ByteArray[($Offset)] -band 0x3F))
                $NewOffsetValue = [bitconverter]::ToUInt16($NewOffsetValueArray, 0)

                # If the label offset is already indexed, use that value.
                if($this.LabelDictionary.ContainsKey($NewOffsetValue))
                {
                    ((($NewOffsetValueArray)|ForEach-Object ToString X2) -join '').ToLower()
                    $Labels += $this.LabelDictionary[$NewOffsetValue] 
                }

                # Else, parse label starting at NewOffsetValue
                else
                {
                    # Limit the number of times recursion can happen to prevent infinite recursion.
                    if($RecursionDepth -le 20)
                    {
                        $RecurseiveResults = $this.ParseLabel($NewOffsetValue, $RecursionDepth+1)
                        $Labels += $RecurseiveResults.Label
                    }
                }

                $Offset += 2
                $EncounteredEnd = $true
            }

            # Labels are limited to 63 octets in length and only labels longer than 0 matter.
            elseif($LabelLength -gt 63 -or $LabelLength -eq 0)
            {
                $EncounteredEnd = $true
                $Offset++
            }

            elseif(($LabelLength + $Offset) -lt $this.ByteArray.Count)
            {
                $NewLabel = [System.Text.Encoding]::ASCII.GetString($this.ByteArray[($Offset+1)..($Offset+$LabelLength)])
                $Labels += $NewLabel
                $this.LabelDictionary[$Offset] = $NewLabel
                $Offset += ($LabelLength + 1)
                $EncounteredPointer = $false
            }
        }

        $ReturnValue.Label = ($Labels -join '.')
        $ReturnValue.NewOffset = $Offset
        return $ReturnValue
    }

    [PSObject] ParseLabel([byte[]] $TargetArray, [int]$Offset, [int]$RecursionDepth)
    {
        $ReturnValue = New-Object System.Object
        $ReturnValue | Add-Member -type NoteProperty -name Label -Value ""
        $ReturnValue | Add-Member -type NoteProperty -name NewOffset -Value $Offset

        # Bool tracking the end of label parsing.
        $EncounteredEnd = $false
        $Labels = @()
        
        while($EncounteredEnd -eq $false -and $Offset -lt $TargetArray.Count)
        {
            $LabelLength = $TargetArray[$Offset]
            
            # Check to see if this label is a pointer.
            if((($LabelLength -band 0xC0) -shr 6) -eq 0x3)
            {
                $NewOffsetValueArray = @($TargetArray[($Offset+1)], ($TargetArray[($Offset)] -band 0x3F))
                $NewOffsetValue = [bitconverter]::ToUInt16($NewOffsetValueArray, 0)

                # If the label offset is already indexed, use that value.
                if($this.LabelDictionary.ContainsKey($NewOffsetValue))
                {
                    ((($NewOffsetValueArray)|ForEach-Object ToString X2) -join '').ToLower()
                    $Labels += $this.LabelDictionary[$NewOffsetValue] 
                }

                # Else, parse label starting at NewOffsetValue
                else
                {
                    # Limit the number of times recursion can happen to prevent infinite recursion.
                    if($RecursionDepth -le 20)
                    {
                        $RecurseiveResults = $this.ParseLabel($NewOffsetValue, $RecursionDepth+1)
                        $Labels += $RecurseiveResults.Label
                    }
                }

                $Offset += 2
                $EncounteredEnd = $true
            }

            # Labels are limited to 63 octets in length and only labels longer than 0 matter.
            elseif($LabelLength -gt 63 -or $LabelLength -eq 0)
            {
                $EncounteredEnd = $true
                $Offset++
            }

            elseif(($LabelLength + $Offset) -lt $TargetArray.Count)
            {
                $NewLabel = [System.Text.Encoding]::ASCII.GetString($TargetArray[($Offset+1)..($Offset+$LabelLength)])
                $Labels += $NewLabel
                $Offset += ($LabelLength + 1)
            }
        }

        $ReturnValue.Label = ($Labels -join '.')
        $ReturnValue.NewOffset = $Offset
        return $ReturnValue
    }

    # Take a value and turn it into a byte array, and then reverse its order.
    [byte[]] ToReverseByteArray($Argument)
    {
        $ReturnValue = [bitconverter]::GetBytes($Argument)
        [array]::Reverse($ReturnValue)
        return $ReturnValue
    }

    [void] AddQuestionRecord([string]$QName, [Uint16]$QType, [Uint16]$QClass)
    {
        $QuestionRecord = New-Object System.Object
        $QuestionRecord | Add-Member -type NoteProperty -name QNAME -Value $QName
        $QuestionRecord | Add-Member -type NoteProperty -name QTYPE -Value $QType
        $QuestionRecord | Add-Member -type NoteProperty -name QCLASS -Value $QClass
        $this.QuestionRecords += $QuestionRecord

        $this.QDCOUNT = $this.QuestionRecords.Count
    }

    [PSObject] AddResourceRecord([string]$Name, [Uint16]$Type, [Uint16]$Class, [Uint32]$TTL, [Uint16]$RDLength, [byte[]]$RData)
    {
        $ResourceRecord = New-Object System.Object
        $ResourceRecord | Add-Member -type NoteProperty -name NAME -Value $Name
        $ResourceRecord | Add-Member -type NoteProperty -name TYPE -Value $Type
        $ResourceRecord | Add-Member -type NoteProperty -name CLASS -Value $Class
        $ResourceRecord | Add-Member -type NoteProperty -name TTL -Value $TTL
        $ResourceRecord | Add-Member -type NoteProperty -name RDLENGTH -Value $RDLength
        $ResourceRecord | Add-Member -type NoteProperty -name RDATA -Value $RData
        
        return $ResourceRecord
    }

    [byte[]] GetQuestionRecord($QuestionRecord, [ref]$CurrentOffset)
    {
        [byte[]] $ReturnValue = @()
        $LastLabelWasPointer = $false
        $OriginalOffset = $CurrentOffset.Value

        $Labels = $QuestionRecord.QNAME.Split(".")
        $Complete = $false

        # Build the return value byte-array first.
        for($LabelIndex = 0; ($LabelIndex -lt $Labels.Count -and $Complete -eq $false); $LabelIndex++)
        {
            $CurrentLabel = $Labels[$LabelIndex]
            $NextLargestLabel = $Labels[$LabelIndex..($Labels.Count-1)] -join '.'

            # If the next largest label is already in the CompressionDictionary, lookup the offset and use it.
            if($this.CompressionDictionary.ContainsKey($NextLargestLabel))
            {
                $OffsetBytes = $this.ToReverseByteArray([uint16]$this.CompressionDictionary[$NextLargestLabel])
                $ReturnValue += @(($OffsetBytes[0] -bor 0xC0), $OffsetBytes[1])
                $CurrentOffset.Value += 2
                $LastLabelWasPointer = $true
                $Complete = $true
            }

            # Else, add the CurrentLabel to the return value, record the starting index of this NextLargestLabel,
            #    and increment the CurrentOffset.
            else
            {
                $ReturnValue += [int]$CurrentLabel.Length
                $ReturnValue += [system.Text.Encoding]::ASCII.GetBytes($CurrentLabel)
                $this.CompressionDictionary[$NextLargestLabel] = [uint16]$CurrentOffset.Value
                $CurrentOffset.Value += ([system.Text.Encoding]::ASCII.GetBytes($CurrentLabel)).Count + 1
                $LastLabelWasPointer = $false
            }
        }

        if($LastLabelWasPointer -eq $false)
        {
            $ReturnValue += [int]0
            $CurrentOffset.Value += 1
        }

        $ReturnValue += $this.ToReverseByteArray($QuestionRecord.QTYPE)
        $ReturnValue += $this.ToReverseByteArray($QuestionRecord.QCLASS)
        $CurrentOffset.Value += 4

        return $ReturnValue
    }

    [byte[]] GetResourceRecord($ResourceRecord, [ref]$CurrentOffset)
    {
        [byte[]] $ReturnValue = @()
        $LastLabelWasPointer = $false
        $OriginalOffset = $CurrentOffset.Value

        $Labels = $ResourceRecord.NAME.Split(".")
        $Complete = $false

        # Build the return value byte-array first.
        for($LabelIndex = 0; ($LabelIndex -lt $Labels.Count -and $Complete -eq $false); $LabelIndex++)
        {
            $CurrentLabel = $Labels[$LabelIndex]
            $NextLargestLabel = $Labels[$LabelIndex..($Labels.Count-1)] -join '.'

            # If the next largest label is already in the CompressionDictionary, lookup the offset and use it.
            if($this.CompressionDictionary.ContainsKey($NextLargestLabel))
            {
                $OffsetBytes = $this.ToReverseByteArray([uint16]$this.CompressionDictionary[$NextLargestLabel])
                $ReturnValue += @(($OffsetBytes[0] -bor 0xC0), $OffsetBytes[1])
                $CurrentOffset.Value += 2
                $LastLabelWasPointer = $true
                $Complete = $true
            }

            # Else, add the CurrentLabel to the return value, record the starting index of this NextLargestLabel,
            #    and increment the CurrentOffset.
            else
            {
                $ReturnValue += [int]$CurrentLabel.Length
                $ReturnValue += [system.Text.Encoding]::ASCII.GetBytes($CurrentLabel)
                $this.CompressionDictionary[$NextLargestLabel] = [uint16]$CurrentOffset.Value
                $CurrentOffset.Value += ([system.Text.Encoding]::ASCII.GetBytes($CurrentLabel)).Count + 1
                $LastLabelWasPointer = $false
            }
        }

        if($LastLabelWasPointer -eq $false)
        {
            $ReturnValue += [int]0
            $CurrentOffset.Value += 1
        }

        $ReturnValue += $this.ToReverseByteArray($ResourceRecord.TYPE)
        $ReturnValue += $this.ToReverseByteArray($ResourceRecord.CLASS)
        $ReturnValue += $this.ToReverseByteArray($ResourceRecord.TTL)
        $ReturnValue += $this.ToReverseByteArray($ResourceRecord.RDLENGTH)
        $ReturnValue += $ResourceRecord.RDATA
        $CurrentOffset.Value += (8 + $ResourceRecord.RDATA.Count)

        return $ReturnValue
    }

    [void] AddData([Byte[]] $ByteArray)
    {
        # Reset the LabelDictionary so that it gets rebuilt from the supplied ByteArray
        $this.LabelDictionary = @{}

        $this.ByteArray = $ByteArray

        if($ByteArray.Count -ge 12)
        {
            $this.ID = [bitconverter]::ToUInt16($ByteArray[1..0], 0)
            $this.QR = ($ByteArray[2] -band 0x80) -shr 7
            $this.OPCODE = ($ByteArray[2] -band 0x78) -shr 3
            $this.AA = ($ByteArray[2] -band 0x4) -shr 2
            $this.TC = ($ByteArray[2] -band 0x2) -shr 1
            $this.RD = ($ByteArray[2] -band 0x1)
            $this.RA = ($ByteArray[3] -band 0x80) -shr 7
            $this.Z = ($ByteArray[3] -band 0x70) -shr 4
            $this.RCODE = $ByteArray[3] -band 0xF
            $this.QDCOUNT = [bitconverter]::ToUInt16($ByteArray[5..4], 0)
            $this.ANCOUNT = [bitconverter]::ToUInt16($ByteArray[7..6], 0)
            $this.NSCOUNT = [bitconverter]::ToUInt16($ByteArray[9..8], 0)
            $this.ARCOUNT = [bitconverter]::ToUInt16($ByteArray[11..10], 0)

            $CurrentOffset = 12

            # Parse Questions From Question Section
            for($QuestionRecordNumber = 0; $QuestionRecordNumber -lt $this.QDCOUNT; $QuestionRecordNumber++)
            {
                $LabelResults = $this.ParseLabel($CurrentOffset, 1)
                $NewLabel = $LabelResults.Label
                $CurrentOffset = $LabelResults.NewOffset
                
                if($NewLabel -ne $null -and $NewLabel -ne "")
                {
                    $QuestionRecord = New-Object System.Object
                    $QuestionRecord | Add-Member -type NoteProperty -name QNAME -Value $NewLabel
                    $QuestionRecord | Add-Member -type NoteProperty -name QTYPE -Value ([bitconverter]::ToUInt16($ByteArray[($CurrentOffset+1)..$CurrentOffset], 0))
                    $QuestionRecord | Add-Member -type NoteProperty -name QCLASS -Value ([bitconverter]::ToUInt16($ByteArray[($CurrentOffset+3)..($CurrentOffset+2)], 0))
                    $CurrentOffset += 4
                    $this.QuestionRecords += $QuestionRecord
                }
            }
            
            # Parse Resource Records From Answer Section
            for($ResourceRecordNumber = 0; $ResourceRecordNumber -lt $this.ANCOUNT; $ResourceRecordNumber++)
            {
                $LabelResults = $this.ParseLabel($CurrentOffset, 1)
                $NewLabel = $LabelResults.Label
                $CurrentOffset = $LabelResults.NewOffset
                
                if($NewLabel -ne $null -and $NewLabel -ne "")
                {
                    $ResourceRecord = New-Object System.Object
                    $ResourceRecord | Add-Member -type NoteProperty -name NAME -Value $NewLabel
                    $ResourceRecord | Add-Member -type NoteProperty -name TYPE -Value ([bitconverter]::ToUInt16($ByteArray[($CurrentOffset+1)..$CurrentOffset], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name CLASS -Value ([bitconverter]::ToUInt16($ByteArray[($CurrentOffset+3)..($CurrentOffset+2)], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name TTL -Value ([bitconverter]::ToUInt32($ByteArray[($CurrentOffset+7)..($CurrentOffset+4)], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name RDLENGTH -Value ([bitconverter]::ToUInt16($ByteArray[($CurrentOffset+9)..($CurrentOffset+8)], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name RDATA -Value $ByteArray[($CurrentOffset+10)..($ResourceRecord.RDLENGTH+$CurrentOffset+9)]
                    
                    $CurrentOffset += (10 + $ResourceRecord.RDATA.Count)
                    $this.AnswerRecords += $ResourceRecord
                }
            }

            # Parse Server Resource Records From Authority Section
            for($ResourceRecordNumber = 0; $ResourceRecordNumber -lt $this.NSCOUNT; $ResourceRecordNumber++)
            {
                $LabelResults = $this.ParseLabel($CurrentOffset, 1)
                $NewLabel = $LabelResults.Label
                $CurrentOffset = $LabelResults.NewOffset
                
                if($NewLabel -ne $null -and $NewLabel -ne "")
                {
                    $ResourceRecord = New-Object System.Object
                    $ResourceRecord | Add-Member -type NoteProperty -name NAME -Value $NewLabel
                    $ResourceRecord | Add-Member -type NoteProperty -name TYPE -Value ([bitconverter]::ToUInt16($ByteArray[($CurrentOffset+1)..$CurrentOffset], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name CLASS -Value ([bitconverter]::ToUInt16($ByteArray[($CurrentOffset+3)..($CurrentOffset+2)], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name TTL -Value ([bitconverter]::ToUInt32($ByteArray[($CurrentOffset+7)..($CurrentOffset+4)], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name RDLENGTH -Value ([bitconverter]::ToUInt16($ByteArray[($CurrentOffset+9)..($CurrentOffset+8)], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name RDATA -Value $ByteArray[($CurrentOffset+10)..($ResourceRecord.RDLENGTH+$CurrentOffset+9)]
                    
                    $CurrentOffset += (10 + $ResourceRecord.RDATA.Count)
                    $this.AuthorityRecords += $ResourceRecord
                }
            }

            # Parse Resource Records From Additional Records Section
            for($ResourceRecordNumber = 0; $ResourceRecordNumber -lt $this.ARCOUNT; $ResourceRecordNumber++)
            {
                $LabelResults = $this.ParseLabel($CurrentOffset, 1)
                $NewLabel = $LabelResults.Label
                $CurrentOffset = $LabelResults.NewOffset
                
                if($NewLabel -ne $null -and $NewLabel -ne "")
                {
                    $ResourceRecord = New-Object System.Object
                    $ResourceRecord | Add-Member -type NoteProperty -name NAME -Value $NewLabel
                    $ResourceRecord | Add-Member -type NoteProperty -name TYPE -Value ([bitconverter]::ToUInt16($ByteArray[($CurrentOffset+1)..$CurrentOffset], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name CLASS -Value ([bitconverter]::ToUInt16($ByteArray[($CurrentOffset+3)..($CurrentOffset+2)], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name TTL -Value ([bitconverter]::ToUInt32($ByteArray[($CurrentOffset+7)..($CurrentOffset+4)], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name RDLENGTH -Value ([bitconverter]::ToUInt16($ByteArray[($CurrentOffset+9)..($CurrentOffset+8)], 0))
                    $ResourceRecord | Add-Member -type NoteProperty -name RDATA -Value $ByteArray[($CurrentOffset+10)..($ResourceRecord.RDLENGTH+$CurrentOffset+9)]
                    
                    $CurrentOffset += (10 + $ResourceRecord.RDATA.Count)
                    $this.AdditionalRecords += $ResourceRecord
                }
            }
        }
    }

    [byte[]] GetData()
    {
        # Reset the CompressionDictionary so that it is rebuilt with any new offsets.
        $this.CompressionDictionary = @{}
        
        [byte[]] $ReturnValue = @()

        $this.QDCOUNT = $this.QuestionRecords.Count
        $this.ANCOUNT = $this.AnswerRecords.Count
        $this.NSCOUNT = $this.AuthorityRecords.Count
        $this.ARCOUNT = $this.AdditionalRecords.Count
        
        $ReturnValue += $this.ToReverseByteArray($this.ID)
        $ReturnValue += ([int]$this.QR -shl 7) -bor ([int]$this.OPCODE -shl 3) -bor ([int]$this.AA -shl 2) -bor ([int]$this.TC -shl 1) -bor ([int]$this.RD)
        $ReturnValue += ([int]$this.RA -shl 7) -bor ([int]$this.Z -shl 4) -bor ([int]$this.RCODE)
        $ReturnValue += $this.ToReverseByteArray($this.QDCOUNT)
        $ReturnValue += $this.ToReverseByteArray($this.ANCOUNT)
        $ReturnValue += $this.ToReverseByteArray($this.NSCOUNT)
        $ReturnValue += $this.ToReverseByteArray($this.ARCOUNT)

        $CurrentOffset = $ReturnValue.Count

        foreach($QuestionRecord in $this.QuestionRecords)
        {
            $ReturnValue += ($this.GetQUestionRecord($QuestionRecord, [ref] $CurrentOffset))
        }

        foreach($ResourceRecord in $this.AnswerRecords)
        {
            $ReturnValue += ($this.GetResourceRecord($ResourceRecord, [ref] $CurrentOffset))
        }

        foreach($ResourceRecord in $this.AuthorityRecords)
        {
            $ReturnValue += ($this.GetResourceRecord($ResourceRecord, [ref] $CurrentOffset))
        }

        foreach($ResourceRecord in $this.AdditionalRecords)
        {
            $ReturnValue += ($this.GetResourceRecord($ResourceRecord, [ref] $CurrentOffset))
        }

        return $ReturnValue
    }

    [void] DebugResourceRecord($ResourceRecord)
    {
        try
        {
            $TypeVal = [TYPEValues]$ResourceRecord.TYPE 
        }
        catch
        {
            $TypeVal = "Unknown"
        }

        $Properties = @{
            "CLASS" = $ResourceRecord.CLASS;
            "TYPE" = ("{0} ({1})" -F $ResourceRecord.TYPE, $TypeVal);
            "TTL" = $ResourceRecord.TTL;
            "RDLENGTH" = $ResourceRecord.RDLENGTH;
            "RDATA" = (($ResourceRecord.RDATA|ForEach-Object ToString X2) -join '');
        }

        if($ResourceRecord.Type -eq [TYPEValues]::A_HostAddress)
        {
            if($ResourceRecord.RDATA.Count -eq 4)
            {
                $Properties["Address"] = "{0}.{1}.{2}.{3}" -F $ResourceRecord.RDATA[0], $ResourceRecord.RDATA[1], $ResourceRecord.RDATA[2], $ResourceRecord.RDATA[3]
            }
        }
        elseif($ResourceRecord.Type -eq [TYPEValues]::SRV_ServiceRecord)
        {
            $Properties["Priority"] = [bitconverter]::ToUInt16($ResourceRecord.RDATA[1..0], 0)
            $Properties["Weight"] = [bitconverter]::ToUInt16($ResourceRecord.RDATA[3..2], 0)
            $Properties["Port"] = [bitconverter]::ToUInt16($ResourceRecord.RDATA[5..4], 0)
            $Properties["Target"] = ($this.ParseLabel($ResourceRecord.RDATA, 6, 10)).Label
        }
        elseif($ResourceRecord.Type -eq [TYPEValues]::CNAME_Alias)
        {
            $Properties["CNAME"] = ($this.ParseLabel($ResourceRecord.RDATA, 0, 10)).Label
        }
        elseif($ResourceRecord.Type -eq [TYPEValues]::NS_AuthoritativeNameServer)
        {
            $Properties["CNAME"] = ($this.ParseLabel($ResourceRecord.RDATA, 0, 10)).Label
        }
        elseif($ResourceRecord.Type -eq [TYPEValues]::SOA_ZoneAuthroity)
        {
            $MName = $this.ParseLabel($ResourceRecord.RDATA, 0, 10)
            $Properties["MNAME"] = $MName.Label

            $RName = $this.ParseLabel($ResourceRecord.RDATA, $MName.NewOffset, 10)
            $Properties["RNAME"] = $RName.Label

            $Properties["SERIAL"] = [bitconverter]::ToUInt32($ResourceRecord.RDATA[($RName.NewOffset+3)..$RName.NewOffset], 0)
            $Properties["REFRESH"] = [bitconverter]::ToUInt32($ResourceRecord.RDATA[($RName.NewOffset+7)..($RName.NewOffset+4)], 0)
            $Properties["RETRY"] = [bitconverter]::ToUInt32($ResourceRecord.RDATA[($RName.NewOffset+11)..($RName.NewOffset+8)], 0)
            $Properties["EXPIRE"] = [bitconverter]::ToUInt32($ResourceRecord.RDATA[($RName.NewOffset+15)..($RName.NewOffset+12)], 0)
            $Properties["MINIMUM"] = [bitconverter]::ToUInt32($ResourceRecord.RDATA[($RName.NewOffset+19)..($RName.NewOffset+16)], 0)
        }
        elseif($ResourceRecord.Type -eq [TYPEValues]::MX_MailExchange)
        {
            $Properties["PREFERENCE"] = [bitconverter]::ToUInt16($ResourceRecord.RDATA[1..0], 0)
            $Properties["EXCHANGE"] = ($this.ParseLabel($ResourceRecord.RDATA, 2, 10)).Label
        }


        $OutputString = "`t{0,-64}" -F $ResourceRecord.NAME

        foreach($Property in (@($Properties.Keys) | Sort))
        {
            $OutputString += "`r`n`t`t{0,10}: {1}" -F $Property, $Properties[$Property]
        }
        $OutputString | Write-Host
    }

    [void] Debug()
    {
        "ID:      0x{0,-6:X2}" -F $this.ID | Write-Host
        "QR:      {0,-6}" -F $this.QR | Write-Host
        "OPCODE:  {0,-6}" -F $this.OPCODE | Write-Host
        "AA:      {0,-6}" -F $this.AA | Write-Host
        "TC:      {0,-6}" -F $this.TC | Write-Host
        "RD:      {0,-6}" -F $this.RD | Write-Host
        "RA:      {0,-6}" -F $this.RA | Write-Host
        "Z:       {0,-6}" -F $this.Z | Write-Host
        try
        {
            "RCODE:   {0,-6} ({1})" -F $this.RCODE, [RCODEValues]$this.RCODE | Write-Host
        }
        catch
        {
            "RCODE:   {0,-6} (Unknown)" -F $this.RCODE | Write-Host
        }
        "QDCOUNT: {0,-6}" -F $this.QDCOUNT | Write-Host
        "ANCOUNT: {0,-6}" -F $this.ANCOUNT | Write-Host
        "NSCOUNT: {0,-6}" -F $this.NSCOUNT | Write-Host
        "ARCOUNT: {0,-6}" -F $this.ARCOUNT | Write-Host

        if($this.QuestionRecords.Count -gt 0)
        {
            "`nQuestion Records: " | Write-Host
            foreach($QuestionRecord in $this.QuestionRecords)
            {
                try
                {
                    $TypeVal = [TYPEValues]$QuestionRecord.QTYPE 
                }
                catch
                {
                    $TypeVal = "Unknown"
                }
                "`t{0,-64}   CLASS:{1,-5} TYPE:{2,-5} ({3})" -F $QuestionRecord.QNAME, $QuestionRecord.QCLASS, $QuestionRecord.QTYPE, $TypeVal | Write-Host
            }
        }

        if($this.AnswerRecords.Count -gt 0)
        {
            "`nAnswer Records: " | Write-Host
            foreach($ResourceRecord in $this.AnswerRecords)
            {
                $this.DebugResourceRecord($ResourceRecord)
            }
        }

        if($this.AuthorityRecords.Count -gt 0)
        {
            "`nAuthority Records: " | Write-Host
            foreach($ResourceRecord in $this.AuthorityRecords)
            {
                $this.DebugResourceRecord($ResourceRecord)
            }
        }

        if($this.AdditionalRecords.Count -gt 0)
        {
            "`nAdditional Records: " | Write-Host
            foreach($ResourceRecord in $this.AdditionalRecords)
            {
                $this.DebugResourceRecord($ResourceRecord)
            }
        }
    }
}
