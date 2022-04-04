$payload = "enc.doc"

[string]$output = "" 

$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 17
    if ($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2) 
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
Write-Host "[*] String copied to clipboard"
Write-Host "[*] Encrypted string:"
Write-Host $output
$output | clip
