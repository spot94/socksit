<#
.SYNOPSIS
  Generates ui/tray/icon.ico — the SocksIt tray/app icon.

.DESCRIPTION
  A teal rounded-square badge (stays visible on light and dark taskbars) with a
  white "routing" arrow (a bent redirect arrow: traffic enters and is rerouted
  up/out — i.e. into the proxy). Rendered at multiple sizes and packed into a
  proper multi-resolution .ico: 16/24/32/48 as 32-bit BMP (crisp when small),
  64/128/256 as PNG (compact). Transparent outside the badge.

.EXAMPLE
  pwsh -File build/make-icon.ps1
#>
[CmdletBinding()]
param(
    [string]$Out
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $PSScriptRoot
if (-not $Out) { $Out = Join-Path $root 'ui/tray/icon.ico' }
$preview = Join-Path $root 'build/icon-preview.png'

# Brand colours.
$teal  = [System.Drawing.Color]::FromArgb(255, 14, 124, 134)
$white = [System.Drawing.Color]::FromArgb(255, 255, 255, 255)

function New-IconBitmap([int]$s) {
    $bmp = New-Object System.Drawing.Bitmap($s, $s, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    # Rounded-square badge.
    $pad = [Math]::Max(1, [int]($s * 0.055))
    $rr  = [Math]::Max(2, [int]($s * 0.24))
    $x = $pad; $y = $pad; $w = $s - 2*$pad - 1; $h = $s - 2*$pad - 1
    $d = $rr * 2
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc($x,        $y,        $d, $d, 180, 90)
    $path.AddArc($x+$w-$d,  $y,        $d, $d, 270, 90)
    $path.AddArc($x+$w-$d,  $y+$h-$d,  $d, $d,   0, 90)
    $path.AddArc($x,        $y+$h-$d,  $d, $d,  90, 90)
    $path.CloseFigure()
    $badge = New-Object System.Drawing.SolidBrush($teal)
    $g.FillPath($badge, $path)

    # Routing arrow (white): horizontal shaft from the left, bending up-right,
    # ending in an arrowhead — a "redirect into the tunnel" glyph.
    function P([double]$nx, [double]$ny) {
        New-Object System.Drawing.PointF([single]($nx*$s), [single]($ny*$s))
    }
    $pw = [single]([Math]::Max(1.5, $s * 0.135)) # shaft width
    $p0 = P 0.24 0.68     # shaft start (left)
    $p1 = P 0.54 0.68     # corner
    $tip = P 0.77 0.30    # arrow tip (up-right)

    # Arrowhead geometry along p1 -> tip.
    $dx = $tip.X - $p1.X; $dy = $tip.Y - $p1.Y
    $len = [Math]::Sqrt($dx*$dx + $dy*$dy)
    $ux = $dx/$len; $uy = $dy/$len          # unit direction
    $px = -$uy; $py = $ux                    # perpendicular
    $ah = $pw * 1.35                          # arrowhead half-width
    $al = $pw * 2.1                           # arrowhead length
    $baseX = $tip.X - $ux*$al; $baseY = $tip.Y - $uy*$al
    $v1 = New-Object System.Drawing.PointF([single]($baseX + $px*$ah), [single]($baseY + $py*$ah))
    $v2 = New-Object System.Drawing.PointF([single]($baseX - $px*$ah), [single]($baseY - $py*$ah))
    $baseP = New-Object System.Drawing.PointF([single]$baseX, [single]$baseY)

    $pen = New-Object System.Drawing.Pen($white, $pw)
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $g.DrawLines($pen, [System.Drawing.PointF[]]@($p0, $p1, $baseP))

    $wb = New-Object System.Drawing.SolidBrush($white)
    $g.FillPolygon($wb, [System.Drawing.PointF[]]@($tip, $v1, $v2))

    $g.Dispose(); $badge.Dispose(); $pen.Dispose(); $wb.Dispose(); $path.Dispose()
    return $bmp
}

# Build a 32-bit BMP DIB (XOR pixels + AND mask), bottom-up, for one bitmap.
function Get-DibBytes([System.Drawing.Bitmap]$bmp) {
    $s = $bmp.Width
    $rect = New-Object System.Drawing.Rectangle(0, 0, $s, $s)
    $bd = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $stride = $bd.Stride
    $buf = New-Object byte[] ($stride * $s)
    [System.Runtime.InteropServices.Marshal]::Copy($bd.Scan0, $buf, 0, $buf.Length)
    $bmp.UnlockBits($bd)

    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    # BITMAPINFOHEADER
    $bw.Write([int]40); $bw.Write([int]$s); $bw.Write([int]($s*2))
    $bw.Write([int16]1); $bw.Write([int16]32); $bw.Write([int]0)
    $bw.Write([int]0); $bw.Write([int]0); $bw.Write([int]0); $bw.Write([int]0); $bw.Write([int]0)
    # XOR bitmap, bottom-up (BGRA already in memory order for 32bppArgb)
    for ($row = $s-1; $row -ge 0; $row--) {
        $bw.Write($buf, $row*$stride, $s*4)
    }
    # AND mask: 1bpp, rows padded to 4 bytes, all zero (alpha channel carries transparency)
    $andRow = [int]([Math]::Floor(($s + 31) / 32) * 4)
    $zero = New-Object byte[] $andRow
    for ($row = 0; $row -lt $s; $row++) { $bw.Write($zero, 0, $andRow) }
    $bw.Flush()
    return $ms.ToArray()
}

function Get-PngBytes([System.Drawing.Bitmap]$bmp) {
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    return $ms.ToArray()
}

$sizes = @(
    @{ s=16;  png=$false },
    @{ s=24;  png=$false },
    @{ s=32;  png=$false },
    @{ s=48;  png=$false },
    @{ s=64;  png=$true  },
    @{ s=128; png=$true  },
    @{ s=256; png=$true  }
)

$images = @()
foreach ($e in $sizes) {
    $bmp = New-IconBitmap $e.s
    if ($e.s -eq 256) { $bmp.Save($preview, [System.Drawing.Imaging.ImageFormat]::Png) }
    $data = if ($e.png) { Get-PngBytes $bmp } else { Get-DibBytes $bmp }
    $images += [pscustomobject]@{ s=$e.s; data=$data }
    $bmp.Dispose()
}

# Assemble the .ico container.
$fs = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([int16]0); $bw.Write([int16]1); $bw.Write([int16]$images.Count) # ICONDIR
$offset = 6 + 16 * $images.Count
foreach ($img in $images) {
    $bDim = if ($img.s -ge 256) { 0 } else { $img.s }
    $bw.Write([byte]$bDim); $bw.Write([byte]$bDim)  # width, height
    $bw.Write([byte]0); $bw.Write([byte]0)          # colours, reserved
    $bw.Write([int16]1); $bw.Write([int16]32)       # planes, bitcount
    $bw.Write([int]$img.data.Length)                # bytes in resource
    $bw.Write([int]$offset)                          # image offset
    $offset += $img.data.Length
}
foreach ($img in $images) { $bw.Write($img.data, 0, $img.data.Length) }
$bw.Flush()
[System.IO.File]::WriteAllBytes($Out, $fs.ToArray())

$kb = [math]::Round((Get-Item $Out).Length / 1KB, 1)
Write-Host "Wrote $Out ($kb KB, $($images.Count) sizes) + preview $preview"
