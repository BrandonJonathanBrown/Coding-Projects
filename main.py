from yt_dlp import YoutubeDL
from tqdm import tqdm
import os

# Author: Brandon Jonathan Brown

class YouTubeDownloader:
    def __init__(self, url):
        print("[*] Initializing YouTube Downloader...")
        self.url = url
        self.title = None
        self.pbar = None

    def download(self):
        try:
            print(f"[*] Fetching video info for: {self.url}")

            def hook(d):
                if d['status'] == 'downloading':
                    total = d.get('total_bytes') or d.get('total_bytes_estimate') or 0
                    if self.pbar.total != total:
                        self.pbar.total = total
                    downloaded = d.get('downloaded_bytes', 0)
                    self.pbar.update(downloaded - self.pbar.n)
                elif d['status'] == 'finished':
                    self.pbar.close()
                    print(f"\n[*] Download complete: {d['filename']}")

            with tqdm(desc="Progress", unit='B', unit_scale=True, ncols=80) as pbar:
                self.pbar = pbar

                ydl_opts = {
                    'format': 'bestvideo+bestaudio/best',
                    'outtmpl': '%(title)s.%(ext)s',
                    'merge_output_format': 'mp4',
                    'progress_hooks': [hook],
                    'quiet': True,
                    'noplaylist': True,
                }

                with YoutubeDL(ydl_opts) as ydl:
                    ydl.download([self.url])

        except Exception as ex:
            if self.pbar:
                self.pbar.close()
            print(f"[!] Failed to download video: {type(ex).__name__}: {ex}")

# Main Function
if __name__ == "__main__":
    urls = []
    print("YouTube Downloader - Brandon Jonathan Brown (yt-dlp edition)")
    while True:
        url = input("Please enter a URL or 'q' to quit:\n").strip()
        if url.lower() == 'q':
            break
        urls.append(url)
        break

    for url in urls:
        clean_url = url.split('&')[0]  
        downloader = YouTubeDownloader(clean_url)
        downloader.download()
